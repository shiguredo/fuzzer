%% fuzz target と、feedback または dict_modules で指定したモジュールから、
%% libFuzzer の辞書を自動生成する。
%%
%% abstract code の関数本体から binary、文字列、整数のリテラルを取り出す。
%% debug_info がないモジュールでは、BEAM の literal chunk から取り出せる分だけを
%% 使う。
%%
%% 整数は 2/3/4/8 バイトの big-endian と little-endian の両方で出力する。
%% 例えば STUN の magic cookie (16#2112A442) は、ネットワークバイトオーダーの
%% 4 バイト列として辞書に入る。
-module(fuzzer_dict).

-export([generate/1, merge/3, temp_directory/0]).

%% 辞書に含めるエントリーの上限
-define(MAX_ENTRIES, 4096).
%% 1 エントリーの最大バイト数
-define(MAX_ENTRY_BYTES, 64).
%% 整数をバイト列にする最小値。小さな整数は長さやフラグが多く、辞書としての
%% 価値が低いため除外する。
-define(MIN_INTEGER, 256).
%% 整数をバイト列にできる最大値
-define(MAX_INTEGER, 16#FFFFFFFFFFFFFFFF).


%% モジュールの abstract code と literal chunk から辞書エントリーを生成する。
%%
%% 読み込めないモジュールやリテラルを持たないモジュールは無視する。
-spec generate([module()]) -> {ok, [binary()]}.
generate(Modules) ->
    Entries =
        lists:foldl(fun(Module, Acc0) ->
                            Acc1 = collect_abstract(Module, Acc0),
                            collect_literal_chunk(Module, Acc1)
                    end,
                    #{},
                    Modules),
    % パターン・ガード・比較の中のリテラルを優先し、同じ優先度なら辞書順にする。
    % 4,096 件を超える場合は、この順序で先頭から採用する。
    Sorted =
        lists:sort(fun({EntryA, PriorityA}, {EntryB, PriorityB}) ->
                           case PriorityA > PriorityB of
                               true ->
                                   true;
                               false ->
                                   case PriorityA < PriorityB of
                                       true ->
                                           false;
                                       false ->
                                           EntryA =< EntryB
                                   end
                           end
                   end,
                   maps:to_list(Entries)),
    {ok, [ Entry || {Entry, _Priority} <:- lists:sublist(Sorted, ?MAX_ENTRIES) ]}.


%% 利用者の辞書と自動生成した辞書を 1 つのファイルへまとめる。
%%
%% libFuzzer の -dict は最後の 1 個しか有効にならないため、必ず 1 ファイルに
%% まとめてから渡す。生成したファイルは呼び出し側が削除する。
-spec merge(undefined | file:filename_all(), [binary()], file:filename_all()) ->
          {ok, file:filename_all()} | {error, term()}.
merge(_UserDict, [], _Directory) ->
    {error, empty_entries};
merge(UserDict, Entries, Directory) ->
    case user_dict_content(UserDict) of
        {ok, UserContent} ->
            Body =
                iolist_to_binary([ensure_newline(UserContent),
                                  [ [Entry, $\n] || Entry <:- Entries ]]),
            Path =
                filename:join(Directory,
                              <<".fuzzer-auto-",
                                (integer_to_binary(erlang:unique_integer([positive])))/binary,
                                ".dict">>),
            case file:write_file(Path, Body) of
                ok ->
                    {ok, Path};
                {error, Reason} ->
                    {error, {write_failed, Path, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.


%% abstract code の関数本体を走査する。属性 (spec など) は入力リテラルを
%% 含まないため対象にしない。
-spec collect_abstract(module(), map()) -> map().
collect_abstract(Module, Acc) ->
    case module_beam(Module) of
        {ok, Beam} ->
            case abstract_forms(Module, Beam) of
                {ok, Forms} ->
                    lists:foldl(fun(Form, MapAcc) ->
                                        case Form of
                                            {function, _, _, _, _} ->
                                                Tree = erl_syntax:form_list([Form]),
                                                collect_tree(Tree, outside, 0, MapAcc);
                                            _ ->
                                                MapAcc
                                        end
                                end,
                                Acc,
                                Forms);
                error ->
                    Acc
            end;
        error ->
            Acc
    end.


-spec abstract_forms(module(), file:filename_all()) -> {ok, [term()]} | error.
abstract_forms(Module, Beam) ->
    case beam_lib:chunks(Beam, [abstract_code]) of
        {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} ->
            {ok, Forms};
        _ ->
            error
    end.


%% 構文木を親から子へ走査する。
%%
%% 文字列は、binary のフィールドの中では既定で latin1、/utf8 の指定がある場合だけ
%% UTF-8 として扱う。binary の外の文字列は Erlang の文字列なので UTF-8 にする。
%%
%% Priority は、パターン、ガード、比較の内側では 1、それ以外では 0 にする。
%% 4,096 件の上限を超えたときに、マジックナンバーになりやすいリテラルを残すため。
-spec collect_tree(erl_syntax:syntaxTree(), outside | latin1 | utf8, 0 | 1, map()) -> map().
collect_tree(Node, Mode, Priority, Acc0) ->
    Acc1 = collect_node(Node, Mode, Priority, Acc0),
    case erl_syntax:type(Node) of
        binary ->
            lists:foldl(fun(Field, Acc) ->
                                collect_tree(Field, latin1, Priority, Acc)
                        end,
                        Acc1,
                        erl_syntax:binary_fields(Node));
        binary_field ->
            collect_binary_field(Node, Priority, Acc1);
        clause ->
            collect_clause(Node, Mode, Acc1);
        op ->
            collect_op(Node, Mode, Priority, Acc1);
        _ ->
            collect_children(Node, Mode, Priority, Acc1)
    end.


%% 子ノードを現在の文字列モードと優先度のまま走査する。
-spec collect_children(erl_syntax:syntaxTree(),
                       outside | latin1 | utf8,
                       0 | 1,
                       map()) -> map().
collect_children(Node, Mode, Priority, Acc) ->
    lists:foldl(fun(Group, GroupAcc) ->
                        lists:foldl(fun(Child, ChildAcc) ->
                                            collect_tree(Child, Mode, Priority, ChildAcc)
                                    end,
                                    GroupAcc,
                                    Group)
                end,
                Acc,
                erl_syntax:subtrees(Node)).


%% 節のパターンとガードを優先し、本体は通常の優先度で走査する。
-spec collect_clause(erl_syntax:syntaxTree(), outside | latin1 | utf8, map()) -> map().
collect_clause(Node, Mode, Acc) ->
    Patterns = erl_syntax:clause_patterns(Node),
    Guard = erl_syntax:clause_guard(Node),
    Body = erl_syntax:clause_body(Node),
    Acc1 = collect_list(Patterns, Mode, 1, Acc),
    Acc2 = collect_guard(Guard, Mode, Acc1),
    collect_list(Body, Mode, 0, Acc2).


-spec collect_guard(none | erl_syntax:syntaxTree(), outside | latin1 | utf8, map()) -> map().
collect_guard(none, _Mode, Acc) ->
    Acc;
collect_guard(Guard, Mode, Acc) ->
    collect_tree(Guard, Mode, 1, Acc).


-spec collect_list([erl_syntax:syntaxTree()],
                   outside | latin1 | utf8,
                   0 | 1,
                   map()) -> map().
collect_list(Nodes, Mode, Priority, Acc) ->
    lists:foldl(fun(Node, ChildAcc) ->
                        collect_tree(Node, Mode, Priority, ChildAcc)
                end,
                Acc,
                Nodes).


%% 比較の内側のリテラルも、パターンやガードと同じ優先度にする。
-spec collect_op(erl_syntax:syntaxTree(), outside | latin1 | utf8, 0 | 1, map()) -> map().
collect_op(Node, Mode, Priority, Acc) ->
    case is_comparison(erl_syntax:operator(Node)) of
        true ->
            collect_children(Node, Mode, 1, Acc);
        false ->
            collect_children(Node, Mode, Priority, Acc)
    end.


-spec is_comparison(atom()) -> boolean().
is_comparison(Operator) ->
    lists:member(Operator, ['=:=', '==', '=/=', '/=', '<', '>', '=<', '>=']).


%% binary のフィールドを走査する。フィールドの型に utf8 があれば、本体の文字列は
%% Unicode の文字列として扱う。サイズ式は文字列ではないので latin1 で走査する。
-spec collect_binary_field(erl_syntax:syntaxTree(), 0 | 1, map()) -> map().
collect_binary_field(Field, Priority, Acc) ->
    Body0 = erl_syntax:binary_field_body(Field),
    Types = binary_field_types(Field),
    Mode =
        case lists:member(utf8, Types) of
            true ->
                utf8;
            false ->
                latin1
        end,
    case erl_syntax:type(Body0) of
        size_qualifier ->
            Body = erl_syntax:size_qualifier_body(Body0),
            Size = erl_syntax:size_qualifier_argument(Body0),
            Acc1 = collect_tree(Body, Mode, Priority, Acc),
            collect_tree(Size, latin1, Priority, Acc1);
        _ ->
            collect_tree(Body0, Mode, Priority, Acc)
    end.


-spec binary_field_types(erl_syntax:syntaxTree()) -> [term()].
binary_field_types(Field) ->
    [ erl_syntax:concrete(Type)
      || Type <:- erl_syntax:binary_field_types(Field) ].


%% 構文木のノードからリテラルを取り出す。
-spec collect_node(erl_syntax:syntaxTree(), outside | latin1 | utf8, 0 | 1, map()) -> map().
collect_node(Node, Mode, Priority, Acc) ->
    case erl_syntax:type(Node) of
        integer ->
            add_integer_entries(erl_syntax:integer_value(Node), Priority, Acc);
        char ->
            add_integer_entries(erl_syntax:char_value(Node), Priority, Acc);
        string ->
            add_string(erl_syntax:string_value(Node), Mode, Priority, Acc);
        binary ->
            add_binary_literal(Node, Priority, Acc);
        _ ->
            Acc
    end.


%% 文字列リテラルをバイト列にする。
-spec add_string(string(), outside | latin1 | utf8, 0 | 1, map()) -> map().
add_string(String, outside, Priority, Acc) ->
    add_string_bytes(string_bytes(String), Priority, Acc);
add_string(String, utf8, Priority, Acc) ->
    add_string_bytes(string_bytes(String), Priority, Acc);
add_string(String, latin1, Priority, Acc) ->
    add_string_bytes(latin1_bytes(String), Priority, Acc).


-spec add_string_bytes({ok, binary()} | error, 0 | 1, map()) -> map().
add_string_bytes({ok, Binary}, Priority, Acc) ->
    add_entry(Binary, Priority, Acc);
add_string_bytes(error, _Priority, Acc) ->
    Acc.


%% binary リテラルの静的に決まる先頭部分を組み立てる。
-spec add_binary_literal(erl_syntax:syntaxTree(), 0 | 1, map()) -> map().
add_binary_literal(Node, Priority, Acc) ->
    try assemble_binary(Node) of
        {ok, Binary} ->
            add_entry(Binary, Priority, Acc);
        {prefix, Binary} ->
            % 途中に変数フィールドがあっても、静的に決まる先頭部分は辞書に使える。
            add_entry(Binary, Priority, Acc);
        error ->
            Acc
    catch
        _:_ ->
            Acc
    end.


-spec assemble_binary(erl_syntax:syntaxTree()) -> {ok, binary()} | {prefix, binary()} | error.
assemble_binary(Node) ->
    case erl_syntax:type(Node) of
        binary ->
            assemble_fields(erl_syntax:binary_fields(Node), []);
        _ ->
            error
    end.


-spec assemble_fields([erl_syntax:syntaxTree()], [binary()]) ->
          {ok, binary()} | {prefix, binary()} | error.
assemble_fields([Field | Rest], Acc) ->
    case assemble_field(Field) of
        {ok, Binary} ->
            assemble_fields(Rest, [Binary | Acc]);
        {prefix, Binary} ->
            % 入れ子の binary が途中までしか決まらない場合も、その先頭部分までを
            % 外側の binary の先頭部分として使う。
            prefix_or_error([Binary | Acc]);
        error ->
            prefix_or_error(Acc)
    end;
assemble_fields([], Acc) ->
    {ok, iolist_to_binary(lists:reverse(Acc))}.


%% 静的フィールドが 1 つでもあれば、その先頭部分を返す。
-spec prefix_or_error([binary()]) -> {prefix, binary()} | error.
prefix_or_error([]) ->
    error;
prefix_or_error(Acc) ->
    {prefix, iolist_to_binary(lists:reverse(Acc))}.


-spec assemble_field(erl_syntax:syntaxTree()) -> {ok, binary()} | {prefix, binary()} | error.
assemble_field(Field) ->
    Body0 = erl_syntax:binary_field_body(Field),
    {Body, Size} =
        case erl_syntax:type(Body0) of
            size_qualifier ->
                {erl_syntax:size_qualifier_body(Body0),
                 erl_syntax:size_qualifier_argument(Body0)};
            _ ->
                {Body0, none}
        end,
    Types = [ erl_syntax:concrete(Type)
              || Type <:- erl_syntax:binary_field_types(Field) ],
    case erl_syntax:type(Body) of
        integer ->
            assemble_integer(erl_syntax:integer_value(Body), Size, Types);
        char ->
            assemble_integer(erl_syntax:char_value(Body), Size, Types);
        string ->
            assemble_string(erl_syntax:string_value(Body), Size, Types);
        binary ->
            case Size of
                none ->
                    assemble_binary(Body);
                _ ->
                    error
            end;
        _ ->
            error
    end.


-spec assemble_integer(integer(), none | erl_syntax:syntaxTree(), [term()]) ->
          {ok, binary()} | error.
assemble_integer(Integer, _Size, _Types) when Integer < 0 ->
    error;
assemble_integer(Integer, Size, Types) ->
    case lists:member(utf8, Types) of
        true ->
            assemble_utf8(Integer);
        false ->
            assemble_bits(Integer, Size, Types)
    end.


-spec assemble_utf8(integer()) -> {ok, binary()} | error.
assemble_utf8(Integer) ->
    try
        {ok, <<Integer/utf8>>}
    catch
        _:_ ->
            error
    end.


-spec assemble_bits(integer(), none | erl_syntax:syntaxTree(), [term()]) ->
          {ok, binary()} | error.
assemble_bits(Integer, Size, Types) ->
    case field_bits(Size, unit_size(Types)) of
        {ok, Bits} when Bits =< 64, Bits rem 8 =:= 0 ->
            case Integer < (1 bsl Bits) of
                true ->
                    assemble_endian(Integer, Bits, endian(Types));
                false ->
                    error
            end;
        _ ->
            error
    end.


-spec assemble_endian(integer(), pos_integer(), big | little | native) ->
          {ok, binary()} | error.
assemble_endian(Integer, Bits, little) ->
    {ok, <<Integer:Bits/little>>};
assemble_endian(Integer, Bits, big) ->
    {ok, <<Integer:Bits>>};
assemble_endian(_Integer, _Bits, native) ->
    error.


-spec assemble_string(string(), none | erl_syntax:syntaxTree(), [term()]) ->
          {ok, binary()} | error.
assemble_string(String, none, Types) ->
    case lists:member(utf8, Types) of
        true ->
            string_bytes(String);
        false ->
            case Types =:= [] orelse Types =:= [binary] of
                true ->
                    latin1_bytes(String);
                false ->
                    error
            end
    end;
assemble_string(_String, _Size, _Types) ->
    % サイズ指定付きの文字列は、パディングや切り詰めの解釈が曖昧なので扱わない。
    error.


%% フィールドのビット数を返す。サイズが変数などで静的に決まらない場合は error。
-spec field_bits(none | erl_syntax:syntaxTree(), pos_integer()) ->
          {ok, pos_integer()} | error.
field_bits(none, Unit) ->
    {ok, 8 * Unit};
field_bits(Size, Unit) ->
    case erl_syntax:type(Size) of
        integer ->
            Bits = erl_syntax:integer_value(Size) * Unit,
            case Bits > 0 of
                true ->
                    {ok, Bits};
                false ->
                    error
            end;
        _ ->
            error
    end.


-spec unit_size([term()]) -> pos_integer().
unit_size(Types) ->
    lists:foldl(fun({unit, Unit}, _Acc) when is_integer(Unit), Unit > 0 ->
                        Unit;
                   (_Type, Acc) ->
                        Acc
                end,
                1,
                Types).


-spec endian([term()]) -> big | little | native.
endian(Types) ->
    case lists:member(little, Types) of
        true ->
            little;
        false ->
            case lists:member(native, Types) of
                true ->
                    native;
                false ->
                    big
            end
    end.


%% literal chunk からもリテラルを取り出す。debug_info がないモジュールでも
%% binary や文字列を拾える。
-spec collect_literal_chunk(module(), map()) -> map().
collect_literal_chunk(Module, Acc) ->
    case module_beam(Module) of
        {ok, Beam} ->
            case beam_lib:chunks(Beam, [literals]) of
                {ok, {Module, [{literals, Literals}]}} ->
                    collect_terms([ Term || {_Index, Term} <:- Literals ], Acc);
                _ ->
                    Acc
            end;
        error ->
            Acc
    end.


-spec module_beam(module()) -> {ok, file:filename_all()} | error.
module_beam(Module) ->
    case code:which(Module) of
        Beam when is_list(Beam); is_binary(Beam) ->
            {ok, Beam};
        _ ->
            error
    end.


%% literal chunk の用語を再帰的に走査する。
-spec collect_terms([term()], map()) -> map().
collect_terms([Term | Rest], Acc) ->
    collect_terms(Rest, collect_term(Term, Acc));
collect_terms([], Acc) ->
    Acc.


-spec collect_term(term(), map()) -> map().
collect_term(Binary, Acc) when is_binary(Binary) ->
    add_entry(Binary, 0, Acc);
collect_term(Integer, Acc) when is_integer(Integer) ->
    add_integer_entries(Integer, 0, Acc);
collect_term(List, Acc) when is_list(List) ->
    case latin1_bytes(List) of
        {ok, Binary} ->
            add_entry(Binary, 0, Acc);
        error ->
            case string_bytes(List) of
                {ok, Binary} ->
                    add_entry(Binary, 0, Acc);
                error ->
                    lists:foldl(fun collect_term/2, Acc, List)
            end
    end;
collect_term(Tuple, Acc) when is_tuple(Tuple) ->
    collect_terms(tuple_to_list(Tuple), Acc);
collect_term(Map, Acc) when is_map(Map) ->
    maps:fold(fun(Key, Value, MapAcc) ->
                      collect_term(Value, collect_term(Key, MapAcc))
              end,
              Acc,
              Map);
collect_term(_Other, Acc) ->
    Acc.


%% 整数を big-endian と little-endian のバイト列にする。
-spec add_integer_entries(integer(), 0 | 1, map()) -> map().
add_integer_entries(Integer, Priority, Acc)
  when Integer >= ?MIN_INTEGER, Integer =< ?MAX_INTEGER ->
    lists:foldl(fun(Size, MapAcc) ->
                        BigEndian = <<Integer:Size/unit:8>>,
                        LittleEndian = <<Integer:Size/unit:8-little>>,
                        add_entry(LittleEndian,
                                  Priority,
                                  add_entry(BigEndian, Priority, MapAcc))
                end,
                Acc,
                integer_sizes(Integer));
add_integer_entries(_Integer, _Priority, Acc) ->
    Acc.


-spec integer_sizes(pos_integer()) -> [2 | 3 | 4 | 8].
integer_sizes(Integer) when Integer =< 16#FFFF ->
    [2];
integer_sizes(Integer) when Integer =< 16#FFFFFF ->
    [3];
integer_sizes(Integer) when Integer =< 16#FFFFFFFF ->
    [4];
integer_sizes(_Integer) ->
    [8].


%% 整数のリストを latin1 のバイト列として扱えるならバイト列にする。
-spec latin1_bytes([term()]) -> {ok, binary()} | error.
latin1_bytes([]) ->
    error;
latin1_bytes(List) ->
    case lists:all(fun(Char) ->
                           is_integer(Char) andalso Char >= 0 andalso Char =< 255
                   end,
                   List) of
        true ->
            {ok, list_to_binary(List)};
        false ->
            error
    end.


%% 整数のリストを Unicode の文字列として扱えるなら UTF-8 のバイト列にする。
-spec string_bytes([term()]) -> {ok, binary()} | error.
string_bytes([]) ->
    error;
string_bytes(List) ->
    case lists:all(fun erlang:is_integer/1, List) of
        true ->
            try unicode:characters_to_binary(List) of
                Binary when is_binary(Binary), byte_size(Binary) > 0 ->
                    {ok, Binary};
                _ ->
                    error
            catch
                _:_ ->
                    error
            end;
        false ->
            error
    end.


%% 辞書エントリーを追加する。空、長すぎる、重複したエントリーは無視する。
-spec add_entry(binary(), 0 | 1, map()) -> map().
add_entry(Binary, Priority, Acc) when byte_size(Binary) > 0,
                                      byte_size(Binary) =< ?MAX_ENTRY_BYTES ->
    Escaped = escape(Binary),
    maps:update_with(Escaped,
                     fun(OldPriority) ->
                             case OldPriority >= Priority of
                                 true ->
                                     OldPriority;
                                 false ->
                                     Priority
                             end
                     end,
                     Priority,
                     Acc);
add_entry(_Binary, _Priority, Acc) ->
    Acc.


%% libFuzzer の辞書形式へエスケープする。
-spec escape(binary()) -> binary().
escape(Binary) ->
    Escaped = [ escape_byte(Byte) || <<Byte>> <:= Binary ],
    iolist_to_binary([$", Escaped, $"]).


-spec escape_byte(byte()) -> binary().
escape_byte($") ->
    <<"\\\"">>;
escape_byte($\\) ->
    <<"\\\\">>;
escape_byte(Byte) when Byte >= 32, Byte =< 126 ->
    <<Byte>>;
escape_byte(Byte) ->
    <<"\\x", (hex_digit(Byte bsr 4)), (hex_digit(Byte band 16#0F))>>.


-spec hex_digit(0..15) -> byte().
hex_digit(Nibble) when Nibble < 10 ->
    $0 + Nibble;
hex_digit(Nibble) ->
    $a + (Nibble - 10).


-spec user_dict_content(undefined | file:filename_all()) -> {ok, binary()} | {error, term()}.
user_dict_content(undefined) ->
    {ok, <<>>};
user_dict_content(Path) ->
    case file:read_file(Path) of
        {ok, Binary} ->
            {ok, Binary};
        {error, Reason} ->
            {error, {read_failed, Path, Reason}}
    end.


%% 一時ファイルを置くディレクトリを返す。
%%
%% abort で BEAM が落ちても artifacts ディレクトリを汚さないよう、システムの
%% 一時ディレクトリを使う。
-spec temp_directory() -> file:filename_all().
temp_directory() ->
    case os:getenv("TMPDIR") of
        false ->
            "/tmp";
        Directory ->
            Directory
    end.


%% 利用者の辞書の末尾に改行がなければ補う。
-spec ensure_newline(binary()) -> binary().
ensure_newline(<<>>) ->
    <<>>;
ensure_newline(Binary) ->
    case binary:last(Binary) of
        $\n ->
            Binary;
        _ ->
            <<Binary/binary, $\n>>
    end.
