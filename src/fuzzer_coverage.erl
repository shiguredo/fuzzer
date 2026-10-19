%% 節 (clause) 単位のカバレッジ計測。
%%
%% このモジュールは 2 つの役割を持つ。
%%
%%   1. abstract code を走査し、関数・case・if・receive・try・fun・maybe の
%%      すべての節の本体先頭へ fuzzer_coverage:hit/1 の呼び出しを挿入する。
%%   2. 挿入した呼び出しが更新するカウンターを atomics で保持し、入力ごとに
%%      読み出して 0 に戻す。
%%
%% 節の識別子はモジュールごとに Base から連番で割り当てる。fuzzer_feedback は
%% 複数モジュール分の節を 1 個の atomics 配列へ詰め、その全体を libFuzzer の
%% カウンターへ渡す。
%%
%% カウンターは fuzzing 専用の BEAM で 1 個のワーカーだけが更新することを前提に
%% している。他のプロセスが同じ計測対象を実行すると、その分もカウントされる。
-module(fuzzer_coverage).

-export([parse_transform/2,
         instrument/2,
         init/1,
         stop/0,
         reset/0,
         read_and_reset/2,
         hit/1]).

%% 節の識別子を割り当てるためのプロセス辞書のキー。
-define(NEXT_ID_KEY, {?MODULE, next_id}).
%% 現在のカウンターを保持する persistent_term のキー。
-define(STATE_KEY, {?MODULE, state}).


%% 通常の parse transform として使う場合の入口。
%%
%% この入口では節の識別子を 0 から割り当てる。fuzzer 本体は複数モジュールの
%% 節を 1 個の配列へまとめるため、instrument/2 に Base を渡して使う。
-spec parse_transform([term()], [term()]) -> [term()].
parse_transform(Forms, _Options) ->
    {Forms2, _Count} = instrument(Forms, 0),
    Forms2.


%% abstract code の全節へ hit/1 の呼び出しを挿入し、割り当てた節の数を返す。
%%
%% Base はこのモジュールの最初の節に割り当てる識別子である。戻り値の Count は
%% Base から Base + Count - 1 までを使ったことを意味する。
-spec instrument([term()], non_neg_integer()) -> {[term()], non_neg_integer()}.
instrument(Forms, Base) when is_list(Forms), is_integer(Base), Base >= 0 ->
    put(?NEXT_ID_KEY, Base),
    try
        Tree = erl_syntax:form_list(Forms),
        Tree2 = erl_syntax_lib:map(fun instrument_node/1, Tree),
        Forms2 = erl_syntax:revert_forms(Tree2),
        Count = get(?NEXT_ID_KEY) - Base,
        {Forms2, Count}
    after
        erase(?NEXT_ID_KEY)
    end.


%% 節を持つ構文木を探し、本体の先頭へ計測用の呼び出しを挿入する。
%%
%% erl_syntax_lib:map/2 は子から親へ向かう順に適用される。節の本体を書き換えた
%% 後に、その節自身がもう一度走査されることはないため、挿入した呼び出しが
%% 二重に計測されることはない。
-spec instrument_node(erl_syntax:syntaxTree()) -> erl_syntax:syntaxTree().
instrument_node(Node) ->
    case erl_syntax:type(Node) of
        clause ->
            instrument_clause(Node);
        receive_expr ->
            instrument_receive_expr(Node);
        _ ->
            Node
    end.


%% 通常の節の本体先頭へ hit/1 を挿入する。
-spec instrument_clause(erl_syntax:syntaxTree()) -> erl_syntax:syntaxTree().
instrument_clause(Node) ->
    Position = erl_syntax:get_pos(Node),
    Body = erl_syntax:clause_body(Node),
    % 計測呼び出しは最初の本体式と同じ行に置く。line_coverage と併用したときに
    % 節の見出し行が新しい実行行として追加されるのを避けるため。
    Hit = hit_call(next_id(), body_position(Body, Position)),
    New =
        erl_syntax:clause(erl_syntax:clause_patterns(Node),
                          erl_syntax:clause_guard(Node),
                          [Hit | Body]),
    erl_syntax:set_pos(New, Position).


%% receive の after 本体は節ではないが、タイムアウト側の分岐を表すため
%% 同じように計測する。after のない receive は節だけを計測する。
-spec instrument_receive_expr(erl_syntax:syntaxTree()) -> erl_syntax:syntaxTree().
instrument_receive_expr(Node) ->
    case erl_syntax:receive_expr_timeout(Node) of
        none ->
            Node;
        Timeout ->
            Position = erl_syntax:get_pos(Node),
            Action = erl_syntax:receive_expr_action(Node),
            Hit = hit_call(next_id(), body_position(Action, Position)),
            New =
                erl_syntax:receive_expr(erl_syntax:receive_expr_clauses(Node),
                                        Timeout,
                                        [Hit | Action]),
            erl_syntax:set_pos(New, Position)
    end.


%% 次の節の識別子を返し、内部の連番を 1 つ進める。
-spec next_id() -> non_neg_integer().
next_id() ->
    Id = get(?NEXT_ID_KEY),
    put(?NEXT_ID_KEY, Id + 1),
    Id.


%% 最初の本体式の位置を返す。本体が空の場合は節の位置を使う。
-spec body_position([erl_syntax:syntaxTree()], erl_anno:anno()) -> erl_anno:anno().
body_position([First | _Rest], _Default) ->
    erl_syntax:get_pos(First);
body_position([], Default) ->
    Default.


%% 節の本体先頭へ挿入する fuzzer_coverage:hit(Id) を組み立てる。
-spec hit_call(non_neg_integer(), erl_anno:anno()) -> erl_syntax:syntaxTree().
hit_call(Id, Position) ->
    Call =
        erl_syntax:application(erl_syntax:atom(?MODULE),
                               erl_syntax:atom(hit),
                               [erl_syntax:integer(Id)]),
    erl_syntax:set_pos(Call, Position).


%% 節の数だけカウンターを確保する。
%%
%% 節が 1 個もない場合は persistent_term を消し、hit/1 を無効にする。
%% 戻り値の ref は read_and_reset/2 に渡す。節がない場合は undefined になる。
-spec init(non_neg_integer()) -> {ok, undefined | reference()}.
init(0) ->
    stop(),
    {ok, undefined};
init(Count) when is_integer(Count), Count > 0 ->
    Ref = atomics:new(Count, [{signed, false}]),
    persistent_term:put(?STATE_KEY, {Ref, Count}),
    {ok, Ref}.


%% カウンターを破棄する。fuzzing の終了時に呼ぶ。
-spec stop() -> ok.
stop() ->
    _ = persistent_term:erase(?STATE_KEY),
    ok.


%% すべてのカウンターを 0 に戻す。
%%
%% fuzz target の reset/0 が実行した分を評価対象から外すため、reset/0 の直後、
%% evaluate/1 の直前に呼ぶ。
-spec reset() -> ok.
reset() ->
    case persistent_term:get(?STATE_KEY, undefined) of
        undefined ->
            ok;
        {Ref, Count} ->
            reset_counters(Ref, Count, 1)
    end.


%% すべてのカウンターを読み出し、同時に 0 へ戻す。
%%
%% atomics:exchange/3 を使って読み出しと初期化を 1 回の走査で行う。
-spec read_and_reset(undefined | reference(), non_neg_integer()) ->
          [non_neg_integer()].
read_and_reset(undefined, _Count) ->
    [];
read_and_reset(_Ref, 0) ->
    [];
read_and_reset(Ref, Count) when is_reference(Ref), is_integer(Count), Count > 0 ->
    read_and_reset(Ref, Count, 1, []).


%% 節が実行されるたびに呼ばれる計測用の関数。
%%
%% fuzzing 中以外 (通常のアプリケーション実行やテスト) に呼ばれても壊れないよう、
%% カウンターが初期化されていない場合は何もしない。
-spec hit(non_neg_integer()) -> ok.
hit(Id) when is_integer(Id), Id >= 0 ->
    case persistent_term:get(?STATE_KEY, undefined) of
        undefined ->
            ok;
        {Ref, _Count} ->
            atomics:add(Ref, Id + 1, 1)
    end.


-spec reset_counters(reference(), non_neg_integer(), pos_integer()) -> ok.
reset_counters(_Ref, 0, _Index) ->
    ok;
reset_counters(Ref, Count, Index) ->
    atomics:put(Ref, Index, 0),
    reset_counters(Ref, Count - 1, Index + 1).


-spec read_and_reset(reference(), non_neg_integer(), pos_integer(), [non_neg_integer()]) ->
          [non_neg_integer()].
read_and_reset(_Ref, 0, _Index, Acc) ->
    lists:reverse(Acc);
read_and_reset(Ref, Count, Index, Acc) ->
    Value = atomics:exchange(Ref, Index, 0),
    read_and_reset(Ref, Count - 1, Index + 1, [Value | Acc]).
