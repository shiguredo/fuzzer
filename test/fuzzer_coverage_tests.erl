-module(fuzzer_coverage_tests).

-include_lib("eunit/include/eunit.hrl").


clause_instrumentation_test_() ->
    {timeout, 30, fun clause_instrumentation/0}.


if_instrumentation_test_() ->
    {timeout, 30, fun if_instrumentation/0}.


parse_transform_test() ->
    Forms = sample_forms(),
    Instrumented = fuzzer_coverage:parse_transform(Forms, []),
    % 節の本体先頭に計測呼び出しが入るため、元のフォームより要素が増える。
    ?assert(is_list(Instrumented)),
    ?assert(length(Instrumented) >= length(Forms)),
    % 生成したフォームがそのままコンパイルできることを確認する。
    ?assertMatch({ok, fuzzer_clause_sample, _},
                 compile:forms(Instrumented, [binary, return_errors])).


counter_reset_test() ->
    fuzzer_coverage:stop(),
    {ok, Ref} = fuzzer_coverage:init(3),
    try
        ok = fuzzer_coverage:reset(),
        ok = fuzzer_coverage:hit(0),
        ok = fuzzer_coverage:hit(2),
        % 読み出しと同時に 0 に戻る。
        ?assertEqual([1, 0, 1], fuzzer_coverage:read_and_reset(Ref, 3)),
        ?assertEqual([0, 0, 0], fuzzer_coverage:read_and_reset(Ref, 3)),
        ok = fuzzer_coverage:hit(1),
        ok = fuzzer_coverage:reset(),
        ?assertEqual([0, 0, 0], fuzzer_coverage:read_and_reset(Ref, 3))
    after
        fuzzer_coverage:stop()
    end.


hit_without_init_test() ->
    fuzzer_coverage:stop(),
    % 計測用のカウンターが初期化されていなくても、通常の実行を壊さない。
    ?assertEqual(ok, fuzzer_coverage:hit(0)).


%% すべての節に計測呼び出しが入り、実行した節だけがカウントされることを確認する。
clause_instrumentation() ->
    Forms = sample_forms(),
    {Instrumented, Count} = fuzzer_coverage:instrument(Forms, 0),
    % 次の節の数:
    %   clauses/2           関数節 2
    %   case_clauses/1      関数節 1 + case 節 3
    %   receive_clauses/1   関数節 1 + receive 節 2 + after 本体 1
    %   try_clauses/1       関数節 1 + case 節 2 + of 節 1 + catch 節 2
    %   fun_clauses/1       関数節 1 + fun 節 2
    %   maybe_clauses/1     関数節 1 + maybe の else 節 2
    %   receive_after/0     関数節 1 + receive 節 1 + after 本体 1
    ?assertEqual(25, Count),
    Name = instrumented_module_name(),
    ok = load_instrumented(Name, Instrumented),
    {ok, Ref} = fuzzer_coverage:init(Count),
    try
        % 関数節の選択が区別できる。
        A = nonzero(Name, Ref, Count, clauses, [a, 1]),
        B = nonzero(Name, Ref, Count, clauses, [b, 1]),
        ?assertEqual(1, length(A)),
        ?assertEqual(1, length(B)),
        ?assertNotEqual(A, B),

        % case の節の選択が区別できる。関数節と選択した節の 2 個が立つ。
        CaseOne = nonzero(Name, Ref, Count, case_clauses, [1]),
        CaseOther = nonzero(Name, Ref, Count, case_clauses, [3]),
        ?assertEqual(2, length(CaseOne)),
        ?assertEqual(2, length(CaseOther)),
        ?assertNotEqual(CaseOne, CaseOther),

        % receive の節の選択が区別できる。after は実行されない。
        ReceiveOne = nonzero(Name, Ref, Count, receive_clauses, [1]),
        ReceiveOther = nonzero(Name, Ref, Count, receive_clauses, [2]),
        ?assertEqual(2, length(ReceiveOne)),
        ?assertEqual(2, length(ReceiveOther)),
        ?assertNotEqual(ReceiveOne, ReceiveOther),

        % try の of 節と catch 節の選択が区別できる。
        TryOf = nonzero(Name, Ref, Count, try_clauses, [ok]),
        TryCatch = nonzero(Name, Ref, Count, try_clauses, [badarg]),
        ?assertEqual(3, length(TryOf)),
        ?assertEqual(3, length(TryCatch)),
        ?assertNotEqual(TryOf, TryCatch),

        % fun の節の選択が区別できる。
        FunOne = nonzero(Name, Ref, Count, fun_clauses, [1]),
        FunOther = nonzero(Name, Ref, Count, fun_clauses, [2]),
        ?assertEqual(2, length(FunOne)),
        ?assertEqual(2, length(FunOther)),
        ?assertNotEqual(FunOne, FunOther),

        % maybe の本体が成功した場合は else 節を通らない。
        MaybeOk = nonzero(Name, Ref, Count, maybe_clauses, [{ok, 1}]),
        ?assertEqual(1, length(MaybeOk)),
        % else 節の選択が区別できる。関数節と選択した else 節の 2 個が立つ。
        MaybeError = nonzero(Name, Ref, Count, maybe_clauses, [error]),
        MaybeOther = nonzero(Name, Ref, Count, maybe_clauses, [other]),
        ?assertEqual(2, length(MaybeError)),
        ?assertEqual(2, length(MaybeOther)),
        ?assertNotEqual(MaybeError, MaybeOther),

        % receive の節はメッセージがないため選ばれず、after の本体だけが
        % 関数節と合わせて 2 個立つ。
        After = nonzero(Name, Ref, Count, receive_after, []),
        ?assertEqual(2, length(After))
    after
        fuzzer_coverage:stop(),
        _ = code:delete(Name),
        _ = code:purge(Name)
    end.


%% if 節もほかの節と同じように計測できることを確認する。
%%
%% if 式は elint の case_over_if に引っかかるため、サンプルモジュールには置かず、
%% テスト時に生成したモジュールを計測する。
if_instrumentation() ->
    Name = instrumented_module_name(),
    Forms = source_forms(if_sample_source(Name), Name),
    {Instrumented, Count} = fuzzer_coverage:instrument(Forms, 0),
    % 関数節 1 + if 節 3
    ?assertEqual(4, Count),
    ok = load_instrumented(Name, Instrumented),
    {ok, Ref} = fuzzer_coverage:init(Count),
    try
        % 関数節と選択した if 節の 2 個が立つ。
        IfOne = nonzero(Name, Ref, Count, if_clauses, [1]),
        IfOther = nonzero(Name, Ref, Count, if_clauses, [3]),
        ?assertEqual(2, length(IfOne)),
        ?assertEqual(2, length(IfOther)),
        ?assertNotEqual(IfOne, IfOther)
    after
        fuzzer_coverage:stop(),
        _ = code:delete(Name),
        _ = code:purge(Name)
    end.


%% サンプルモジュールの abstract code を取得する。
-spec sample_forms() -> [term()].
sample_forms() ->
    Beam = code:which(fuzzer_clause_sample),
    {ok, {fuzzer_clause_sample, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
        beam_lib:chunks(Beam, [abstract_code]),
    Forms.


%% 元のモジュールを書き換えないよう、テストごとに別名のモジュールとしてロードする。
-spec instrumented_module_name() -> module().
instrumented_module_name() ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    list_to_atom("fuzzer_clause_sample_instrumented_" ++ Unique).


%% 計測用フォームの module 属性を Name に変えてコンパイルし、ロードする。
-spec load_instrumented(module(), [term()]) -> ok.
load_instrumented(Name, Forms) ->
    Renamed =
        [ case Form of
              {attribute, Anno, module, _OldName} ->
                  {attribute, Anno, module, Name};
              _ ->
                  Form
          end
          || Form <:- Forms ],
    Binary =
        case compile:forms(Renamed,
                           [binary, debug_info, return_errors,
                            return_warnings]) of
            {ok, Name, Compiled} ->
                Compiled;
            {ok, Name, Compiled, _Warnings} ->
                Compiled;
            {error, Errors, Warnings} ->
                erlang:error({compile_failed, Errors, Warnings})
        end,
    case code:load_binary(Name, "fuzzer_clause_sample_instrumented.erl", Binary) of
        {module, Name} ->
            ok;
        {error, Reason} ->
            erlang:error({load_failed, Name, Reason})
    end.


%% if 式を含むモジュールのソースを返す。
-spec if_sample_source(module()) -> string().
if_sample_source(Name) ->
    lists:flatten(
      io_lib:format("-module(~p).~n"
                    "-export([if_clauses/1]).~n"
                    "if_clauses(Value) ->~n"
                    "    if~n"
                    "        Value =:= 1 ->~n"
                    "            one;~n"
                    "        Value =:= 2 ->~n"
                    "            two;~n"
                    "        true ->~n"
                    "            other~n"
                    "    end.~n",
                    [Name])).


%% ソース文字列を debug_info 付きでコンパイルし、abstract code を取り出す。
%%
%% elint の対象にならない if 式のテスト用モジュールを、テストの実行時に作る。
-spec source_forms(string(), module()) -> [term()].
source_forms(Source, Name) ->
    Dir = test_directory(),
    SourcePath = filename:join(Dir, atom_to_list(Name) ++ ".erl"),
    try
        ok = filelib:ensure_dir(SourcePath),
        ok = file:write_file(SourcePath, Source),
        {ok, Name} = compile:file(SourcePath,
                                  [{outdir, Dir}, debug_info, return_errors]),
        Beam = filename:join(Dir, atom_to_list(Name) ++ ".beam"),
        {ok, {Name, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
            beam_lib:chunks(Beam, [abstract_code]),
        Forms
    after
        _ = file:del_dir_r(Dir)
    end.


-spec test_directory() -> file:filename_all().
test_directory() ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    filename:absname(filename:join(["_build", "fuzzer_coverage_test", Unique])).


%% 1 回呼び出して、カウントが増えた節の位置を返す。
-spec nonzero(module(),
              reference(),
              non_neg_integer(),
              atom(),
              [term()]) -> [pos_integer()].
nonzero(Name, Ref, Count, Function, Arguments) ->
    ok = fuzzer_coverage:reset(),
    _ = apply(Name, Function, Arguments),
    Counters = fuzzer_coverage:read_and_reset(Ref, Count),
    [ Index
      || {Index, Value} <:- lists:zip(lists:seq(1, Count), Counters),
         Value > 0 ].
