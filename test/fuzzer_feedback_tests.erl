-module(fuzzer_feedback_tests).

-include_lib("eunit/include/eunit.hrl").


line_feedback_test_() ->
    {timeout, 30, fun line_feedback/0}.


clause_feedback_test_() ->
    {timeout, 30, fun clause_feedback/0}.


saturation_test_() ->
    {timeout, 30, fun saturation/0}.


same_line_clause_test_() ->
    {timeout, 30, fun same_line_clause/0}.


read_reset_test_() ->
    {timeout, 30, fun read_reset/0}.


reset_clears_test_() ->
    {timeout, 30, fun reset_clears/0}.


missing_module_test_() ->
    {timeout, 30,
              ?_assertError({feedback, {module_not_found, no_such_feedback_module, non_existing}},
                            fuzzer_feedback:setup(#{
                                                    modules => [no_such_feedback_module],
                                                    mode => line
                                                   }))}.


already_running_test() ->
    % 別のプロセスが feedback をセットアップ中であることを模擬する。
    true = global:set_lock({fuzzer_feedback, fake_requester}, [node()], 0),
    try
        ?assertError({feedback, already_running},
                     fuzzer_feedback:setup(#{
                                             modules => [fuzzer_feedback_parser],
                                             mode => line
                                            }))
    after
        true = global:del_lock({fuzzer_feedback, fake_requester}, [node()])
    end.


no_debug_info_test_() ->
    {timeout, 30, fun no_debug_info/0}.


export_all_option_test_() ->
    {timeout, 30, fun export_all_option/0}.


line_feedback_finds_crash_test_() ->
    {timeout, 120, fun line_feedback_finds_crash/0}.


reset_target_feedback_finds_crash_test_() ->
    {timeout, 120, fun reset_target_feedback_finds_crash/0}.


continue_feedback_test_() ->
    {timeout, 120, fun continue_feedback/0}.


continue_timeout_feedback_test_() ->
    {timeout, 30, fun continue_timeout_feedback/0}.


clause_feedback_finds_crash_test_() ->
    {timeout, 120, fun clause_feedback_finds_crash/0}.


%% 行カバレッジが入力に応じて増えることを確認する。
line_feedback() ->
    OldMode = code:get_coverage_mode(),
    State = fuzzer_feedback:setup(#{
                                    modules => [fuzzer_feedback_parser],
                                    mode => line
                                   }),
    try
        ?assert(fuzzer_feedback:counter_count(State) >= 6),
        % AB では check/1 と check_b/1 の一致行と、check_c/1 の
        % 不一致行の 3 行が実行される。
        AB = nonzero_indexes(State, fuzzer_feedback_parser, <<"AB">>),
        ?assertEqual(3, length(AB)),
        % ABC では check_c/1 の一致行が実行され、AB とは別の行が立つ。
        ABC = nonzero_indexes(State, fuzzer_feedback_parser, <<"ABC">>),
        ?assertEqual(3, length(ABC)),
        ?assertNotEqual(AB, ABC),
        % 入力間でカウンターが持ち越されない。
        ?assertEqual(AB, nonzero_indexes(State, fuzzer_feedback_parser, <<"AB">>))
    after
        fuzzer_feedback:teardown(State)
    end,
    ?assertEqual(OldMode, code:get_coverage_mode()),
    % teardown が同時実行用のロックを解放していることを確認する。
    true = global:set_lock({fuzzer_feedback, lock_probe}, [node()], 0),
    true = global:del_lock({fuzzer_feedback, lock_probe}, [node()]).


%% 節カバレッジが入力に応じて増えることを確認する。
clause_feedback() ->
    OldMode = code:get_coverage_mode(),
    State = fuzzer_feedback:setup(#{
                                    modules => [fuzzer_feedback_parser],
                                    mode => clause
                                   }),
    try
        ?assert(fuzzer_feedback:counter_count(State) >= 6),
        AB = nonzero_indexes(State, fuzzer_feedback_parser, <<"AB">>),
        ABC = nonzero_indexes(State, fuzzer_feedback_parser, <<"ABC">>),
        ?assertEqual(3, length(AB)),
        ?assertEqual(3, length(ABC)),
        ?assertNotEqual(AB, ABC),
        ?assertEqual(AB, nonzero_indexes(State, fuzzer_feedback_parser, <<"AB">>))
    after
        fuzzer_feedback:teardown(State)
    end,
    % clause モードは native coverage の mode を変更しない。
    ?assertEqual(OldMode, code:get_coverage_mode()).


%% read(State, true) が読み出し後にカウンターを 0 に戻すことを確認する。
%%
%% reset/0 を持たない target では、この経路で次の入力を 0 から始める。
read_reset() ->
    lists:foreach(fun(Mode) ->
                          State = fuzzer_feedback:setup(#{
                                                          modules => [fuzzer_feedback_parser],
                                                          mode => Mode
                                                         }),
                          try
                              ok = fuzzer_feedback:reset(State),
                              _ = fuzzer_feedback_parser:check(<<"AB">>),
                              First = binary_to_list(fuzzer_feedback:read(State, true)),
                              ?assert(lists:any(fun(Value) -> Value > 0 end, First)),
                              Second = binary_to_list(fuzzer_feedback:read(State, true)),
                              ?assertEqual([], [ Value || Value <:- Second, Value =/= 0 ])
                          after
                              fuzzer_feedback:teardown(State)
                          end
                  end,
                  [line, clause]).


%% reset/1 が line と clause のカウンターを 0 に戻すことを確認する。
reset_clears() ->
    lists:foreach(fun(Mode) ->
                          State = fuzzer_feedback:setup(#{
                                                          modules => [fuzzer_feedback_parser],
                                                          mode => Mode
                                                         }),
                          try
                              ok = fuzzer_feedback:reset(State),
                              _ = fuzzer_feedback_parser:check(<<"AB">>),
                              Before = binary_to_list(fuzzer_feedback:read(State, false)),
                              ?assert(lists:any(fun(Value) -> Value > 0 end, Before)),
                              ok = fuzzer_feedback:reset(State),
                              After = binary_to_list(fuzzer_feedback:read(State, true)),
                              ?assertEqual([], [ Value || Value <:- After, Value =/= 0 ])
                          after
                              fuzzer_feedback:teardown(State)
                          end
                  end,
                  [line, clause]).


%% カウンターが 255 を超えても、1 バイトのカウンターへ飽和させて渡すことを確認する。
saturation() ->
    State = fuzzer_feedback:setup(#{
                                    modules => [fuzzer_feedback_parser],
                                    mode => clause
                                   }),
    try
        ok = fuzzer_feedback:reset(State),
        lists:foreach(fun(_) -> _ = fuzzer_feedback_parser:check(<<"ABC">>) end,
                      lists:seq(1, 300)),
        Counters = binary_to_list(fuzzer_feedback:read(State)),
        ?assertEqual(6, length(Counters)),
        % ABC で立つ 3 個の節は 300 回実行され、255 に飽和する。
        ?assertEqual([255, 255, 255],
                     [ Value || Value <:- Counters, Value > 0 ])
    after
        fuzzer_feedback:teardown(State)
    end.


%% debug_info のないモジュールは feedback の対象にできないことを確認する。
no_debug_info() ->
    Dir = test_directory(),
    Name = list_to_atom("fuzzer_feedback_no_debug_info_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    Source = filename:join(Dir, atom_to_list(Name) ++ ".erl"),
    try
        ok = filelib:ensure_dir(Source),
        Body =
            lists:flatten(
              io_lib:format("-module(~p).~n-export([f/0]).~nf() -> ok.~n", [Name])),
        ok = file:write_file(Source, Body),
        {ok, Name} = compile:file(Source, [{outdir, Dir}, return_errors]),
        true = code:add_patha(Dir),
        % debug_info がないため abstract code を取り出せず、セットアップが失敗する。
        ?assertError({feedback, {no_debug_info, Name}},
                     fuzzer_feedback:setup(#{modules => [Name], mode => line}))
    after
        _ = code:del_path(Dir),
        _ = file:del_dir_r(Dir)
    end.


%% コンパイルオプションで export_all を付けたモジュールでも、feedback の
%% 再コンパイル後に内部関数が公開されたままであることを確認する。
export_all_option() ->
    Dir = test_directory(),
    Name = list_to_atom("fuzzer_feedback_export_all_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    Source = filename:join(Dir, atom_to_list(Name) ++ ".erl"),
    Body = lists:flatten(io_lib:format("-module(~p).~n"
                                       "-export([public/0]).~n"
                                       "public() -> internal().~n"
                                       "internal() -> ok.~n",
                                       [Name])),
    try
        ok = filelib:ensure_dir(Source),
        ok = file:write_file(Source, Body),
        % -export 属性ではなくコンパイルオプションで export_all を付ける。
        {ok, Name} = compile:file(Source,
                                  [export_all,
                                   {outdir, Dir},
                                   debug_info,
                                   return_errors]),
        true = code:add_patha(Dir),
        {module, Name} = code:ensure_loaded(Name),
        ?assert(erlang:function_exported(Name, internal, 0)),
        lists:foreach(fun(Mode) ->
                              State = fuzzer_feedback:setup(#{
                                                              modules => [Name],
                                                              mode => Mode
                                                             }),
                              try
                                  ?assert(erlang:function_exported(Name, internal, 0))
                              after
                                  fuzzer_feedback:teardown(State)
                              end,
                              ?assert(erlang:function_exported(Name, internal, 0))
                      end,
                      [line, clause])
    after
        _ = code:del_path(Dir),
        % teardown で元のコードへ戻した分の古いコードを先に破棄する。
        _ = code:purge(Name),
        _ = code:delete(Name),
        _ = code:purge(Name),
        _ = file:del_dir_r(Dir)
    end.


%% 行カバレッジのフィードバックだけで ABC を見つけられることを確認する。
line_feedback_finds_crash() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Options =
                  #{
                    target => fuzzer_feedback_target,
                    runs => 200000,
                    max_length => 16,
                    corpus => CorpusDir,
                    artifacts => ArtifactDir,
                    seed => 1,
                    feedback => [fuzzer_feedback_parser]
                   },
              ?assertNotEqual(0, run_in_subprocess(Options)),
              ?assertEqual(true, has_crash_artifact(ArtifactDir))
      end).


%% reset/0 を持つ target でも、評価前リセットの経路を通して ABC を
%% 見つけられることを確認する。
reset_target_feedback_finds_crash() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Options =
                  #{
                    target => fuzzer_feedback_reset_target,
                    runs => 200000,
                    max_length => 16,
                    corpus => CorpusDir,
                    artifacts => ArtifactDir,
                    seed => 1,
                    feedback => [fuzzer_feedback_parser]
                   },
              ?assertNotEqual(0, run_in_subprocess(Options)),
              ?assertEqual(true, has_crash_artifact(ArtifactDir))
      end).


%% feedback 付きでクラッシュしても継続し、クラッシュ後のカウンターを
%% 次の入力へ持ち越さないことを確認する。
continue_feedback() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Result =
                  fuzzer:run(#{
                               target => fuzzer_feedback_target,
                               runs => 200000,
                               max_length => 16,
                               corpus => CorpusDir,
                               artifacts => ArtifactDir,
                               seed => 1,
                               feedback => [fuzzer_feedback_parser],
                               on_crash => continue
                              }),
              ?assertEqual(0, maps:get(exit_code, Result)),
              Crashes = maps:get(crashes, Result),
              ?assertEqual(1, length(Crashes)),
              [Crash] = Crashes,
              ?assertMatch(#{
                             crash_id := #{
                                           class := crash,
                                           reason := target_returned_crash
                                          }
                            },
                           Crash),
              {ok, Files} = file:list_dir(ArtifactDir),
              ?assertEqual(1,
                           length([ File
                                    || File <:- Files,
                                       lists:prefix("crash-", File),
                                       not lists:suffix(".report", File) ])),
              ?assertEqual(1,
                           length([ File
                                    || File <:- Files,
                                       lists:suffix(".report", File) ]))
      end).


%% feedback 付きでタイムアウトしてもワーカーを作り直して継続できることを確認する。
continue_timeout_feedback() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Result =
                  fuzzer:run(#{
                               target => fuzzer_timeout_target,
                               runs => 2,
                               max_length => 8,
                               corpus => CorpusDir,
                               artifacts => ArtifactDir,
                               timeout => 1,
                               feedback => [fuzzer_timeout_target],
                               on_crash => continue
                              }),
              ?assertEqual(0, maps:get(exit_code, Result)),
              Crashes = maps:get(crashes, Result),
              ?assertEqual(1, length(Crashes)),
              ?assertMatch(#{crash_id := #{class := crash, reason := timeout}},
                           hd(Crashes))
      end).


%% 節カバレッジのフィードバックだけで ABC を見つけられることを確認する。
clause_feedback_finds_crash() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Options =
                  #{
                    target => fuzzer_feedback_target,
                    runs => 200000,
                    max_length => 16,
                    corpus => CorpusDir,
                    artifacts => ArtifactDir,
                    seed => 1,
                    feedback =>
                        #{modules => [fuzzer_feedback_parser], mode => clause}
                   },
              ?assertNotEqual(0, run_in_subprocess(Options)),
              ?assertEqual(true, has_crash_artifact(ArtifactDir))
      end).


%% 1 回の入力評価で立ったカウンターの位置を返す。
-spec nonzero_indexes(fuzzer_feedback:state(), module(), binary()) -> [pos_integer()].
nonzero_indexes(State, Module, Data) ->
    ok = fuzzer_feedback:reset(State),
    _ = Module:check(Data),
    Counters = binary_to_list(fuzzer_feedback:read(State)),
    [ Index
      || {Index, Value} <:- lists:zip(lists:seq(1, length(Counters)), Counters),
         Value > 0 ].


%% 同じ行に複数の節がある場合、line では節を区別できず、clause では区別できる
%% ことを確認する。同じ行の分岐に clause モードを使う理由をここで担保する。
same_line_clause() ->
    Dir = test_directory(),
    Name = list_to_atom("fuzzer_feedback_same_line_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    SourcePath = filename:join(Dir, atom_to_list(Name) ++ ".erl"),
    try
        ok = filelib:ensure_dir(SourcePath),
        ok = file:write_file(SourcePath, same_line_source(Name)),
        {ok, Name} = compile:file(SourcePath,
                                  [{outdir, Dir}, debug_info, return_errors]),
        true = code:add_patha(Dir),
        % すべての節が 1 行にあるため、line モードでは AB も ABCDEF も同じ
        % 行カウンターだけが立つ。
        LineState = fuzzer_feedback:setup(#{modules => [Name], mode => line}),
        try
            ?assertEqual(nonzero_indexes(LineState, Name, <<"AB">>),
                         nonzero_indexes(LineState, Name, <<"ABCDEF">>))
        after
            fuzzer_feedback:teardown(LineState)
        end,
        % clause モードでは段階ごとに違う節が立つ。
        ClauseState = fuzzer_feedback:setup(#{modules => [Name], mode => clause}),
        try
            AB = nonzero_indexes(ClauseState, Name, <<"AB">>),
            ABCDEF = nonzero_indexes(ClauseState, Name, <<"ABCDEF">>),
            ?assertNotEqual(AB, ABCDEF)
        after
            fuzzer_feedback:teardown(ClauseState)
        end
    after
        _ = code:del_path(Dir),
        _ = code:purge(Name),
        _ = code:delete(Name),
        _ = code:purge(Name),
        _ = file:del_dir_r(Dir)
    end.


%% すべての節を 1 行に書いたパーサーのソースを返す。
-spec same_line_source(module()) -> string().
same_line_source(Name) ->
    lists:flatten(
      io_lib:format("-module(~p).~n"
                    "-export([check/1]).~n"
                    "check(<<$A,R/binary>>) -> case R of <<$B,R2/binary>> -> "
                    "case R2 of <<$C,R3/binary>> -> case R3 of <<$D,R4/binary>> -> "
                    "case R4 of <<$E,R5/binary>> -> case R5 of <<$F,_/binary>> -> true; "
                    "_ -> false end; _ -> false end; _ -> false end; "
                    "_ -> false end; _ -> false end; check(_) -> false.~n",
                    [Name])).


%% テスト用のコーパスと artifact ディレクトリーを用意し、処理後に削除する。
-spec with_fuzzing_directory(fun((file:filename_all(), file:filename_all()) -> ok)) -> ok.
with_fuzzing_directory(Test) ->
    RootDir = test_directory(),
    CorpusDir = filename:join(RootDir, "corpus"),
    ArtifactDir = filename:join(RootDir, "artifacts"),
    try
        ok = filelib:ensure_dir(filename:join(CorpusDir, "seed")),
        ok = filelib:ensure_dir(filename:join(ArtifactDir, ".keep")),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<"\n">>),
        Test(CorpusDir, ArtifactDir)
    after
        _ = file:del_dir_r(RootDir)
    end.


-spec test_directory() -> file:filename_all().
test_directory() ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    filename:absname(filename:join(["_build", "fuzzer_feedback_test", Unique])).


%% fuzzing を別の BEAM で実行し、終了コードを返す。
-spec run_in_subprocess(map()) -> non_neg_integer().
run_in_subprocess(Options) ->
    FuzzerEbin = filename:dirname(code:which(fuzzer)),
    TargetDir = filename:dirname(code:which(fuzzer_feedback_target)),
    Eval =
        lists:flatten(
          io_lib:format(
            "case fuzzer:run(~p) of "
            "#{exit_code := 0} -> halt(0); "
            "#{exit_code := Code} -> halt(Code) end.",
            [Options])),
    run_erl(FuzzerEbin, TargetDir, Eval).


-spec run_erl(file:filename_all(), file:filename_all(), string()) ->
          non_neg_integer().
run_erl(FuzzerEbin, TargetDir, Eval) ->
    Erl = os:find_executable("erl"),
    Port =
        open_port(
          {spawn_executable, Erl},
          [binary,
           exit_status,
           stderr_to_stdout,
           {args,
            ["-noshell", "-pa", FuzzerEbin, TargetDir, "-eval", Eval]}]),
    {ExitStatus, _Output} = collect_port(Port, []),
    ExitStatus.


-spec collect_port(port(), [binary()]) -> {non_neg_integer(), binary()}.
collect_port(Port, Output) ->
    receive
        {Port, {data, Data}} ->
            collect_port(Port, [Data | Output]);
        {Port, {exit_status, ExitStatus}} ->
            {ExitStatus, iolist_to_binary(lists:reverse(Output))}
    end.


-spec has_crash_artifact(file:filename_all()) -> boolean().
has_crash_artifact(ArtifactDir) ->
    {ok, Files} = file:list_dir(ArtifactDir),
    lists:any(fun(File) ->
                      lists:prefix("crash-", File) andalso
                      not lists:suffix(".report", File)
              end,
              Files).
