-module(fuzzer_tests).

-include_lib("eunit/include/eunit.hrl").


fuzzes_in_current_beam_test_() ->
    {timeout, 30, fun fuzzes_in_current_beam/0}.


crash_artifact_test_() ->
    {timeout, 30, fun crash_artifact/0}.


continue_on_crash_test_() ->
    {timeout, 30, fun continue_on_crash/0}.


continue_on_exception_test_() ->
    {timeout, 30, fun continue_on_exception/0}.


continue_on_timeout_test_() ->
    {timeout, 30, fun continue_on_timeout/0}.


continue_multiple_crashes_test_() ->
    {timeout, 30, fun continue_multiple_crashes/0}.


crash_line_distinguishes_test_() ->
    {timeout, 30, fun crash_line_distinguishes/0}.


auto_dict_cleanup_test_() ->
    {timeout, 30, fun auto_dict_cleanup/0}.


run_options_test_() ->
    {timeout, 30, fun run_options/0}.


feature_combinations_test_() ->
    {timeout, 60, fun feature_combinations/0}.


max_feature_test_() ->
    {timeout, 30, fun max_feature/0}.


invalid_feature_report_test_() ->
    {timeout, 30, fun invalid_feature_report/0}.


exception_report_test_() ->
    {timeout, 30, fun exception_report/0}.


reset_callbacks_test_() ->
    {timeout, 30, fun reset_callbacks/0}.


coverage_test_() ->
    {timeout, 60, fun coverage/0}.


unicode_path_test_() ->
    {timeout, 30, fun unicode_path/0}.


artifact_directory_test_() ->
    {timeout, 30, fun artifact_directory/0}.


timeout_report_test_() ->
    {timeout, 30, fun timeout_report/0}.


run_one_test_() ->
    {timeout, 30, fun run_one/0}.


reproduce_test_() ->
    {timeout, 30, fun reproduce/0}.


libfuzzer_version_test() ->
    % NIF に静的リンクした libFuzzer のバージョンが、空でない数値形式で返ることを確認する。
    Version = fuzzer:libfuzzer_version(),
    ?assert(is_binary(Version)),
    ?assertEqual(match, re:run(Version, <<"^[0-9]+(\\.[0-9]+)*$">>, [{capture, none}])).


max_feedback_counters_test() ->
    % NIF がフィードバックカウンターの上限を正の整数で返すことを確認する。
    Max = fuzzer:max_feedback_counters(),
    ?assert(is_integer(Max)),
    ?assert(Max > 0).


option_validation_test_() ->
    [?_assertError({invalid_option, {missing, target}},
                   fuzzer:run(#{})),
     ?_assertError({invalid_option, {max_length, 0}},
                   fuzzer:run(#{target => fuzzer_test_target, max_length => 0})),
     ?_assertError({invalid_option, {jobs, unsupported_in_embedded_driver}},
                   fuzzer:run(#{target => fuzzer_test_target, jobs => 2})),
     ?_assertError({invalid_option, {unknown, [bogus]}},
                   fuzzer:run(#{target => fuzzer_test_target, bogus => 1})),
     ?_assertError({invalid_option, {dict, _, not_found}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                dict => "/no/such/fuzzer/dict"
                               })),
     ?_assertError({invalid_option, {extra_args, <<"-jobs=2">>}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                extra_args => ["-jobs=2"]
                               })),
     ?_assertError({invalid_option, {feedback, {module, 123}}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                feedback => [123]
                               })),
     ?_assertError({invalid_option, {feedback, {mode, invalid}}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                feedback => #{
                                              modules => [fuzzer_test_target],
                                              mode => invalid
                                             }
                               })),
     ?_assertError({invalid_option, {feedback, {unknown, [bogus]}}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                feedback => #{
                                              modules => [fuzzer_test_target],
                                              bogus => true
                                             }
                               })),
     ?_assertError({invalid_option, {feedback, incompatible_with_cover}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                feedback => [fuzzer_test_target],
                                cover => [fuzzer_test_target]
                               })),
     ?_assertError({invalid_option, {on_crash, bogus}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                on_crash => bogus
                               })),
     ?_assertError({invalid_option, {auto_dict, invalid}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                auto_dict => invalid
                               })),
     ?_assertError({invalid_option, {dict_modules, 123}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                dict_modules => [123]
                               })),
     ?_assertError({invalid_option, {dict_modules, fuzzer_test_target}},
                   fuzzer:run(#{
                                target => fuzzer_test_target,
                                dict_modules => fuzzer_test_target
                               }))].


dictionary_and_limit_options_test_() ->
    {timeout, 30, fun dictionary_and_limit_options/0}.


fuzzes_in_current_beam() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        true = register(fuzzer_test_receiver, self()),
        ?assertEqual(0,
                     fuzzer:run(fuzzer_test_target,
                                100,
                                8,
                                CorpusDir,
                                ArtifactDir ++ "/")),
        Inputs = collect_inputs([]),
        ?assert(lists:any(fun is_mutated_input/1, Inputs))
    after
        unregister_receiver(),
        _ = file:del_dir_r(TestDir)
    end.


crash_artifact() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        ExitStatus = run_crashing_fuzzer(CorpusDir, ArtifactDir),
        ?assertNotEqual(0, ExitStatus),
        {ok, Artifacts} = file:list_dir(ArtifactDir),
        ?assertNotEqual([], Artifacts),
        CrashInputs =
            [ begin
                  {ok, Data} =
                      file:read_file(filename:join(ArtifactDir, Artifact)),
                  Data
              end || Artifact <:- Artifacts, not lists:suffix(".report", Artifact) ],
        ?assert(lists:any(fun is_crash_input/1, CrashInputs))
    after
        _ = file:del_dir_r(TestDir)
    end.


%% クラッシュしても BEAM を終了せず、重複を除いたクラッシュを返す。
continue_on_crash() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_crash_target,
                         runs => 1000,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         on_crash => continue
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Crashes = maps:get(crashes, Result),
        ?assertEqual(1, length(Crashes)),
        [Crash] = Crashes,
        ?assertMatch(#{
                       crash_id := #{
                                     class := error,
                                     reason := target_crash
                                    }
                      },
                     Crash),
        ?assert(is_binary(maps:get(input_sha1, Crash))),
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
    after
        _ = file:del_dir_r(TestDir)
    end.


%% 例外のクラッシュでも継続し、同じ crash_id の artifact を重複して作らない。
continue_on_exception() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_error_target,
                         runs => 10,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         on_crash => continue
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Crashes = maps:get(crashes, Result),
        ?assertEqual(1, length(Crashes)),
        [Crash] = Crashes,
        ?assertMatch(#{
                       crash_id := #{
                                     class := error,
                                     reason := boom
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
    after
        _ = file:del_dir_r(TestDir)
    end.


%% タイムアウトしてもワーカーを作り直して継続し、タイムアウトを 1 件だけ残す。
continue_on_timeout() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_timeout_target,
                         runs => 3,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         timeout => 1,
                         on_crash => continue
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Crashes = maps:get(crashes, Result),
        ?assertEqual(1, length(Crashes)),
        [Crash] = Crashes,
        ?assertMatch(#{crash_id := #{class := crash, reason := timeout}}, Crash),
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
    after
        _ = file:del_dir_r(TestDir)
    end.


%% 異なる crash_id は別々に残し、同じ crash_id の入力は重複して残さない。
continue_multiple_crashes() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "a"), <<"a">>),
        ok = file:write_file(filename:join(CorpusDir, "a2"), <<"a", 1>>),
        ok = file:write_file(filename:join(CorpusDir, "b"), <<"b">>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_multi_crash_target,
                         runs => 10,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         on_crash => continue
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Crashes = maps:get(crashes, Result),
        ?assertEqual(2, length(Crashes)),
        Reasons =
            lists:sort([ maps:get(reason, maps:get(crash_id, Crash))
                         || Crash <:- Crashes ]),
        ?assertEqual([bang, boom], Reasons),
        {ok, Files} = file:list_dir(ArtifactDir),
        ?assertEqual(2,
                     length([ File
                              || File <:- Files,
                                 lists:prefix("crash-", File),
                                 not lists:suffix(".report", File) ])),
        ?assertEqual(2,
                     length([ File
                              || File <:- Files,
                                 lists:suffix(".report", File) ]))
    after
        _ = file:del_dir_r(TestDir)
    end.


%% 同じ関数の別の行で起きた badmatch を別のクラッシュとして残す。
crash_line_distinguishes() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "zero"), <<0>>),
        ok = file:write_file(filename:join(CorpusDir, "one"), <<1>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_crash_line_target,
                         runs => 10,
                         max_length => 4,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         seed => 1,
                         on_crash => continue
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Crashes = maps:get(crashes, Result),
        ?assertEqual(2, length(Crashes)),
        ?assertEqual([badmatch, badmatch],
                     lists:sort([ maps:get(reason, maps:get(crash_id, Crash))
                                  || Crash <:- Crashes ])),
        Frames = [ maps:get(frame, maps:get(crash_id, Crash)) || Crash <:- Crashes ],
        ?assertEqual(2, length(lists:usort(Frames))),
        ?assert(lists:all(fun({fuzzer_crash_line_target, crash, 1, _Line}) ->
                                  true;
                             (_Frame) ->
                                  false
                          end,
                          Frames))
    after
        _ = file:del_dir_r(TestDir)
    end.


%% 自動生成した辞書の一時ファイルが fuzzing 後に残らないことを確認する。
auto_dict_cleanup() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_feature_target,
                         runs => 10,
                         max_length => 2,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         feedback => [fuzzer_dict_sample]
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        {ok, Files} = file:list_dir(ArtifactDir),
        ?assertEqual([],
                     [ File
                       || File <:- Files,
                          lists:prefix(".fuzzer-auto-", File) ])
    after
        _ = file:del_dir_r(TestDir)
    end.


run_options() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        true = register(fuzzer_test_receiver, self()),
        Result =
            fuzzer:run(#{
                         target => fuzzer_test_target,
                         runs => 100,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        ?assertEqual(undefined, maps:get(coverage, Result)),
        ?assertEqual([], maps:get(crashes, Result))
    after
        unregister_receiver(),
        _ = file:del_dir_r(TestDir)
    end.


feature_combinations() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        % bit 0, 1, 2 を個別に踏むシードだけを置く。
        % 組み合わせが feature として扱われていれば、3 以上の bit の組み合わせを
        % 持つ入力がコーパスへ追加される。
        ok = file:write_file(filename:join(CorpusDir, "one"), <<1>>),
        ok = file:write_file(filename:join(CorpusDir, "two"), <<2>>),
        ok = file:write_file(filename:join(CorpusDir, "four"), <<4>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_feature_target,
                         runs => 30000,
                         max_length => 2,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Features = corpus_features(CorpusDir),
        ?assert(lists:any(fun is_combination/1, Features))
    after
        _ = file:del_dir_r(TestDir)
    end.


max_feature() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        Result =
            fuzzer:run(#{
                         target => fuzzer_max_feature_target,
                         runs => 10,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir
                        }),
        ?assertEqual(0, maps:get(exit_code, Result))
    after
        _ = file:del_dir_r(TestDir)
    end.


invalid_feature_report() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        ExitStatus =
            run_in_subprocess(#{
                                target => fuzzer_invalid_feature_target,
                                runs => 1000,
                                max_length => 8,
                                corpus => CorpusDir,
                                artifacts => ArtifactDir
                               }),
        ?assertNotEqual(0, ExitStatus),
        Body = iolist_to_binary(read_reports(ArtifactDir)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"invalid_features">>)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"crash_id">>))
    after
        _ = file:del_dir_r(TestDir)
    end.


exception_report() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        ExitStatus =
            run_in_subprocess(#{
                                target => fuzzer_error_target,
                                runs => 1000,
                                max_length => 8,
                                corpus => CorpusDir,
                                artifacts => ArtifactDir
                               }),
        ?assertNotEqual(0, ExitStatus),
        Body = iolist_to_binary(read_reports(ArtifactDir)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"boom">>)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"stacktrace">>)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"crash_id">>))
    after
        _ = file:del_dir_r(TestDir)
    end.


reset_callbacks() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        true = register(fuzzer_test_receiver, self()),
        Result =
            fuzzer:run(#{
                         target => fuzzer_reset_target,
                         runs => 3,
                         max_length => 4,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Callbacks = collect_callbacks([]),
        ?assertEqual([init,
                      reset,
                      evaluate,
                      reset,
                      evaluate,
                      reset,
                      evaluate,
                      terminate],
                     Callbacks)
    after
        unregister_receiver(),
        _ = file:del_dir_r(TestDir)
    end.


coverage() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        true = register(fuzzer_test_receiver, self()),
        Result =
            fuzzer:run(#{
                         target => fuzzer_test_target,
                         runs => 20,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         cover => [fuzzer_test_target]
                        }),
        ?assertEqual(0, maps:get(exit_code, Result)),
        Coverage = maps:get(coverage, Result),
        ?assert(is_map(Coverage)),
        Stats = maps:get(fuzzer_test_target, Coverage),
        ?assert(maps:get(covered, Stats) > 0),
        ?assert(maps:get(total, Stats) >= maps:get(covered, Stats))
    after
        unregister_receiver(),
        _ = file:del_dir_r(TestDir)
    end.


unicode_path() ->
    TestDir = test_directory(),
    RootDir = filename:join(TestDir, "日本語"),
    CorpusDir = filename:join(RootDir, "corpus"),
    ArtifactDir = filename:join(RootDir, "artifacts"),
    try
        true = register(fuzzer_test_receiver, self()),
        Result =
            fuzzer:run(#{
                         target => fuzzer_test_target,
                         runs => 10,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir
                        }),
        ?assertEqual(0, maps:get(exit_code, Result))
    after
        unregister_receiver(),
        _ = file:del_dir_r(TestDir)
    end.


artifact_directory() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    % 末尾に / を付けず、存在しないディレクトリーを指定する。
    ArtifactDir = filename:join(TestDir, "new_artifacts"),
    try
        ok = filelib:ensure_dir(filename:join(CorpusDir, "seed")),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        ExitStatus =
            run_in_subprocess(#{
                                target => fuzzer_crash_target,
                                runs => 1000,
                                max_length => 8,
                                corpus => CorpusDir,
                                artifacts => ArtifactDir
                               }),
        ?assertNotEqual(0, ExitStatus),
        {ok, Files} = file:list_dir(ArtifactDir),
        ?assert(lists:any(fun is_crash_artifact/1, Files))
    after
        _ = file:del_dir_r(TestDir)
    end.


dictionary_and_limit_options() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    Dict = filename:join(TestDir, "dict.txt"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        ok = file:write_file(Dict, <<"\"v=0\\x0d\\x0a\"\n">>),
        true = register(fuzzer_test_receiver, self()),
        Result =
            fuzzer:run(#{
                         target => fuzzer_test_target,
                         runs => 100,
                         max_length => 8,
                         corpus => CorpusDir,
                         artifacts => ArtifactDir,
                         dict => Dict,
                         timeout => 10,
                         max_total_time => 1,
                         seed => 123,
                         rss_limit_mb => 4096
                        }),
        ?assertEqual(0, maps:get(exit_code, Result))
    after
        unregister_receiver(),
        _ = file:del_dir_r(TestDir)
    end.


timeout_report() ->
    TestDir = test_directory(),
    CorpusDir = filename:join(TestDir, "corpus"),
    ArtifactDir = filename:join(TestDir, "artifacts"),
    try
        ok = prepare_directories(CorpusDir, ArtifactDir),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<0>>),
        Start = erlang:monotonic_time(millisecond),
        ExitStatus =
            run_in_subprocess(#{
                                target => fuzzer_timeout_target,
                                runs => 10,
                                max_length => 8,
                                corpus => CorpusDir,
                                artifacts => ArtifactDir,
                                timeout => 1
                               }),
        Elapsed = erlang:monotonic_time(millisecond) - Start,
        ?assertNotEqual(0, ExitStatus),
        % 1 秒でタイムアウトするはず。外部の EUnit タイムアウトまで待たない。
        ?assert(Elapsed < 15000),
        Body = iolist_to_binary(read_reports(ArtifactDir)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"timeout">>)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"crash_id">>))
    after
        _ = file:del_dir_r(TestDir)
    end.


run_one() ->
    true = register(fuzzer_test_receiver, self()),
    try
        ?assertEqual({ok, 0}, fuzzer:run_one(fuzzer_reset_target, <<0>>)),
        % ok を返す target は feature bitmap を報告しないものとして扱う。
        ?assertEqual({ok, 0}, fuzzer:run_one(fuzzer_feedback_target, <<"x">>)),
        ?assertEqual([init, reset, evaluate, terminate], collect_callbacks([])),
        {crash, ErrorReport} = fuzzer:run_one(fuzzer_error_target, <<0>>),
        ?assertMatch(#{reason := {error, boom}, stacktrace := _}, ErrorReport),
        ?assertMatch(#{
                       class := error,
                       reason := boom,
                       frame := {fuzzer_error_target, evaluate, 1, _}
                      },
                     maps:get(crash_id, ErrorReport)),
        {crash, HelperReport} = fuzzer:run_one(fuzzer_crash_helper_target, <<0>>),
        ?assertMatch(#{frame := {fuzzer_crash_helper, boom, 0, _}},
                     maps:get(crash_id, HelperReport)),
        {crash, InvalidReport} = fuzzer:run_one(fuzzer_invalid_feature_target, <<0>>),
        ?assertMatch(#{reason := {invalid_features, _}}, InvalidReport),
        ?assertMatch(#{class := crash, reason := invalid_features},
                     maps:get(crash_id, InvalidReport)),
        ?assertMatch({error, _}, fuzzer:run_one(fuzzer_no_such_target, <<0>>))
    after
        unregister_receiver()
    end.


reproduce() ->
    TestDir = test_directory(),
    Artifact = filename:join(TestDir, "artifact"),
    Missing = filename:join(TestDir, "missing"),
    try
        ok = filelib:ensure_dir(Artifact),
        ok = file:write_file(Artifact, <<0>>),
        ?assertMatch({crash, #{reason := {error, boom}}},
                     fuzzer:reproduce(fuzzer_error_target, Artifact)),
        ?assertMatch({error, {file, _, _}},
                     fuzzer:reproduce(fuzzer_error_target, Missing))
    after
        _ = file:del_dir_r(TestDir)
    end.


-spec prepare_directories(file:filename_all(), file:filename_all()) -> ok.
prepare_directories(CorpusDir, ArtifactDir) ->
    ok = filelib:ensure_dir(filename:join(CorpusDir, "seed")),
    filelib:ensure_dir(filename:join(ArtifactDir, "placeholder")).


-spec test_directory() -> file:filename_all().
test_directory() ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    filename:absname(filename:join(["_build", "fuzzer_test", Unique])).


-spec run_crashing_fuzzer(file:filename_all(), file:filename_all()) ->
          non_neg_integer().
run_crashing_fuzzer(CorpusDir, ArtifactDir) ->
    FuzzerEbin = filename:dirname(code:which(fuzzer)),
    TargetDir = filename:dirname(code:which(fuzzer_crash_target)),
    Eval =
        lists:flatten(
          io_lib:format(
            "case fuzzer:run(fuzzer_crash_target, 1000, 8, ~p, ~p) of "
            "0 -> halt(0); Code -> halt(Code) end.",
            [CorpusDir, ArtifactDir ++ "/"])),
    run_erl(FuzzerEbin, TargetDir, Eval).


-spec run_in_subprocess(map()) -> non_neg_integer().
run_in_subprocess(Options) ->
    FuzzerEbin = filename:dirname(code:which(fuzzer)),
    Target = maps:get(target, Options),
    TargetDir = filename:dirname(code:which(Target)),
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


-spec collect_inputs([binary()]) -> [binary()].
collect_inputs(Inputs) ->
    receive
        {fuzzer_test_input, Data} ->
            collect_inputs([Data | Inputs])
    after
        0 ->
            Inputs
    end.


-spec collect_callbacks([atom()]) -> [atom()].
collect_callbacks(Callbacks) ->
    receive
        {fuzzer_callback, Event} ->
            collect_callbacks([Event | Callbacks])
    after
        200 ->
            lists:reverse(Callbacks)
    end.


-spec collect_port(port(), [binary()]) -> {non_neg_integer(), binary()}.
collect_port(Port, Output) ->
    receive
        {Port, {data, Data}} ->
            collect_port(Port, [Data | Output]);
        {Port, {exit_status, ExitStatus}} ->
            {ExitStatus, iolist_to_binary(lists:reverse(Output))}
    end.


-spec unregister_receiver() -> ok.
unregister_receiver() ->
    case whereis(fuzzer_test_receiver) of
        Receiver when Receiver =:= self() ->
            true = unregister(fuzzer_test_receiver),
            ok;
        _Receiver ->
            ok
    end.


-spec is_mutated_input(binary()) -> boolean().
is_mutated_input(<<>>) ->
    false;
is_mutated_input(<<0>>) ->
    false;
is_mutated_input(_Data) ->
    true.


-spec is_crash_input(binary()) -> boolean().
is_crash_input(<<>>) ->
    false;
is_crash_input(<<0>>) ->
    false;
is_crash_input(_Data) ->
    true.


-spec corpus_features(file:filename_all()) -> [non_neg_integer()].
corpus_features(CorpusDir) ->
    {ok, Files} = file:list_dir(CorpusDir),
    lists:filtermap(fun(File) ->
                            Path = filename:join(CorpusDir, File),
                            case file:read_file(Path) of
                                {ok, <<Byte, _/binary>>} ->
                                    {true, Byte band 7};
                                _ ->
                                    false
                            end
                    end,
                    Files).


-spec is_combination(non_neg_integer()) -> boolean().
is_combination(Features) ->
    Features =/= 0 andalso (Features band (Features - 1)) =/= 0.


-spec is_crash_artifact(file:filename()) -> boolean().
is_crash_artifact(File) ->
    lists:prefix("crash-", File) andalso not lists:suffix(".report", File).


-spec read_reports(file:filename_all()) -> [binary()].
read_reports(ArtifactDir) ->
    {ok, Files} = file:list_dir(ArtifactDir),
    [ Body
      || File <:- Files,
         lists:suffix(".report", File),
         {ok, Body} <:- [file:read_file(filename:join(ArtifactDir, File))] ].
