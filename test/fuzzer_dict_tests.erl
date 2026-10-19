-module(fuzzer_dict_tests).

-include_lib("eunit/include/eunit.hrl").


generate_test_() ->
    {timeout, 30, fun generate/0}.


merge_test_() ->
    {timeout, 30, fun merge/0}.


merge_without_user_dict_test_() ->
    {timeout, 30, fun merge_without_user_dict/0}.


auto_dict_finds_magic_cookie_test_() ->
    {timeout, 60, fun auto_dict_finds_magic_cookie/0}.


no_auto_dict_does_not_find_magic_cookie_test_() ->
    {timeout, 60, fun no_auto_dict_does_not_find_magic_cookie/0}.


dict_modules_generates_dictionary_test_() ->
    {timeout, 60, fun dict_modules_generates_dictionary/0}.


generate() ->
    {ok, Entries} = fuzzer_dict:generate([fuzzer_dict_sample]),
    % 16#2112A442 の big-endian と little-endian。
    ?assert(lists:member(<<"\"!\\x12\\xa4B\"">>, Entries)),
    ?assert(lists:member(<<"\"B\\xa4\\x12!\"">>, Entries)),
    % binary リテラルのフィールドも組み立てる。
    ?assert(lists:member(<<"\"\\xde\\xad\\xbe\\xef\"">>, Entries)),
    ?assert(lists:member(<<"\"\\xef\\xbe\\xad\\xde\"">>, Entries)),
    % 24 bit のフィールドは 3 バイトで入る。
    ?assert(lists:member(<<"\"\\xab\\xcd\\xef\"">>, Entries)),
    ?assert(lists:member(<<"\"\\xef\\xcd\\xab\"">>, Entries)),
    % 入れ子の binary も、静的に決まる先頭部分までを組み立てる。
    ?assert(lists:member(<<"\"\\xaa\\xbb\"">>, Entries)),
    % 型指定のない binary の中の文字列は latin1 のバイト列として入る。
    ?assert(lists:member(<<"\"\\x89PNG\\x0d\\x0a\\x1a\\x0a\"">>, Entries)),
    ?assert(lists:member(<<"\"\\xff\\xfe\"">>, Entries)),
    ?assertNot(lists:member(<<"\"\\xc2\\x89PNG\\x0d\\x0a\\x1a\\x0a\"">>,
                            Entries)),
    ?assertNot(lists:member(<<"\"\\xc3\\xbf\\xc3\\xbe\"">>, Entries)),
    % 文字列リテラル。
    ?assert(lists:member(<<"\"magic\"">>, Entries)),
    % 同じリテラルが重複して入らない。
    ?assertEqual(length(Entries), length(lists:usort(Entries))).


merge() ->
    Dir = test_directory(),
    UserDict = filename:join(Dir, "user.dict"),
    try
        ok = filelib:ensure_dir(filename:join(Dir, ".keep")),
        ok = file:write_file(UserDict, <<"\"user\"\n">>),
        {ok, Entries} = fuzzer_dict:generate([fuzzer_dict_sample]),
        {ok, Path} = fuzzer_dict:merge(UserDict, Entries, Dir),
        {ok, Body} = file:read_file(Path),
        ?assertNotEqual(nomatch, binary:match(Body, <<"\"user\"">>)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"\"magic\"">>)),
        ?assertEqual(ok, file:delete(Path))
    after
        _ = file:del_dir_r(Dir)
    end.


merge_without_user_dict() ->
    Dir = test_directory(),
    try
        ok = filelib:ensure_dir(filename:join(Dir, ".keep")),
        {ok, Entries} = fuzzer_dict:generate([fuzzer_dict_sample]),
        {ok, Path} = fuzzer_dict:merge(undefined, Entries, Dir),
        {ok, Body} = file:read_file(Path),
        ?assertNotEqual(nomatch, binary:match(Body, <<"\"magic\"">>)),
        ?assertEqual(ok, file:delete(Path))
    after
        _ = file:del_dir_r(Dir)
    end.


%% 自動生成した辞書で 32 bit の magic cookie を突破できることを確認する。
auto_dict_finds_magic_cookie() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Result =
                  fuzzer:run(#{
                               target => fuzzer_dict_target,
                               runs => 100000,
                               max_length => 16,
                               corpus => CorpusDir,
                               artifacts => ArtifactDir,
                               seed => 1,
                               on_crash => continue
                              }),
              ?assertEqual(0, maps:get(exit_code, Result)),
              ?assertEqual(1, length(maps:get(crashes, Result)))
      end).


%% 自動生成を止めると、同じ回数では 32 bit の magic cookie を突破できない。
no_auto_dict_does_not_find_magic_cookie() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Result =
                  fuzzer:run(#{
                               target => fuzzer_dict_target,
                               runs => 100000,
                               max_length => 16,
                               corpus => CorpusDir,
                               artifacts => ArtifactDir,
                               seed => 1,
                               auto_dict => false,
                               on_crash => continue
                              }),
              ?assertEqual(0, maps:get(exit_code, Result)),
              ?assertEqual([], maps:get(crashes, Result))
      end).


%% dict_modules で指定したモジュールのリテラルから辞書を作れることを確認する。
dict_modules_generates_dictionary() ->
    with_fuzzing_directory(
      fun(CorpusDir, ArtifactDir) ->
              Result =
                  fuzzer:run(#{
                               target => fuzzer_dict_module_target,
                               runs => 10000,
                               max_length => 8,
                               corpus => CorpusDir,
                               artifacts => ArtifactDir,
                               seed => 1,
                               dict_modules => [fuzzer_dict_sample],
                               on_crash => continue
                              }),
              ?assertEqual(0, maps:get(exit_code, Result)),
              ?assertEqual(1, length(maps:get(crashes, Result)))
      end).


-spec with_fuzzing_directory(fun((file:filename_all(), file:filename_all()) -> ok)) -> ok.
with_fuzzing_directory(Test) ->
    Dir = test_directory(),
    CorpusDir = filename:join(Dir, "corpus"),
    ArtifactDir = filename:join(Dir, "artifacts"),
    try
        ok = filelib:ensure_dir(filename:join(CorpusDir, "seed")),
        ok = filelib:ensure_dir(filename:join(ArtifactDir, ".keep")),
        ok = file:write_file(filename:join(CorpusDir, "seed"), <<"\n">>),
        Test(CorpusDir, ArtifactDir)
    after
        _ = file:del_dir_r(Dir)
    end.


-spec test_directory() -> file:filename_all().
test_directory() ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    filename:absname(filename:join(["_build", "fuzzer_dict_test", Unique])).
