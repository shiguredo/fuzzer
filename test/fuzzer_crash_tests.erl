-module(fuzzer_crash_tests).

-include_lib("eunit/include/eunit.hrl").


reason_tag_test() ->
    % 例外の理由が持つ値は識別子に含めない。
    Id1 = fuzzer_crash:id(error, {badmatch, 1}, []),
    Id2 = fuzzer_crash:id(error, {badmatch, 2}, []),
    ?assertEqual(Id1, Id2),
    ?assertEqual(badmatch, maps:get(reason, Id1)),
    ?assertEqual(undefined, maps:get(reason_arity, Id1)).


function_clause_arity_test() ->
    % function_clause の引数は値ではなくアリティに正規化する。
    Stacktrace = [{fuzzer_crash_target, function, 2, [{file, "x.erl"}, {line, 1}]}],
    Id1 = fuzzer_crash:id(error, {function_clause, [1, 2]}, Stacktrace),
    Id2 = fuzzer_crash:id(error, {function_clause, [a, b]}, Stacktrace),
    ?assertEqual(Id1, Id2),
    ?assertEqual(2, maps:get(reason_arity, Id1)),
    Id3 = fuzzer_crash:id(error, {function_clause, [1]}, Stacktrace),
    ?assertNotEqual(Id1, Id3),
    ?assertEqual(1, maps:get(reason_arity, Id3)).


function_clause_atom_test() ->
    % VM が理由をアトムで返す場合も、フレームのアリティを使う。
    Stacktrace = [{fuzzer_crash_target, function, 3, [{file, "x.erl"}, {line, 1}]}],
    Id = fuzzer_crash:id(error, function_clause, Stacktrace),
    ?assertEqual(3, maps:get(reason_arity, Id)).


frame_test() ->
    % OTP のフレームを飛ばし、利用者コードの最初のフレームを使う。
    Stacktrace =
        [{lists, map, 2, [{file, "lists.erl"}, {line, 10}]},
         {parser_module, decode, 1, [{file, "parser.erl"}, {line, 20}]},
         {target_module, evaluate, 1, [{file, "target.erl"}, {line, 30}]}],
    Id = fuzzer_crash:id(error, {badmatch, value}, Stacktrace),
    ?assertEqual({parser_module, decode, 1, 20}, maps:get(frame, Id)),
    ?assertEqual(undefined,
                 maps:get(frame,
                          fuzzer_crash:id(error,
                                          {badmatch, value},
                                          [{lists, map, 2, []}]))).


line_number_distinguishes_test() ->
    % 同じ関数の別の行で起きたクラッシュは別の識別子になる。
    Stacktrace1 = [{module, function, 1, [{file, "x.erl"}, {line, 10}]}],
    Stacktrace2 = [{module, function, 1, [{file, "x.erl"}, {line, 20}]}],
    ?assertNotEqual(fuzzer_crash:id(error, badarg, Stacktrace1),
                    fuzzer_crash:id(error, badarg, Stacktrace2)).


class_test() ->
    % 同じ理由タグでも例外の種類が違えば別のクラッシュとして扱う。
    ?assertNotEqual(fuzzer_crash:id(error, badarg, []),
                    fuzzer_crash:id(exit, badarg, [])).


report_test() ->
    ExceptionReport =
        #{
          reason => {error, {badmatch, value}},
          stacktrace => [{target_module, evaluate,
                                         1,
                                         [{file, "target.erl"}, {line, 42}]}]
         },
    ExceptionId = fuzzer_crash:id_from_report(ExceptionReport),
    ?assertMatch(#{
                   class := error,
                   reason := badmatch,
                   frame := {target_module, evaluate, 1, 42}
                  },
                 ExceptionId),
    TimeoutId = fuzzer_crash:id_from_report(#{reason => timeout}),
    ?assertMatch(#{class := crash, reason := timeout, frame := undefined},
                 TimeoutId),
    InvalidId =
        fuzzer_crash:id_from_report(#{reason => {invalid_features, 1 bsl 64}}),
    ?assertMatch(#{class := crash, reason := invalid_features}, InvalidId).
