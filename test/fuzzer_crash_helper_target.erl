%% target の外で起きた例外のフレームを使うことを確認する target。
-module(fuzzer_crash_helper_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(_Data) ->
    fuzzer_crash_helper:boom().
