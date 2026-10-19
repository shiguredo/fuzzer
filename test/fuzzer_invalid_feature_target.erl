-module(fuzzer_invalid_feature_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


%% 64 bit を超える feature を返し、検証エラーになることを確認する。
-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(_Data) ->
    {ok, 1 bsl 64}.
