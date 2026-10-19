-module(fuzzer_max_feature_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


%% 64 bit すべてを立てた feature を返し、上限値が扱えることを確認する。
-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(_Data) ->
    {ok, 16#FFFFFFFFFFFFFFFF}.
