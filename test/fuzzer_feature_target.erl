-module(fuzzer_feature_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


%% 先頭バイトの下位 3 bit を feature bitmap として返す。
%% bit の組み合わせが feature として扱われることを検証するために使う。
-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(<<Byte, _/binary>>) ->
    {ok, Byte band 7};
evaluate(_Data) ->
    {ok, 0}.
