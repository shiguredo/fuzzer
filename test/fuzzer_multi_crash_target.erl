%% 複数のクラッシュ識別子と、同じ識別子の重複を確認するための target。
-module(fuzzer_multi_crash_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(<<"a", _/binary>>) ->
    erlang:error(boom);
evaluate(<<"b", _/binary>>) ->
    erlang:error(bang);
evaluate(_Data) ->
    {ok, 0}.
