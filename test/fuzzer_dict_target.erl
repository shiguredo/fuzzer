%% 自動生成した辞書で magic cookie を突破できることを確認する target。
-module(fuzzer_dict_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> ok | {ok, non_neg_integer()}.
evaluate(<<16#2112A442:32, _Rest/binary>>) ->
    erlang:error(magic_cookie);
evaluate(_Data) ->
    {ok, 0}.
