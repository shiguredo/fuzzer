%% 同じ関数の別の行で起きる badmatch を区別できることを確認する target。
-module(fuzzer_crash_line_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(<<0>>) ->
    crash(0);
evaluate(<<1>>) ->
    crash(1);
evaluate(_Data) ->
    {ok, 0}.


-spec crash(0 | 1) -> {ok, non_neg_integer()}.
crash(0) ->
    {ok, _Value} = result(0),
    {ok, 0};
crash(1) ->
    {ok, _Value} = result(1),
    {ok, 0}.


-spec result(0 | 1) -> {ok, non_neg_integer()} | {error, non_neg_integer()}.
result(0) ->
    {error, 0};
result(1) ->
    {error, 1}.
