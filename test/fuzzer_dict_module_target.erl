%% dict_modules で指定したモジュールのリテラルだけを使うことを確認する target。
-module(fuzzer_dict_module_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()} | crash.
evaluate(Data) ->
    case fuzzer_dict_sample:magic(Data) of
        ok ->
            crash;
        error ->
            {ok, 0}
    end.
