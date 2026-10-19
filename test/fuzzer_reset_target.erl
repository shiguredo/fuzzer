-module(fuzzer_reset_target).

-behaviour(fuzzer_target).

-export([init/0, reset/0, terminate/0, evaluate/1]).


%% 各コールバックが呼ばれたことをテストプロセスへ通知する。
-spec init() -> ok.
init() ->
    notify(init).


-spec reset() -> ok.
reset() ->
    notify(reset).


-spec terminate() -> ok.
terminate() ->
    notify(terminate).


-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(_Data) ->
    ok = notify(evaluate),
    {ok, 0}.


-spec notify(atom()) -> ok.
notify(Event) ->
    case whereis(fuzzer_test_receiver) of
        undefined ->
            ok;
        Receiver ->
            Receiver ! {fuzzer_callback, Event},
            ok
    end.
