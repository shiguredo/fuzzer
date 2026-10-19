%% 節単位の計測対象として使うサンプルモジュール。
%%
%% 関数節、case、receive、try、fun、maybe、receive after を一通り含む。
%% if の計測は fuzzer_coverage_tests が実行時に生成したモジュールで確認する。
%% テストはこのモジュールの abstract code を取り出し、計測用に書き換えて
%% 別名でロードする。元のモジュール自体は書き換えない。
-module(fuzzer_clause_sample).

-export([clauses/2,
         case_clauses/1,
         receive_clauses/1,
         try_clauses/1,
         fun_clauses/1,
         maybe_clauses/1,
         receive_after/0]).


%% 関数節が 2 個ある。
-spec clauses(a | b, term()) -> {a | b, term()}.
clauses(a, Value) ->
    {a, Value};
clauses(b, Value) ->
    {b, Value}.


%% case の節が 3 個ある。
-spec case_clauses(term()) -> one | two | other.
case_clauses(Value) ->
    case Value of
        1 ->
            one;
        2 ->
            two;
        _ ->
            other
    end.


%% receive の節が 2 個あり、after の本体も持つ。
-spec receive_clauses(term()) -> one | other.
receive_clauses(Value) ->
    Ref = make_ref(),
    self() ! {Ref, Value},
    receive
        {Ref, 1} ->
            one;
        {Ref, _Other} ->
            other
    after
        0 ->
            timeout
    end.


%% try の of 節と catch 節を持つ。
-spec try_clauses(term()) -> ok | badarg | other_error.
try_clauses(Value) ->
    try case Value of
            badarg ->
                erlang:error(badarg);
            _ ->
                ok
        end of
        Result ->
            Result
    catch
        error:badarg ->
            badarg;
        _:_ ->
            other_error
    end.


%% fun の節が 2 個ある。
-spec fun_clauses(term()) -> one | other.
fun_clauses(Value) ->
    Function =
        fun(1) ->
                one;
           (_) ->
                other
        end,
    Function(Value).


%% maybe の else 節が 2 個ある。
-spec maybe_clauses(term()) -> term().
maybe_clauses(Value) ->
    maybe
        {ok, Result} ?= Value,
        Result
    else
        error ->
            other;
        _ ->
            unknown
    end.


%% after の本体だけを持つ receive。
-spec receive_after() -> timeout.
receive_after() ->
    Ref = make_ref(),
    receive
        {Ref, never} ->
            never
    after
        0 ->
            timeout
    end.
