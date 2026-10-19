%% rebar3_fuzzer が起動するサブプロセス用の小さな CLI。
%%
%% シェル経由で Erlang の式を組み立てると、引用符・セミコロン・波括弧の
%% エスケープが環境依存になる。ここではオプションを base64 で受け取り、
%% サブプロセス側で復号して実行する。
-module(fuzzer_cli).

-export([run/1, reproduce/1]).


%% fuzzer:run/1 を実行し、終了コードで halt する。
-spec run(binary()) -> no_return().
run(Encoded) ->
    Options = binary_to_term(base64:decode(Encoded)),
    Result = fuzzer:run(Options),
    print_coverage(maps:get(coverage, Result)),
    halt(maps:get(exit_code, Result)).


%% fuzzer:reproduce/2 を実行し、結果に応じた終了コードで halt する。
-spec reproduce(binary()) -> no_return().
reproduce(Encoded) ->
    {Target, Path} = binary_to_term(base64:decode(Encoded)),
    case fuzzer:reproduce(Target, Path) of
        {ok, Features} ->
            io:format("OK: ~p~n", [Features]),
            halt(0);
        {crash, Report} ->
            io:format("CRASH: ~p~n", [Report]),
            halt(1);
        {error, Reason} ->
            io:format("ERROR: ~p~n", [Reason]),
            halt(2)
    end.


%% cover を指定した場合だけカバレッジを表示する。
-spec print_coverage(undefined | fuzzer:coverage()) -> ok.
print_coverage(undefined) ->
    ok;
print_coverage(Coverage) ->
    io:format("Coverage: ~p~n", [Coverage]),
    ok.
