%% Erlang の fuzz target を libFuzzer から実行するための API。
%%
%% 実行モデル:
%%   fuzzer:run/1 または run/5 を呼ぶと、NIF が dirty CPU スケジューラーで
%%   LLVMFuzzerRunDriver を実行する。libFuzzer が入力を生成するたびに、NIF は
%%   通常スケジューラーで動く 1 個の Erlang ワーカーへバイナリーを送る。
%%   ワーカーは fuzz target の evaluate/1 を呼び、feature bitmap または crash を返す。
%%
%% feature bitmap:
%%   0 以上 16#FFFFFFFFFFFFFFFF 以下の 64 bit 値。fuzz target が到達した意味的な
%%   状態を各 bit に割り当てる。NIF は各 bit と bitmap 全体のハッシュを libFuzzer の
%%   カウンターへ反映する。
%%
%% クラッシュ:
%%   crash が返るかワーカーが終了すると、libFuzzer は BEAM 全体を終了する。
%%   その前に、artifact と同じ SHA-1 を持つレポートを artifacts ディレクトリーへ書く。
%%
%% カバレッジ:
%%   cover オプションで指定した Erlang モジュールのカバレッジを実行後に返す。
%%
%% このモジュールは fuzzing 専用の BEAM で使うこと。他の処理と同じ BEAM で
%% 長時間実行すると、dirty CPU スケジューラーを 1 本占有し続ける。
-module(fuzzer).

-on_load(init/0).

-export([run/1, run/5, run_one/2, reproduce/2]).

%% fuzzer:run/1 が受け付けるオプション。
%% 必須は target だけ。その他は既定値を持つか、未指定なら libFuzzer の既定値に任せる。
-type path() :: file:filename_all().
-type options() ::
        #{
          target := module(),
          runs => non_neg_integer(),
          max_length => pos_integer(),
          corpus => path(),
          artifacts => path(),
          dict => path(),
          timeout => pos_integer(),
          max_total_time => non_neg_integer(),
          seed => non_neg_integer(),
          rss_limit_mb => pos_integer(),
          cover => [module()],
          extra_args => [string() | binary()]
         }.
%% cover オプションを指定した場合に返る、モジュールごとのカバレッジ。
-type coverage() ::
        #{
          module() =>
              #{
                covered := non_neg_integer(),
                not_covered := non_neg_integer(),
                total := non_neg_integer(),
                percentage := float()
               }
         }.
%% fuzzer:run/1 の戻り値。coverage は cover を指定しない場合 undefined になる。
-type result() :: #{exit_code := integer(), coverage := undefined | coverage()}.

-export_type([coverage/0, options/0, result/0]).

-define(MAX_FEATURES,       16#FFFFFFFFFFFFFFFF).
-define(DEFAULT_MAX_LENGTH, 4096).

%%%===================================================================
%%% 公開 API
%%%===================================================================


%% オプションマップを指定して fuzzing を実行する。
%%
%% 戻り値は次のマップ。
%%   #{exit_code := integer(), coverage := undefined | coverage()}
%%
%% オプションが不正な場合は error({invalid_option, ...}) を送出する。
%% クラッシュ時は libFuzzer が BEAM 全体を終了するため、この関数は戻らないことがある。
-spec run(options()) -> result().
run(Options) when is_map(Options) ->
    Config = normalize_options(Options),
    ok = ensure_crypto_started(),
    CoverageState = start_coverage(maps:get(cover, Config)),
    try
        ExitCode = run_fuzzer(Config),
        #{exit_code => ExitCode, coverage => collect_coverage(CoverageState)}
    after
        stop_coverage(CoverageState)
    end.


%% 従来の位置引数 API。run/1 の薄いラッパーで、libFuzzer の終了コードだけを返す。
%% 新規のコードでは run/1 を使うこと。
-spec run(module(), non_neg_integer(), pos_integer(), path(), path()) -> integer().
run(Target, Runs, MaxLength, CorpusDir, ArtifactDir) ->
    Result =
        run(#{
              target => Target,
              runs => Runs,
              max_length => MaxLength,
              corpus => CorpusDir,
              artifacts => ArtifactDir
             }),
    maps:get(exit_code, Result).


%% artifact の 1 入力を再実行する。
%%
%% fuzzing のワーカーと同じ順序で init/0、reset/0、evaluate/1、terminate/0 を呼ぶ。
%% クラッシュしても BEAM を終了せず、{crash, Report} として返す。
%% タイムアウトは 60 秒で、それを超えた場合は {error, timeout} を返す。
-spec run_one(module(), binary()) ->
          {ok, non_neg_integer()} | {crash, map()} | {error, term()}.
run_one(Target, Data) when is_atom(Target), is_binary(Data) ->
    Parent = self(),
    {Pid, Monitor} =
        spawn_monitor(fun() -> Parent ! {run_one_result, run_one_result(Target, Data)} end),
    receive
        {run_one_result, Result} ->
            erlang:demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Pid, Reason} ->
            {error, Reason}
    after
        60000 ->
            exit(Pid, kill),
            {error, timeout}
    end.


%% artifact ファイルを読み込み、run_one/2 で再実行する。
-spec reproduce(module(), file:filename_all()) ->
          {ok, non_neg_integer()} | {crash, map()} | {error, term()}.
reproduce(Target, Path) ->
    case file:read_file(Path) of
        {ok, Data} ->
            run_one(Target, Data);
        {error, Reason} ->
            {error, {file, Path, Reason}}
    end.


%% 再現用の一時プロセスで fuzz target のコールバックを順に呼ぶ。
-spec run_one_result(module(), binary()) ->
          {ok, non_neg_integer()} | {crash, map()} | {error, term()}.
run_one_result(Target, Data) ->
    case code:ensure_loaded(Target) of
        {module, Target} ->
            run_one_callbacks(Target, Data);
        {error, Reason} ->
            {error, {target_not_loaded, Target, Reason}}
    end.


%% init/0 と terminate/0 を含めてコールバックを呼ぶ。
-spec run_one_callbacks(module(), binary()) ->
          {ok, non_neg_integer()} | {crash, map()} | {error, term()}.
run_one_callbacks(Target, Data) ->
    try
        call_optional(Target, init, []),
        try
            % evaluate/2 が reset/0 を呼んでから evaluate/1 を実行する。
            evaluate(Target, Data)
        after
            call_optional(Target, terminate, [])
        end
    catch
        CatchClass:CatchReason:CatchStacktrace ->
            {error, {CatchClass, CatchReason, CatchStacktrace}}
    end.


%%%===================================================================
%%% オプションの正規化と検証
%%%===================================================================


%% オプションを検証し、内部設定のマップへ正規化する。
%%
%% - 未知のキーは typo を早期に検出するためエラーにする
%% - jobs / workers はこの埋め込みドライバーでは動かないため、専用のエラーにする
%% - パスは絶対パスのバイナリーへ変換し、必要なディレクトリーを作成する
%% - 数値は各フラグの許容範囲をここで検査する
-spec normalize_options(options()) -> map().
normalize_options(Options) ->
    %% 未知のキーを検出するために、受け付けるキーを明示する。
    Allowed =
        [target,
         runs,
         max_length,
         corpus,
         artifacts,
         dict,
         timeout,
         max_total_time,
         seed,
         rss_limit_mb,
         jobs,
         workers,
         cover,
         extra_args],
    case maps:keys(Options) -- Allowed of
        [] ->
            ok;
        Unknown ->
            erlang:error({invalid_option, {unknown, Unknown}})
    end,
    ok = validate_jobs_options(Options),
    Target = target_option(Options),
    Runs = non_neg_integer_option(runs, Options, 0),
    MaxLength = pos_integer_option(max_length, Options, ?DEFAULT_MAX_LENGTH),
    %% 辞書と cover は、ディレクトリーを作る前に検証して副作用を減らす。
    Dict = dict_option(Options),
    Cover = cover_option(Options),
    ExtraArgs = extra_args_option(Options),
    Corpus = directory_option(corpus, Options, default_directory(Target, "corpus")),
    Artifacts =
        directory_option(artifacts, Options, default_directory(Target, "artifacts")),
    #{
      target => Target,
      runs => Runs,
      max_length => MaxLength,
      corpus => Corpus,
      %% libFuzzer の artifact_prefix は末尾セパレーターが必要。
      artifacts => add_trailing_separator(Artifacts),
      dict => Dict,
      timeout => optional_pos_integer_option(timeout, Options),
      max_total_time => optional_non_neg_integer_option(max_total_time, Options),
      seed => optional_uint64_option(seed, Options),
      rss_limit_mb => optional_pos_integer_option(rss_limit_mb, Options),
      cover => Cover,
      extra_args => ExtraArgs
     }.


%% libFuzzer の -jobs / -workers は子プロセスを起動するため、NIF に埋め込んだ
%% ドライバーでは動作しない。指定された場合は明確に拒否する。
-spec validate_jobs_options(map()) -> ok.
validate_jobs_options(Options) ->
    case {maps:get(jobs, Options, undefined),
          maps:get(workers, Options, undefined)} of
        {undefined, undefined} ->
            ok;
        {undefined, _Workers} ->
            erlang:error({invalid_option,
                          {workers, unsupported_in_embedded_driver}});
        {_Jobs, _Workers} ->
            erlang:error({invalid_option,
                          {jobs, unsupported_in_embedded_driver}})
    end.


%% target は必須。code:which/1 で code path 上に存在するか確認する。
-spec target_option(options()) -> module().
target_option(Options) ->
    case maps:get(target, Options, undefined) of
        undefined ->
            erlang:error({invalid_option, {missing, target}});
        Target when is_atom(Target) ->
            case code:which(Target) of
                non_existing ->
                    erlang:error({invalid_option, {target, Target, not_found}});
                _ ->
                    Target
            end;
        Target ->
            erlang:error({invalid_option, {target, Target}})
    end.


%% 0 以上の整数だけを受け付ける。
-spec non_neg_integer_option(atom(), map(), non_neg_integer()) -> non_neg_integer().
non_neg_integer_option(Key, Options, Default) ->
    case maps:get(Key, Options, Default) of
        Value when is_integer(Value), Value >= 0 ->
            Value;
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% 1 以上の整数だけを受け付ける。
-spec pos_integer_option(atom(), map(), pos_integer()) -> pos_integer().
pos_integer_option(Key, Options, Default) ->
    case maps:get(Key, Options, Default) of
        Value when is_integer(Value), Value > 0 ->
            Value;
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% 未指定なら undefined を返し、libFuzzer の既定値に任せる。
-spec optional_pos_integer_option(atom(), map()) -> undefined | pos_integer().
optional_pos_integer_option(Key, Options) ->
    case maps:get(Key, Options, undefined) of
        undefined ->
            undefined;
        Value when is_integer(Value), Value > 0 ->
            Value;
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% 未指定なら undefined を返し、libFuzzer の既定値に任せる。
-spec optional_non_neg_integer_option(atom(), map()) ->
          undefined | non_neg_integer().
optional_non_neg_integer_option(Key, Options) ->
    case maps:get(Key, Options, undefined) of
        undefined ->
            undefined;
        Value when is_integer(Value), Value >= 0 ->
            Value;
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% libFuzzer の seed は unsigned 64 bit として扱う。
-spec optional_uint64_option(atom(), map()) -> undefined | non_neg_integer().
optional_uint64_option(Key, Options) ->
    case optional_non_neg_integer_option(Key, Options) of
        undefined ->
            undefined;
        Value when Value =< ?MAX_FEATURES ->
            Value;
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% パスを絶対パスのバイナリーにし、存在しなければ作成する。
-spec directory_option(atom(), map(), file:filename_all()) -> binary().
directory_option(Key, Options, Default) ->
    Path = filename:absname(to_binary(maps:get(Key, Options, Default))),
    case filelib:ensure_dir(filename:join(Path, <<".keep">>)) of
        ok ->
            Path;
        {error, Reason} ->
            erlang:error({invalid_option, {Key, Path, Reason}})
    end.


%% 辞書は存在する通常ファイルでなければならない。
-spec dict_option(map()) -> undefined | binary().
dict_option(Options) ->
    case maps:get(dict, Options, undefined) of
        undefined ->
            undefined;
        Path ->
            Absolute = filename:absname(to_binary(Path)),
            case filelib:is_regular(Absolute) of
                true ->
                    Absolute;
                false ->
                    erlang:error({invalid_option, {dict, Absolute, not_found}})
            end
    end.


%% cover の対象はモジュール名のリスト。実在確認は start_coverage/1 で行う。
-spec cover_option(map()) -> [module()].
cover_option(Options) ->
    case maps:get(cover, Options, []) of
        Modules when is_list(Modules) ->
            lists:foreach(fun validate_cover_module/1, Modules),
            Modules;
        Value ->
            erlang:error({invalid_option, {cover, Value}})
    end.


%% モジュール名以外は受け付けない。
-spec validate_cover_module(term()) -> ok.
validate_cover_module(Module) when is_atom(Module) ->
    ok;
validate_cover_module(Value) ->
    erlang:error({invalid_option, {cover, Value}}).


%% extra_args は libFuzzer へそのまま渡す。
-spec extra_args_option(map()) -> [binary()].
extra_args_option(Options) ->
    case maps:get(extra_args, Options, []) of
        Arguments when is_list(Arguments) ->
            [ validate_extra_arg(to_binary(Argument)) || Argument <:- Arguments ];
        Value ->
            erlang:error({invalid_option, {extra_args, Value}})
    end.


%% C の文字列に埋め込めない NUL を拒否する。
-spec validate_extra_arg(binary()) -> binary().
validate_extra_arg(Argument) ->
    case binary:match(Argument, <<0>>) of
        nomatch ->
            validate_supported_extra_arg(Argument);
        _ ->
            erlang:error({invalid_option, {extra_args, Argument}})
    end.


%% -jobs / -workers は子プロセスを起動するため、埋め込みドライバーでは
%% ハングする。extra_args 経由でも受け付けない。
-spec validate_supported_extra_arg(binary()) -> binary().
validate_supported_extra_arg(<<"-jobs", _/binary>> = Argument) ->
    erlang:error({invalid_option, {extra_args, Argument}});
validate_supported_extra_arg(<<"-workers", _/binary>> = Argument) ->
    erlang:error({invalid_option, {extra_args, Argument}});
validate_supported_extra_arg(Argument) ->
    Argument.


%% ファイルパスを、ファイルシステムのバイト列として扱えるバイナリーにする。
%% 文字列は UTF-8 に変換し、バイナリーはそのまま使う。これにより日本語を含む
%% パスも NIF へ渡せる。
-spec to_binary(term()) -> binary().
to_binary(Value) when is_binary(Value) ->
    Value;
to_binary(Value) when is_list(Value) ->
    case unicode:characters_to_binary(Value, unicode, utf8) of
        Bin when is_binary(Bin) ->
            Bin;
        _ ->
            erlang:error({invalid_option, {path, Value}})
    end;
to_binary(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
to_binary(Value) ->
    erlang:error({invalid_option, {path, Value}}).


%% rebar3_fuzzer と同じ既定ディレクトリーを使う。
-spec default_directory(module(), string()) -> binary().
default_directory(Target, Name) ->
    filename:join([<<"_build">>, <<"fuzz">>, atom_to_binary(Target, utf8), Name]).


%% libFuzzer の artifact_prefix はディレクトリーの末尾にセパレーターが必要。
%% 末尾にない場合はここで補う。
-spec add_trailing_separator(binary()) -> binary().
add_trailing_separator(<<>>) ->
    erlang:error({invalid_option, {artifacts, empty}});
add_trailing_separator(Path) ->
    case binary:last(Path) of
        $/ ->
            Path;
        _ ->
            <<Path/binary, $/>>
    end.


%% クラッシュレポートの SHA-1 計算に crypto を使うため、事前に起動する。
-spec ensure_crypto_started() -> ok.
ensure_crypto_started() ->
    case application:ensure_all_started(crypto) of
        {ok, _Started} ->
            ok;
        {error, Reason} ->
            erlang:error({crypto_unavailable, Reason})
    end.


%%%===================================================================
%%% libFuzzer の実行
%%%===================================================================


%% ワーカーとタイムアウト監視プロセスを起動し、NIF に libFuzzer の実行を任せる。
%% NIF が戻ったら（有限回の実行が終わったら）両方へ stop を送る。
%%
%% libFuzzer の -timeout は BEAM のシグナル処理と競合して効かないため、
%% -timeout=0 で無効化し、入力ごとのタイムアウトは Erlang 側の watchdog が担当する。
-spec run_fuzzer(map()) -> integer().
run_fuzzer(Config) ->
    Target = maps:get(target, Config),
    ArtifactDir = maps:get(artifacts, Config),
    TimeoutMs = timeout_ms(maps:get(timeout, Config)),
    Watchdog = spawn_link(fun() -> watchdog(ArtifactDir, TimeoutMs) end),
    Worker = spawn_link(fun() -> worker(Target, Watchdog, ArtifactDir) end),
    try
        run_nif(Worker, build_argv(Config))
    after
        Worker ! stop,
        Watchdog ! stop
    end.


%% timeout オプションの秒をミリ秒へ変換する。未指定ならタイマーを張らない。
-spec timeout_ms(undefined | pos_integer()) -> non_neg_integer().
timeout_ms(undefined) ->
    0;
timeout_ms(Seconds) ->
    Seconds * 1000.


%% libFuzzer の引数を組み立てる。argv[0] は NIF が設定する。
%% runs と max_total_time の 0 は「無制限」なので、フラグ自体を省略する。
-spec build_argv(map()) -> [binary()].
build_argv(Config) ->
    Base =
        [maps:get(corpus, Config),
         format("-max_len=~B", [maps:get(max_length, Config)]),
         <<"-artifact_prefix=", (maps:get(artifacts, Config))/binary>>,
         %% libFuzzer のタイムアウトは watchdog と競合するため無効化する。
         <<"-timeout=0">>],
    WithRuns = add_integer_flag(runs, "-runs=", Config, Base),
    WithDict = add_path_flag(dict, "-dict=", Config, WithRuns),
    WithMaxTotalTime =
        add_integer_flag(max_total_time, "-max_total_time=", Config, WithDict),
    WithSeed = add_integer_flag(seed, "-seed=", Config, WithMaxTotalTime),
    WithRssLimit =
        add_integer_flag(rss_limit_mb, "-rss_limit_mb=", Config, WithSeed),
    WithRssLimit ++ maps:get(extra_args, Config).


%% 0 を「無制限」として扱うフラグは、0 のときに引数を追加しない。
-spec add_integer_flag(atom(), string(), map(), [binary()]) -> [binary()].
add_integer_flag(Key, Prefix, Config, Arguments) ->
    case maps:get(Key, Config) of
        undefined ->
            Arguments;
        0 when Key =:= runs; Key =:= max_total_time ->
            Arguments;
        Value ->
            Arguments ++ [format(Prefix ++ "~B", [Value])]
    end.


%% パスを伴うフラグを追加する。
-spec add_path_flag(atom(), string(), map(), [binary()]) -> [binary()].
add_path_flag(Key, Prefix, Config, Arguments) ->
    case maps:get(Key, Config) of
        undefined ->
            Arguments;
        Value ->
            Arguments ++ [iolist_to_binary([Prefix, Value])]
    end.


%% io_lib:format/2 の結果をバイナリーにする。
-spec format(string(), [term()]) -> binary().
format(Format, Arguments) ->
    iolist_to_binary(io_lib:format(Format, Arguments)).


%%%===================================================================
%%% Erlang ワーカー
%%%===================================================================


%% ワーカーは fuzzing の間ずっと 1 個を使い回す。
%% init/0 はここで 1 回だけ呼ぶ。
-spec worker(module(), pid(), binary()) -> ok.
worker(Target, Watchdog, ArtifactDir) ->
    case code:ensure_loaded(Target) of
        {module, Target} ->
            call_optional(Target, init, []),
            worker_loop(Target, Watchdog, ArtifactDir);
        {error, Reason} ->
            erlang:error({target_not_loaded, Target, Reason})
    end.


%% 入力ごとに reset/0 を呼んでから evaluate/1 を実行する。
%% 状態を持つ fuzz target は reset/0 で状態を初期化できる。
%% watchdog には入力の開始と終了を通知し、入力タイムアウトを計測してもらう。
-spec worker_loop(module(), pid(), binary()) -> ok.
worker_loop(Target, Watchdog, ArtifactDir) ->
    receive
        {fuzz_input, Context, Data} ->
            Watchdog ! {fuzz_start, Context, Data},
            Result = evaluate(Target, Data),
            Watchdog ! {fuzz_done, Context},
            case Result of
                {ok, Features} ->
                    ok = reply(Context, Features);
                {crash, Report} ->
                    ok = write_crash_report(ArtifactDir, Data, Report),
                    ok = reply(Context, crash)
            end,
            worker_loop(Target, Watchdog, ArtifactDir);
        stop ->
            call_optional(Target, terminate, []),
            ok
    end.


%% fuzz target を呼び出し、例外を含めてクラッシュとして扱う。
%%
%% reset/0 と evaluate/1 のどちらで例外が起きても、その入力をクラッシュ入力として
%% 保存できるようにする。feature が 64 bit の範囲外なら、target の実装ミスとして
%% クラッシュ扱いにする。
-spec evaluate(module(), binary()) -> {ok, non_neg_integer()} | {crash, map()}.
evaluate(Target, Data) ->
    try call_optional(Target, reset, []) of
        _ ->
            try Target:evaluate(Data) of
                {ok, Features} when is_integer(Features),
                                    Features >= 0,
                                    Features =< ?MAX_FEATURES ->
                    {ok, Features};
                {ok, Features} ->
                    {crash, #{reason => {invalid_features, Features}}};
                crash ->
                    {crash, #{reason => target_returned_crash}};
                Other ->
                    {crash, #{reason => {invalid_return, Other}}}
            catch
                Class:Reason:Stacktrace ->
                    {crash,
                     #{
                       reason => {Class, Reason},
                       stacktrace => Stacktrace
                      }}
            end
    catch
        Class:Reason:Stacktrace ->
            {crash,
             #{
               reason => {reset_failed, Class, Reason},
               stacktrace => Stacktrace
              }}
    end.


%% fuzz target が実装していないコールバックは無視する。
%% init/0 / reset/0 / terminate/0 は任意のコールバック。
-spec call_optional(module(), atom(), [term()]) -> term().
call_optional(Target, Function, Arguments) ->
    case erlang:function_exported(Target, Function, length(Arguments)) of
        true ->
            apply(Target, Function, Arguments);
        false ->
            ok
    end.


%%%===================================================================
%%% 入力タイムアウト
%%%===================================================================


%% 入力の開始から終了までの時間を監視する。
%% タイムアウトしたらレポートを書き、NIF のコールバックを起こして BEAM を終了させる。
-spec watchdog(binary(), non_neg_integer()) -> ok.
watchdog(ArtifactDir, TimeoutMs) ->
    watchdog_loop(ArtifactDir, TimeoutMs, undefined).


-spec watchdog_loop(binary(), non_neg_integer(), undefined | reference()) -> ok.
watchdog_loop(ArtifactDir, TimeoutMs, Timer) ->
    receive
        {fuzz_start, Context, Data} ->
            ok = cancel_timer(Timer),
            NextTimer = arm_timer(TimeoutMs, Context, Data),
            watchdog_loop(ArtifactDir, TimeoutMs, NextTimer);
        {fuzz_done, _Context} ->
            ok = cancel_timer(Timer),
            watchdog_loop(ArtifactDir, TimeoutMs, undefined);
        {timeout, Context, Data} ->
            handle_timeout(ArtifactDir, TimeoutMs, Context, Data),
            watchdog_loop(ArtifactDir, TimeoutMs, undefined);
        stop ->
            ok = cancel_timer(Timer),
            ok
    end.


%% タイムアウト値をミリ秒で受け取り、その時間後に自分へメッセージを送る。
-spec arm_timer(non_neg_integer(), reference(), binary()) ->
          undefined | reference().
arm_timer(0, _Context, _Data) ->
    undefined;
arm_timer(TimeoutMs, Context, Data) ->
    erlang:send_after(TimeoutMs, self(), {timeout, Context, Data}).


-spec cancel_timer(undefined | reference()) -> ok.
cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    _ = erlang:cancel_timer(Timer),
    ok.


%% タイムアウトが現在の入力に対するものか確認してからレポートを書き、
%% NIF のコールバックを起こす。すでに入力が終わっていた場合は何もしない。
-spec handle_timeout(binary(), non_neg_integer(), reference(), binary()) -> ok.
handle_timeout(ArtifactDir, TimeoutMs, Context, Data) ->
    Result =
        try
            timeout(Context)
        catch
            _:_ ->
                ok
        end,
    case Result of
        timeout ->
            ok = write_crash_report(ArtifactDir,
                                    Data,
                                    #{
                                      reason => timeout,
                                      timeout_ms => TimeoutMs
                                     }),
            _ = try
                    abort_timeout(Context)
                catch
                    _:_ ->
                        ok
                end,
            ok;
        _ ->
            ok
    end.


%%%===================================================================
%%% クラッシュレポート
%%%===================================================================


%% libFuzzer が保存する artifact と同じ SHA-1 を使い、artifact の隣に
%% クラッシュレポートを書き出す。
%%
%%   crash-<SHA-1>          libFuzzer が保存するクラッシュ入力
%%   crash-<SHA-1>.report   この関数が書くレポート
%%
%% レポートには入力の SHA-1 とサイズ、例外の種類、理由、スタックトレースが入る。
-spec write_crash_report(binary(), binary(), map()) -> ok.
write_crash_report(ArtifactDir, Data, Report) ->
    Hash = sha1_hex(Data),
    FileName = <<"crash-", Hash/binary, ".report">>,
    Path = filename:join(ArtifactDir, FileName),
    Entry =
        maps:merge(#{input_sha1 => Hash, input_size => byte_size(Data)}, Report),
    Body = unicode:characters_to_binary(io_lib:format("~p.~n", [Entry])),
    case file:write_file(Path, Body) of
        ok ->
            ok;
        {error, Reason} ->
            %% レポートの書き込み失敗で fuzzing を止めない。クラッシュ入力自体は
            %% libFuzzer が保存するため、ここでは警告だけにする。
            logger:warning("Failed to write a crash report: ~p", [Reason]),
            ok
    end.


%% libFuzzer の artifact 名は小文字 16 進の SHA-1。
-spec sha1_hex(binary()) -> binary().
sha1_hex(Data) ->
    hex(crypto:hash(sha, Data)).


%% バイナリーを小文字 16 進へ変換する。
-spec hex(binary()) -> binary().
hex(Bin) ->
    << <<(hex_digit(Nibble))>> || <<Nibble:4>> <:= Bin >>.


%% 0..15 を小文字 16 進の文字にする。
-spec hex_digit(0..15) -> byte().
hex_digit(Nibble) when Nibble < 10 ->
    $0 + Nibble;
hex_digit(Nibble) ->
    $a + (Nibble - 10).


%%%===================================================================
%%% Erlang カバレッジ
%%%===================================================================


%% cover サーバーを起動し、対象モジュールを cover でコンパイルする。
%%
%% 自分で cover を起動した場合は、run/1 の最後に stop_coverage/1 で停止する。
%% 呼び出し元が既に cover を起動していた場合は、その状態を壊さないように停止しない。
-spec start_coverage([module()]) -> undefined | map().
start_coverage([]) ->
    undefined;
start_coverage(Modules) ->
    Started = start_cover_server(),
    try
        lists:foreach(fun compile_cover/1, Modules),
        #{started => Started, modules => Modules}
    catch
        Class:Reason:Stacktrace ->
            %% コンパイル途中で失敗した場合、自分で起動した cover を片付ける。
            case Started of
                true ->
                    _ = cover:stop();
                false ->
                    ok
            end,
            erlang:raise(Class, Reason, Stacktrace)
    end.


%% cover サーバーが既に起動している場合は、自分では起動していないことを記録する。
-spec start_cover_server() -> boolean().
start_cover_server() ->
    case cover:start() of
        {ok, _Pid} ->
            true;
        {error, {already_started, _Pid}} ->
            false;
        {error, Reason} ->
            erlang:error({cover_unavailable, Reason})
    end.


%% 既に cover 済みなら二重にコンパイルしない。
-spec compile_cover(module()) -> ok.
compile_cover(Module) ->
    case cover:is_compiled(Module) of
        true ->
            ok;
        false ->
            compile_cover_beam(Module)
    end.


%% beam ファイルの場所を解決する。
-spec compile_cover_beam(module()) -> ok.
compile_cover_beam(Module) ->
    case code:which(Module) of
        non_existing ->
            erlang:error({invalid_option, {cover, Module, not_found}});
        Beam ->
            compile_cover_module(Module, Beam)
    end.


%% debug_info がない beam は cover:compile_beam/1 が失敗する。
%% rebar3 の既定の設定では debug_info が付与される。
-spec compile_cover_module(module(), file:filename_all()) -> ok.
compile_cover_module(Module, Beam) ->
    case cover:compile_beam(Beam) of
        {ok, Module} ->
            ok;
        {error, Reason} ->
            erlang:error({invalid_option, {cover, Module, Reason}})
    end.


%% モジュールごとのカバレッジを集計する。
-spec collect_coverage(undefined | map()) -> undefined | coverage().
collect_coverage(undefined) ->
    undefined;
collect_coverage(#{modules := Modules}) ->
    maps:from_list([ {Module, analyse_coverage(Module)} || Module <:- Modules ]).


%% cover:analyse/3 の結果を、covered / total と割合のマップにする。
-spec analyse_coverage(module()) -> map().
analyse_coverage(Module) ->
    case cover:analyse(Module, coverage, module) of
        {ok, {Module, {Covered, NotCovered}}} ->
            Total = Covered + NotCovered,
            Percentage =
                case Total of
                    0 ->
                        0.0;
                    _ ->
                        Covered * 100.0 / Total
                end,
            #{
              covered => Covered,
              not_covered => NotCovered,
              total => Total,
              percentage => Percentage
             };
        {error, Reason} ->
            #{error => Reason}
    end.


%% 自分で起動した cover だけ停止する。呼び出し元が起動していた場合は触らない。
-spec stop_coverage(undefined | map()) -> ok | {error, term()}.
stop_coverage(undefined) ->
    ok;
stop_coverage(#{started := true}) ->
    cover:stop();
stop_coverage(#{started := false}) ->
    ok.


%%%===================================================================
%%% NIF
%%%===================================================================


%% NIF をロードする。
-spec init() -> ok | {error, term()}.
init() ->
    PrivDir = code:priv_dir(fuzzer),
    erlang:load_nif(filename:join(PrivDir, "fuzzer_nif"), 0).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec run_nif(pid(), [binary()]) -> integer().
run_nif(_Worker, _Argv) ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec reply(reference(), non_neg_integer() | crash) -> ok.
reply(_Context, _Result) ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec timeout(reference()) -> timeout | ok.
timeout(_Context) ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec abort_timeout(reference()) -> ok.
abort_timeout(_Context) ->
    erlang:nif_error(nif_library_not_loaded).
