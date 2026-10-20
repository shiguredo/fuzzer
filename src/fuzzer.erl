%% Erlang の fuzz target を libFuzzer から実行するための API。
%%
%% 実行モデル:
%%   fuzzer:run/1 または run/5 を呼ぶと、NIF が dirty CPU スケジューラーで
%%   LLVMFuzzerRunDriver を実行する。libFuzzer が入力を生成するたびに、NIF は
%%   通常スケジューラーで動く 1 個の Erlang ワーカーへバイナリーを送る。
%%   ワーカーは fuzz target の evaluate/1 を呼び、ok または feature bitmap を返す。
%%   クラッシュは例外で通知する。
%%
%% 探索:
%%   パーサーの行・節の到達は feedback オプションで対象のモジュールを指定して
%%   libFuzzer へ渡す。意味的な状態を追加で伝えたい場合だけ feature bitmap を返す。
%%
%% feature bitmap:
%%   0 以上 16#FFFFFFFFFFFFFFFF 以下の 64 bit 値。fuzz target が到達した意味的な
%%   状態を各 bit に割り当てる。NIF は各 bit と bitmap 全体のハッシュを libFuzzer の
%%   カウンターへ反映する。
%%
%% クラッシュ:
%%   evaluate/1 が例外を送出するかワーカーが終了すると、libFuzzer は BEAM 全体を終了する。
%%   その前に、artifact と同じ SHA-1 を持つレポートを artifacts ディレクトリーへ書く。
%%
%% カバレッジ:
%%   cover オプションで指定した Erlang モジュールのカバレッジを実行後に返す。
%%
%% このモジュールは fuzzing 専用の BEAM で使うこと。他の処理と同じ BEAM で
%% 長時間実行すると、dirty CPU スケジューラーを 1 本占有し続ける。
-module(fuzzer).

-on_load(init/0).

-export([run/1, run/5,
         run_one/2,
         reproduce/2,
         libfuzzer_version/0,
         max_feedback_counters/0]).

%% fuzzer:run/1 が受け付けるオプション。
%% 必須は target だけ。その他は既定値を持つか、未指定なら libFuzzer の既定値に任せる。
-type path() :: file:filename_all().
-type feedback_mode() :: line | clause.
-type on_crash() :: abort | continue.
%% feedback はモジュールのリスト、またはモジュールと計測単位のマップ。
%% リストは line モードの省略形である。
-type feedback() ::
        [module()] |
        #{
          modules := [module()],
          mode => feedback_mode()
         }.
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
          feedback => feedback(),
          auto_dict => boolean(),
          dict_modules => [module()],
          on_crash => on_crash(),
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
%% crashes は on_crash => continue のときに検出した、重複を除いたクラッシュの一覧。
-type result() ::
        #{
          exit_code := integer(),
          coverage := undefined | coverage(),
          crashes := [map()]
         }.

-export_type([coverage/0,
              feedback/0,
              feedback_mode/0,
              on_crash/0,
              options/0,
              result/0]).

-define(MAX_FEATURES,       16#FFFFFFFFFFFFFFFF).
-define(DEFAULT_MAX_LENGTH, 4096).

%%%===================================================================
%%% 公開 API
%%%===================================================================


%% オプションマップを指定して fuzzing を実行する。
%%
%% 戻り値は次のマップ。
%%   #{exit_code := integer(),
%%     coverage := undefined | coverage(),
%%     crashes := [map()]}
%%
%% オプションが不正な場合は error({invalid_option, ...}) を送出する。
%% on_crash => abort の場合、クラッシュ時は libFuzzer が BEAM 全体を終了するため、
%% この関数は戻らないことがある。on_crash => continue の場合は継続し、重複を除いた
%% クラッシュを crashes に返す。
-spec run(options()) -> result().
run(Options) when is_map(Options) ->
    Config0 = normalize_options(Options),
    {Config, DictCleanup} = prepare_dictionary(Config0),
    try
        ok = ensure_crypto_started(),
        CoverageState = start_coverage(maps:get(cover, Config)),
        try
            FeedbackState = start_feedback(maps:get(feedback, Config)),
            try
                {ExitCode, Crashes} = run_fuzzer(Config, FeedbackState),
                #{
                  exit_code => ExitCode,
                  coverage => collect_coverage(CoverageState),
                  crashes => Crashes
                 }
            after
                stop_feedback(FeedbackState)
            end
        after
            stop_coverage(CoverageState)
        end
    after
        cleanup_dictionary(DictCleanup)
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


%% NIF に静的リンクした libFuzzer のバージョンを返す。
%%
%% libFuzzer は compiler-rt の一部であり、NIF をビルドした Clang と同じバージョンで
%% 配布される。この値は NIF をビルドした時点の Clang のバージョンである。
-spec libfuzzer_version() -> binary().
libfuzzer_version() ->
    libfuzzer_version_nif().


%% NIF が 1 回の fuzzing で受け付けられるフィードバックカウンターの上限を返す。
%%
%% 実際に登録されるカウンター数は、feedback で指定したモジュールの行数と節数に
%% よって決まる。この上限を超える場合は feedback のセットアップが失敗する。
-spec max_feedback_counters() -> pos_integer().
max_feedback_counters() ->
    max_feedback_counters_nif().


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
         feedback,
         auto_dict,
         dict_modules,
         on_crash,
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
    %% 辞書と cover と feedback は、ディレクトリーを作る前に検証して副作用を減らす。
    Dict = dict_option(Options),
    Cover = cover_option(Options),
    Feedback = feedback_option(Options),
    ok = validate_feedback_cover(Feedback, Cover),
    AutoDict = boolean_option(auto_dict, Options, true),
    DictModules = modules_option(dict_modules, Options, []),
    OnCrash = on_crash_option(Options),
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
      feedback => Feedback,
      auto_dict => AutoDict,
      dict_modules => DictModules,
      on_crash => OnCrash,
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


%% feedback の指定を、モジュールのリストと計測単位のマップへ正規化する。
%%
%% モジュールのリストは line モードの省略形として受け付ける。マップでは
%% modules が必須で、mode は line / clause のいずれかになる。
-spec feedback_option(map()) -> #{modules := [module()], mode := feedback_mode()}.
feedback_option(Options) ->
    case maps:get(feedback, Options, []) of
        [] ->
            #{modules => [], mode => line};
        Modules when is_list(Modules) ->
            #{modules => normalize_feedback_modules(Modules), mode => line};
        #{modules := Modules} = Config ->
            validate_feedback_keys(Config),
            Mode = maps:get(mode, Config, line),
            ok = validate_feedback_mode(Mode),
            #{modules => normalize_feedback_modules(Modules), mode => Mode};
        Value ->
            erlang:error({invalid_option, {feedback, Value}})
    end.


%% モジュールのリストを受け取るオプションを検証する。
-spec modules_option(atom(), map(), [module()]) -> [module()].
modules_option(Key, Options, Default) ->
    case maps:get(Key, Options, Default) of
        Modules when is_list(Modules) ->
            lists:foreach(fun(Module) when is_atom(Module) ->
                                  ok;
                             (Value) ->
                                  erlang:error({invalid_option, {Key, Value}})
                          end,
                          Modules),
            lists:usort(Modules);
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% feedback のマップで受け付けるキーだけを許可する。
-spec validate_feedback_keys(map()) -> ok.
validate_feedback_keys(Config) ->
    case maps:keys(Config) -- [modules, mode] of
        [] ->
            ok;
        Unknown ->
            erlang:error({invalid_option, {feedback, {unknown, Unknown}}})
    end.


%% モジュール名だけを許可し、重複を除いて順序を固定する。
-spec normalize_feedback_modules(term()) -> [module()].
normalize_feedback_modules(Modules) when is_list(Modules) ->
    lists:foreach(fun validate_feedback_module/1, Modules),
    lists:usort(Modules);
normalize_feedback_modules(Value) ->
    erlang:error({invalid_option, {feedback, {modules, Value}}}).


-spec validate_feedback_module(term()) -> ok.
validate_feedback_module(Module) when is_atom(Module) ->
    ok;
validate_feedback_module(Value) ->
    erlang:error({invalid_option, {feedback, {module, Value}}}).


-spec validate_feedback_mode(term()) -> ok.
validate_feedback_mode(line) ->
    ok;
validate_feedback_mode(clause) ->
    ok;
validate_feedback_mode(Value) ->
    erlang:error({invalid_option, {feedback, {mode, Value}}}).


%% boolean オプションを検証する。
-spec boolean_option(atom(), map(), boolean()) -> boolean().
boolean_option(Key, Options, Default) ->
    case maps:get(Key, Options, Default) of
        true ->
            true;
        false ->
            false;
        Value ->
            erlang:error({invalid_option, {Key, Value}})
    end.


%% on_crash はクラッシュした入力を受け取った後の動作を決める。
-spec on_crash_option(map()) -> on_crash().
on_crash_option(Options) ->
    case maps:get(on_crash, Options, abort) of
        abort ->
            abort;
        continue ->
            continue;
        Value ->
            erlang:error({invalid_option, {on_crash, Value}})
    end.


%% cover は実行後の集計のためにモジュールをロードし直す。feedback と同時に使うと
%% どちらかの計測用コードが失われるため、同時指定は受け付けない。
-spec validate_feedback_cover(#{modules := [module()]}, [module()]) -> ok.
validate_feedback_cover(#{modules := []}, _CoverModules) ->
    ok;
validate_feedback_cover(#{modules := _Modules}, []) ->
    ok;
validate_feedback_cover(#{modules := _Modules}, _CoverModules) ->
    erlang:error({invalid_option,
                  {feedback, incompatible_with_cover}}).


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


%% 自動生成した辞書と利用者の辞書をまとめた一時ファイルを用意する。
%%
%% 生成した辞書を使わない場合や、リテラルが見つからなかった場合は、利用者の
%% 辞書をそのまま使う。戻り値の 2 番目は終了時の後始末に使う。
-spec prepare_dictionary(map()) -> {map(), undefined | {auto_dict, file:filename_all()}}.
prepare_dictionary(Config) ->
    case maps:get(auto_dict, Config) of
        false ->
            {Config, undefined};
        true ->
            prepare_auto_dictionary(Config)
    end.


-spec prepare_auto_dictionary(map()) ->
          {map(), undefined | {auto_dict, file:filename_all()}}.
prepare_auto_dictionary(Config) ->
    Modules = auto_dict_modules(Config),
    case fuzzer_dict:generate(Modules) of
        {ok, []} ->
            logger:warning("No literals were found for the automatic dictionary: ~p",
                           [Modules]),
            {Config, undefined};
        {ok, Entries} ->
            merge_dictionary(Config, Entries)
    end.


%% 自動辞書の生成元を返す。
%%
%% dict_modules が指定されていれば target に加えてそのモジュールを使う。
%% 指定がなければ target と feedback のモジュールを使う。
-spec auto_dict_modules(map()) -> [module()].
auto_dict_modules(Config) ->
    Target = maps:get(target, Config),
    case maps:get(dict_modules, Config) of
        [] ->
            Feedback = maps:get(feedback, Config),
            lists:usort([Target | maps:get(modules, Feedback)]);
        DictModules ->
            lists:usort([Target | DictModules])
    end.


-spec merge_dictionary(map(), [binary()]) ->
          {map(), {auto_dict, file:filename_all()}}.
merge_dictionary(Config, Entries) ->
    UserDict = maps:get(dict, Config),
    case fuzzer_dict:merge(UserDict, Entries, fuzzer_dict:temp_directory()) of
        {ok, Path} ->
            {Config#{dict => Path}, {auto_dict, Path}};
        {error, Reason} ->
            erlang:error({auto_dict, Reason})
    end.


%% 自動生成した辞書の一時ファイルを削除する。
-spec cleanup_dictionary(undefined | {auto_dict, file:filename_all()}) -> ok.
cleanup_dictionary(undefined) ->
    ok;
cleanup_dictionary({auto_dict, Path}) ->
    _ = file:delete(Path),
    ok.


%% feedback で指定されたモジュールを計測用にコンパイルし直してロードする。
%% 指定がない場合は undefined を返し、フィードバックを一切使わない。
-spec start_feedback(#{modules := [module()], mode := feedback_mode()}) ->
          undefined | fuzzer_feedback:state().
start_feedback(#{modules := []}) ->
    undefined;
start_feedback(Config) ->
    fuzzer_feedback:setup(Config).


%% 計測用にロードしたモジュールを元へ戻す。
-spec stop_feedback(undefined | fuzzer_feedback:state()) -> ok.
stop_feedback(undefined) ->
    ok;
stop_feedback(FeedbackState) ->
    fuzzer_feedback:teardown(FeedbackState).


%%%===================================================================
%%% libFuzzer の実行
%%%===================================================================


%% ワーカーとタイムアウト監視プロセスを起動し、NIF に libFuzzer の実行を任せる。
%% NIF が戻ったら（有限回の実行が終わったら）両方へ stop を送る。
%%
%% libFuzzer の -timeout は BEAM のシグナル処理と競合して効かないため、
%% -timeout=0 で無効化し、入力ごとのタイムアウトは Erlang 側の watchdog が担当する。
-spec run_fuzzer(map(), undefined | fuzzer_feedback:state()) ->
          {integer(), [map()]}.
run_fuzzer(Config, FeedbackState) ->
    Target = maps:get(target, Config),
    ArtifactDir = maps:get(artifacts, Config),
    TimeoutMs = timeout_ms(maps:get(timeout, Config)),
    OnCrash = maps:get(on_crash, Config),
    CrashTable = ets:new(fuzzer_crashes, [set, public, {read_concurrency, true}]),
    Parent = self(),
    Watchdog =
        spawn_link(fun() ->
                           watchdog_init(Parent,
                                         Target,
                                         ArtifactDir,
                                         TimeoutMs,
                                         FeedbackState,
                                         CrashTable,
                                         OnCrash)
                   end),
    Worker =
        receive
            {fuzzer_worker, Watchdog, WorkerPid} ->
                WorkerPid
        after
            5000 ->
                erlang:error(watchdog_start_timeout)
        end,
    try
        ExitCode = run_nif(Worker, build_argv(Config), feedback_counter_count(FeedbackState)),
        {ExitCode, crash_summary(CrashTable)}
    after
        ok = stop_watchdog(Watchdog),
        ets:delete(CrashTable)
    end.


%% ワーカーへ stop を送り、terminate/0 が終わるまで待つ。
%%
%% feedback はワーカーの停止後にモジュールを元へ戻す。terminate/0 の実行中に
%% モジュールをリロードすると、実行中のコードと新しいコードが混ざるため、
%% 必ずここで停止を待つ。
-spec stop_worker(pid()) -> ok.
stop_worker(Worker) ->
    Monitor = erlang:monitor(process, Worker),
    Worker ! stop,
    receive
        {'DOWN', Monitor, process, Worker, _Reason} ->
            ok
    after
        5000 ->
            % リンク越しに kill が自分へ伝わらないよう、先にリンクを外す。
            unlink(Worker),
            exit(Worker, kill),
            receive
                {'DOWN', Monitor, process, Worker, _Reason} ->
                    ok
            after
                1000 ->
                    erlang:demonitor(Monitor, [flush]),
                    ok
            end
    end.


%% watchdog へ stop を送り、現在のワーカーの terminate/0 まで待つ。
-spec stop_watchdog(pid()) -> ok.
stop_watchdog(Watchdog) ->
    Monitor = erlang:monitor(process, Watchdog),
    Watchdog ! stop,
    receive
        {'DOWN', Monitor, process, Watchdog, _Reason} ->
            ok
    after
        10000 ->
            unlink(Watchdog),
            exit(Watchdog, kill),
            receive
                {'DOWN', Monitor, process, Watchdog, _Reason} ->
                    ok
            after
                1000 ->
                    erlang:demonitor(Monitor, [flush]),
                    ok
            end
    end.


%% NIF に登録するフィードバックカウンターの数を返す。
-spec feedback_counter_count(undefined | fuzzer_feedback:state()) -> non_neg_integer().
feedback_counter_count(undefined) ->
    0;
feedback_counter_count(FeedbackState) ->
    fuzzer_feedback:counter_count(FeedbackState).


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
%% init/0 は最初の入力の直前に 1 回だけ呼ぶ。タイムアウトでワーカーを
%% 作り直す場合に、使われないワーカーで init/0 を実行しないためである。
-spec worker(module(),
             pid(),
             binary(),
             undefined | fuzzer_feedback:state(),
             ets:tid(),
             on_crash()) -> ok.
worker(Target, Watchdog, ArtifactDir, FeedbackState, CrashTable, OnCrash) ->
    case code:ensure_loaded(Target) of
        {module, Target} ->
            % reset/0 を持たない target では、前回の読み出しでカウンターが
            % 0 に戻っているため、入力ごとの評価前リセットを省略できる。
            HasReset = erlang:function_exported(Target, reset, 0),
            worker_loop(Target,
                        Watchdog,
                        ArtifactDir,
                        FeedbackState,
                        CrashTable,
                        OnCrash,
                        HasReset,
                        false);
        {error, Reason} ->
            erlang:error({target_not_loaded, Target, Reason})
    end.


%% 入力ごとに reset/0 を呼んでから evaluate/1 を実行する。
%% 状態を持つ fuzz target は reset/0 で状態を初期化できる。
%% watchdog には入力の開始と終了を通知し、入力タイムアウトを計測してもらう。
%% feedback を使う場合は、reset/0 の直後と evaluate/1 の直後でカウンターを操作する。
-spec worker_loop(module(),
                  pid(),
                  binary(),
                  undefined | fuzzer_feedback:state(),
                  ets:tid(),
                  on_crash(),
                  boolean(),
                  boolean()) -> ok.
worker_loop(Target,
            Watchdog,
            ArtifactDir,
            FeedbackState,
            CrashTable,
            OnCrash,
            HasReset,
            Initialized) ->
    receive
        {fuzz_input, Context, Generation, Data} ->
            ok = ensure_worker_initialized(Target, FeedbackState, Initialized),
            Watchdog ! {fuzz_start, Context, Generation, Data},
            Result = evaluate(Target, Data, FeedbackState, HasReset),
            case Result of
                {ok, Features, Counters} ->
                    % reply で NIF を先に起こしてから fuzz_done を送る。
                    % 次の入力が始まっても、古い世代のタイマーは NIF 側の
                    % 世代検査で無効になる。
                    ok = reply(Context, Generation, Features, Counters),
                    Watchdog ! {fuzz_done, Context, Generation};
                {crash, #{reason := {feedback_failure, _}} = Report} ->
                    % feedback 自体が壊れている場合は、継続しても正しい
                    % カウンターを渡せないため、target のクラッシュとは区別して
                    % 常に BEAM を終了する。
                    ok = record_crash(CrashTable, ArtifactDir, Data, Report),
                    ok = reply(Context, Generation, crash, <<>>);
                {crash, Report} ->
                    ok = record_crash(CrashTable, ArtifactDir, Data, Report),
                    % 同じ BEAM で継続できるよう、クラッシュ時もカウンターを
                    % 0 に戻しておく。失敗しても元のクラッシュを優先する。
                    ok = reset_feedback_quietly(FeedbackState),
                    case OnCrash of
                        continue ->
                            ok = reply(Context, Generation, continue, <<>>),
                            Watchdog ! {fuzz_done, Context, Generation};
                        abort ->
                            ok = reply(Context, Generation, crash, <<>>)
                    end
            end,
            worker_loop(Target,
                        Watchdog,
                        ArtifactDir,
                        FeedbackState,
                        CrashTable,
                        OnCrash,
                        HasReset,
                        true);
        stop ->
            case Initialized of
                true ->
                    call_optional(Target, terminate, []);
                false ->
                    ok
            end,
            ok
    end.


%% 最初の入力の直前に init/0 を呼び、init/0 のヒットをカウンターから除く。
-spec ensure_worker_initialized(module(),
                                undefined | fuzzer_feedback:state(),
                                boolean()) -> ok.
ensure_worker_initialized(_Target, _FeedbackState, true) ->
    ok;
ensure_worker_initialized(Target, FeedbackState, false) ->
    call_optional(Target, init, []),
    reset_feedback_after_init(FeedbackState).


%% fuzz target を呼び出し、例外を含めてクラッシュとして扱う。
%%
%% reset/0 と evaluate/1 のどちらで例外が起きても、その入力をクラッシュ入力として
%% 保存できるようにする。feature が 64 bit の範囲外なら、target の実装ミスとして
%% クラッシュ扱いにする。
-spec evaluate(module(), binary()) -> {ok, non_neg_integer()} | {crash, map()}.
evaluate(Target, Data) ->
    case evaluate(Target, Data, undefined) of
        {ok, Features, _Counters} ->
            {ok, Features};
        {crash, _Report} = Crash ->
            Crash
    end.


-spec evaluate(module(), binary(), undefined | fuzzer_feedback:state()) ->
          {ok, non_neg_integer(), binary()} | {crash, map()}.
evaluate(Target, Data, FeedbackState) ->
    evaluate(Target, Data, FeedbackState, true).


-spec evaluate(module(), binary(), undefined | fuzzer_feedback:state(), boolean()) ->
          {ok, non_neg_integer(), binary()} | {crash, map()}.
evaluate(Target, Data, FeedbackState, HasReset) ->
    try call_optional(Target, reset, []) of
        _ ->
            case maybe_reset_feedback(FeedbackState, HasReset) of
                ok ->
                    evaluate_target(Target, Data, FeedbackState, not HasReset);
                {error, Reason} ->
                    feedback_failure(Reason)
            end
    catch
        Class:Reason:Stacktrace ->
            Report =
                #{
                  reason => {reset_failed, Class, Reason},
                  stacktrace => Stacktrace
                 },
            {crash, crash_report(Report)}
    end.


%% target の evaluate/1 を呼び、成功時はフィードバックカウンターも読み出す。
-spec evaluate_target(module(),
                      binary(),
                      undefined | fuzzer_feedback:state(),
                      boolean()) ->
          {ok, non_neg_integer(), binary()} | {crash, map()}.
evaluate_target(Target, Data, FeedbackState, ResetLine) ->
    try Target:evaluate(Data) of
        ok ->
            evaluate_features(0, FeedbackState, ResetLine);
        {ok, Features} when is_integer(Features),
                            Features >= 0,
                            Features =< ?MAX_FEATURES ->
            evaluate_features(Features, FeedbackState, ResetLine);
        {ok, Features} ->
            {crash, crash_report(#{reason => {invalid_features, Features}})};
        Other ->
            {crash, crash_report(#{reason => {invalid_return, Other}})}
    catch
        Class:Reason:Stacktrace ->
            Report =
                #{
                  reason => {Class, Reason},
                  stacktrace => Stacktrace
                 },
            {crash, crash_report(Report)}
    end.


%% feature bitmap と、その入力のフィードバックカウンターをまとめて返す。
-spec evaluate_features(non_neg_integer(),
                        undefined | fuzzer_feedback:state(),
                        boolean()) ->
          {ok, non_neg_integer(), binary()} | {crash, map()}.
evaluate_features(Features, FeedbackState, ResetLine) ->
    case read_feedback(FeedbackState, ResetLine) of
        {ok, Counters} ->
            {ok, Features, Counters};
        {error, Reason} ->
            feedback_failure(Reason)
    end.


%% クラッシュレポートに、クラッシュの同一性を表す識別子を加える。
-spec crash_report(map()) -> map().
crash_report(Report) ->
    Report#{crash_id => fuzzer_crash:id_from_report(Report)}.


%% reset/0 が実行した分をフィードバックカウンターから除外する。
%%
%% reset/0 を持たない target では、read/2 が読み出し後にカウンターを 0 に
%% 戻しているため、評価前のリセットを省略できる。
-spec maybe_reset_feedback(undefined | fuzzer_feedback:state(), boolean()) ->
          ok | {error, term()}.
maybe_reset_feedback(_FeedbackState, false) ->
    ok;
maybe_reset_feedback(FeedbackState, true) ->
    reset_feedback(FeedbackState).


%% init/0 が実行した分を、最初の入力の前に取り除く。
-spec reset_feedback_after_init(undefined | fuzzer_feedback:state()) -> ok.
reset_feedback_after_init(undefined) ->
    ok;
reset_feedback_after_init(FeedbackState) ->
    case reset_feedback(FeedbackState) of
        ok ->
            ok;
        {error, Reason} ->
            abort_feedback_failure(Reason)
    end.


%% フィードバック側の失敗は target のクラッシュと区別し、理由を stderr へ
%% 同期的に書いてからクラッシュレポートにする。
-spec reset_feedback(undefined | fuzzer_feedback:state()) ->
          ok | {error, term()}.
reset_feedback(undefined) ->
    ok;
reset_feedback(FeedbackState) ->
    try fuzzer_feedback:reset(FeedbackState) of
        ok ->
            ok
    catch
        Class:Reason:Stacktrace ->
            {error, {feedback_reset_failed, Class, Reason, Stacktrace}}
    end.


%% 入力 1 回分のフィードバックカウンターを読み出す。
-spec read_feedback(undefined | fuzzer_feedback:state(), boolean()) ->
          {ok, binary()} | {error, term()}.
read_feedback(undefined, _ResetLine) ->
    {ok, <<>>};
read_feedback(FeedbackState, ResetLine) ->
    try fuzzer_feedback:read(FeedbackState, ResetLine) of
        Counters ->
            {ok, Counters}
    catch
        Class:Reason:Stacktrace ->
            {error, {feedback_read_failed, Class, Reason, Stacktrace}}
    end.


-spec reset_feedback_quietly(undefined | fuzzer_feedback:state()) -> ok.
reset_feedback_quietly(undefined) ->
    ok;
reset_feedback_quietly(FeedbackState) ->
    case reset_feedback(FeedbackState) of
        ok ->
            ok;
        {error, _Reason} ->
            ok
    end.


-spec feedback_failure(term()) -> {crash, map()}.
feedback_failure(Reason) ->
    log_feedback_failure(Reason),
    {crash, ensure_crash_id(#{reason => {feedback_failure, Reason}})}.


-spec abort_feedback_failure(term()) -> no_return().
abort_feedback_failure(Reason) ->
    log_feedback_failure(Reason),
    erlang:error({feedback_failure, Reason}).


-spec log_feedback_failure(term()) -> ok.
log_feedback_failure(Reason) ->
    io:format(standard_error, "fuzzer: feedback failure: ~p~n", [Reason]).


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
%% タイムアウトしたらワーカーを差し替え、継続モードでは fuzzing を続ける。
-spec watchdog_init(pid(),
                    module(),
                    binary(),
                    non_neg_integer(),
                    undefined | fuzzer_feedback:state(),
                    ets:tid(),
                    on_crash()) -> ok.
watchdog_init(Parent, Target, ArtifactDir, TimeoutMs, FeedbackState, CrashTable, OnCrash) ->
    Worker = spawn_worker(Target, self(), ArtifactDir, FeedbackState, CrashTable, OnCrash),
    Parent ! {fuzzer_worker, self(), Worker},
    watchdog_loop(Target,
                  ArtifactDir,
                  TimeoutMs,
                  FeedbackState,
                  CrashTable,
                  OnCrash,
                  Worker,
                  undefined,
                  undefined).


-spec watchdog_loop(module(),
                    binary(),
                    non_neg_integer(),
                    undefined | fuzzer_feedback:state(),
                    ets:tid(),
                    on_crash(),
                    pid(),
                    undefined | non_neg_integer(),
                    undefined | reference()) -> ok.
watchdog_loop(Target,
              ArtifactDir,
              TimeoutMs,
              FeedbackState,
              CrashTable,
              OnCrash,
              Worker,
              CurrentGeneration,
              Timer) ->
    receive
        {fuzz_start, Context, Generation, Data} ->
            ok = cancel_timer(Timer),
            NextTimer = arm_timer(TimeoutMs, Context, Generation, Data),
            watchdog_loop(Target,
                          ArtifactDir,
                          TimeoutMs,
                          FeedbackState,
                          CrashTable,
                          OnCrash,
                          Worker,
                          Generation,
                          NextTimer);
        {fuzz_done, _Context, Generation} ->
            case CurrentGeneration of
                Generation ->
                    ok = cancel_timer(Timer),
                    watchdog_loop(Target,
                                  ArtifactDir,
                                  TimeoutMs,
                                  FeedbackState,
                                  CrashTable,
                                  OnCrash,
                                  Worker,
                                  undefined,
                                  undefined);
                _ ->
                    watchdog_loop(Target,
                                  ArtifactDir,
                                  TimeoutMs,
                                  FeedbackState,
                                  CrashTable,
                                  OnCrash,
                                  Worker,
                                  CurrentGeneration,
                                  Timer)
            end;
        {timeout, Context, Generation, Data} ->
            case CurrentGeneration of
                Generation ->
                    NextWorker =
                        handle_timeout(Target,
                                       ArtifactDir,
                                       TimeoutMs,
                                       FeedbackState,
                                       CrashTable,
                                       OnCrash,
                                       Worker,
                                       Context,
                                       Generation,
                                       Data),
                    watchdog_loop(Target,
                                  ArtifactDir,
                                  TimeoutMs,
                                  FeedbackState,
                                  CrashTable,
                                  OnCrash,
                                  NextWorker,
                                  undefined,
                                  undefined);
                _ ->
                    watchdog_loop(Target,
                                  ArtifactDir,
                                  TimeoutMs,
                                  FeedbackState,
                                  CrashTable,
                                  OnCrash,
                                  Worker,
                                  CurrentGeneration,
                                  Timer)
            end;
        stop ->
            ok = cancel_timer(Timer),
            ok = stop_worker(Worker),
            ok
    end.


%% ワーカーを起動する。ワーカーは watchdog とリンクせず、タイムアウト時に
%% watchdog が kill できるようにする。
-spec spawn_worker(module(),
                   pid(),
                   binary(),
                   undefined | fuzzer_feedback:state(),
                   ets:tid(),
                   on_crash()) -> pid().
spawn_worker(Target, Watchdog, ArtifactDir, FeedbackState, CrashTable, OnCrash) ->
    spawn(fun() ->
                  worker(Target, Watchdog, ArtifactDir, FeedbackState, CrashTable, OnCrash)
          end).


%% タイムアウトした入力を記録し、必要ならワーカーを差し替える。
%%
%% NIF の timeout/4 がワーカーの差し替えとコールバックの継続を同時に行う。
%% 差し替えに成功した場合だけ古いワーカーを kill する。
-spec handle_timeout(module(),
                     binary(),
                     non_neg_integer(),
                     undefined | fuzzer_feedback:state(),
                     ets:tid(),
                     on_crash(),
                     pid(),
                     reference(),
                     non_neg_integer(),
                     binary()) -> pid().
handle_timeout(Target,
               ArtifactDir,
               TimeoutMs,
               FeedbackState,
               CrashTable,
               OnCrash,
               Worker,
               Context,
               Generation,
               Data) ->
    NewWorker = spawn_worker(Target, self(), ArtifactDir, FeedbackState, CrashTable, OnCrash),
    try timeout(Context, Generation, NewWorker, OnCrash) of
        timeout ->
            case OnCrash of
                continue ->
                    % 古いワーカーが計測対象を実行し続けてカウンターを汚さないよう、
                    % レポートを書く前に kill する。
                    exit(Worker, kill),
                    ok = record_crash(CrashTable,
                                      ArtifactDir,
                                      Data,
                                      #{
                                        reason => timeout,
                                        timeout_ms => TimeoutMs
                                       }),
                    NewWorker;
                abort ->
                    % レポートを書いてから NIF のコールバックを起こす。
                    % 先に起こすと、レポートが書かれる前に BEAM が abort する。
                    % レポートの書き込みが失敗しても、コールバックを待たせたままに
                    % しないよう abort_timeout/1 は必ず呼ぶ。
                    ok = stop_worker(NewWorker),
                    try
                        ok = record_crash(CrashTable,
                                          ArtifactDir,
                                          Data,
                                          #{
                                            reason => timeout,
                                            timeout_ms => TimeoutMs
                                           })
                    after
                        ok = abort_timeout(Context)
                    end,
                    Worker
            end;
        ok ->
            ok = stop_worker(NewWorker),
            Worker
    catch
        Class:Reason:Stacktrace ->
            ok = stop_worker(NewWorker),
            logger:error("Failed to handle input timeout: ~p",
                         [{Class, Reason, Stacktrace}]),
            exit({timeout_failure, Reason})
    end.


%% タイムアウト値をミリ秒で受け取り、その時間後に自分へメッセージを送る。
-spec arm_timer(non_neg_integer(), reference(), non_neg_integer(), binary()) ->
          undefined | reference().
arm_timer(0, _Context, _Generation, _Data) ->
    undefined;
arm_timer(TimeoutMs, Context, Generation, Data) ->
    erlang:send_after(TimeoutMs, self(), {timeout, Context, Generation, Data}).


-spec cancel_timer(undefined | reference()) -> ok.
cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    _ = erlang:cancel_timer(Timer),
    ok.


%%%===================================================================
%%% クラッシュレポート
%%%===================================================================


%% クラッシュを重複なく記録し、初めて見る crash_id のときだけ artifact と
%% レポートを書き出す。同じ crash_id の入力が複数回来ても、最初の入力だけを残す。
-spec record_crash(ets:tid(), binary(), binary(), map()) -> ok.
record_crash(CrashTable, ArtifactDir, Data, Report0) ->
    Report = ensure_crash_id(Report0),
    CrashId = maps:get(crash_id, Report),
    case ets:insert_new(CrashTable, {CrashId, Data, Report}) of
        true ->
            write_crash_artifact(ArtifactDir, Data, Report);
        false ->
            ok
    end.


%% レポートに crash_id がなければ付ける。
-spec ensure_crash_id(map()) -> map().
ensure_crash_id(Report) ->
    case maps:is_key(crash_id, Report) of
        true ->
            Report;
        false ->
            Report#{crash_id => fuzzer_crash:id_from_report(Report)}
    end.


%% クラッシュ入力を artifact として書き出し、レポートも書く。
-spec write_crash_artifact(binary(), binary(), map()) -> ok.
write_crash_artifact(ArtifactDir, Data, Report) ->
    Hash = sha1_hex(Data),
    Path = filename:join(ArtifactDir, <<"crash-", Hash/binary>>),
    case file:write_file(Path, Data) of
        ok ->
            ok;
        {error, Reason} ->
            logger:warning("Failed to write a crash artifact: ~p", [Reason])
    end,
    write_crash_report(ArtifactDir, Data, Report).


%% fuzzing 終了時に、重複を除いたクラッシュの一覧を返す。
-spec crash_summary(ets:tid()) -> [map()].
crash_summary(CrashTable) ->
    Crashes =
        [ Report#{input_sha1 => sha1_hex(Data), input_size => byte_size(Data)}
          || {_CrashId, Data, Report} <:- ets:tab2list(CrashTable) ],
    lists:sort(fun(A, B) ->
                       maps:get(input_sha1, A) =< maps:get(input_sha1, B)
               end,
               Crashes).


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
        ensure_crash_id(
          maps:merge(#{input_sha1 => Hash, input_size => byte_size(Data)}, Report)),
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
-spec libfuzzer_version_nif() -> binary().
libfuzzer_version_nif() ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec max_feedback_counters_nif() -> pos_integer().
max_feedback_counters_nif() ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec run_nif(pid(), [binary()], non_neg_integer()) -> integer().
run_nif(_Worker, _Argv, _FeedbackCount) ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec reply(reference(), non_neg_integer(), non_neg_integer() | crash | continue, binary()) ->
          ok.
reply(_Context, _Generation, _Result, _Counters) ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec timeout(reference(), non_neg_integer(), pid(), on_crash()) -> timeout | ok.
timeout(_Context, _Generation, _NewWorker, _OnCrash) ->
    erlang:nif_error(nif_library_not_loaded).


%% NIF 未ロード時のスタブ。実際の実装は c_src/fuzzer_nif.c にある。
-spec abort_timeout(reference()) -> ok.
abort_timeout(_Context) ->
    erlang:nif_error(nif_library_not_loaded).
