-module(rebar3_fuzzer_prv).

-behaviour(provider).

-export([init/1, do/1, format_error/1]).

-define(PROVIDER, fuzzer).
-define(DEPS,     [compile]).


-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider =
        providers:create([{name, ?PROVIDER},
                          {module, ?MODULE},
                          {bare, true},
                          {deps, ?DEPS},
                          {example, "rebar3 fuzzer --target example_fuzz_target"},
                          {opts, opts()},
                          {short_desc, "Run an Erlang fuzz target with libFuzzer"},
                          {desc, "Run an Erlang fuzz target with libFuzzer"}]),
    {ok, rebar_state:add_provider(State, Provider)}.


-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, term()}.
do(State) ->
    maybe
        {ok, Options} ?= parse_options(State),
        ok ?= prepare(State, Options),
        ok ?= run_fuzzer(State, Options),
        {ok, State}
    else
        {error, Reason} ->
            {error, Reason}
    end.


%% 再現モードでは NIF もコーパスも不要なので、fuzzing の準備を省略する。
-spec prepare(rebar_state:t(), map()) -> ok | {error, term()}.
prepare(_State, #{repro := _Path}) ->
    ok;
prepare(State, Options) ->
    maybe
        {ok, FuzzerApp} ?= find_fuzzer_app(State),
        ok ?= ensure_directories(Options),
        ok ?= build_nif(State, FuzzerApp),
        ok
    end.


-spec format_error(term()) -> iolist().
format_error(missing_target) ->
    "Option --target is required";
format_error({invalid_target, Target}) ->
    io_lib:format("Invalid fuzz target module: ~p", [Target]);
format_error({invalid_runs, Runs}) ->
    io_lib:format("Runs must be zero or greater: ~p", [Runs]);
format_error({invalid_max_length, MaxLength}) ->
    io_lib:format("Max length must be greater than zero: ~p", [MaxLength]);
format_error({unexpected_arguments, Arguments}) ->
    io_lib:format("Unexpected arguments: ~p", [Arguments]);
format_error(fuzzer_app_not_found) ->
    "The fuzzer application is not part of this project or its dependencies";
format_error({makefile_not_found, Path}) ->
    io_lib:format("The fuzzer Makefile was not found: ~ts", [Path]);
format_error({directory_error, Path, Reason}) ->
    io_lib:format("Failed to create directory ~ts: ~p", [Path, Reason]);
format_error({nif_build_failed, Status}) ->
    io_lib:format("Failed to build the fuzzer NIF with exit status ~B", [Status]);
format_error(erl_not_found) ->
    "The erl executable was not found";
format_error({fuzzer_exit, Status}) ->
    io_lib:format("The fuzzer process exited with status ~B", [Status]);
format_error({invalid_option, Key, Value}) ->
    io_lib:format("Invalid option ~p: ~p", [Key, Value]);
format_error({invalid_jobs, Jobs}) ->
    io_lib:format("Jobs must be greater than zero, and runs must be positive: ~p", [Jobs]);
format_error({invalid_feedback, Value}) ->
    io_lib:format("Invalid feedback module: ~p", [Value]);
format_error({invalid_feedback_mode, Value}) ->
    io_lib:format("Feedback mode must be line or clause: ~p", [Value]);
format_error({invalid_on_crash, Value}) ->
    io_lib:format("On-crash behavior must be abort or continue: ~p", [Value]);
format_error({invalid_auto_dict, Value}) ->
    io_lib:format("Auto dictionary must be true or false: ~p", [Value]);
format_error({invalid_dict_modules, Value}) ->
    io_lib:format("Invalid dictionary module: ~p", [Value]);
format_error(Reason) ->
    io_lib:format("~p", [Reason]).


-spec opts() -> [tuple()].
opts() ->
    [{target, $t, "target", string, "Fuzz target module"},
     {runs, $r, "runs", integer, "Number of runs, or zero to run continuously"},
     {max_length, $l, "max-length", integer, "Maximum input length in bytes"},
     {corpus, $c, "corpus", string, "Corpus directory"},
     {artifacts, $a, "artifacts", string, "Artifact directory"},
     {dict, $d, "dict", string, "Dictionary file"},
     {timeout, undefined, "timeout", integer, "Per-input timeout in seconds"},
     {max_total_time, undefined, "max-total-time", integer, "Maximum total fuzzing time in seconds"},
     {seed, undefined, "seed", integer, "Random seed"},
     {rss_limit_mb, undefined, "rss-limit-mb", integer, "RSS limit in megabytes"},
     {cover, undefined, "cover", string, "Comma-separated modules to measure coverage"},
     {feedback, undefined, "feedback", string, "Comma-separated modules for coverage feedback"},
     {feedback_mode, undefined, "feedback-mode", string, "Feedback mode: line or clause"},
     {on_crash, undefined, "on-crash", string, "Crash handling: abort or continue"},
     {auto_dict, undefined, "auto-dict", string, "Generate a dictionary from literals: true or false"},
     {dict_modules, undefined, "dict-modules", string, "Comma-separated modules for automatic dictionary generation"},
     {repro, undefined, "repro", string, "Reproduce an artifact file"},
     {jobs, undefined, "jobs", integer, "Number of parallel fuzzing jobs"}].


-spec parse_options(rebar_state:t()) -> {ok, map()} | {error, term()}.
parse_options(State) ->
    case rebar_state:command_parsed_args(State) of
        {Arguments, []} ->
            parse_options(State, Arguments);
        {_Arguments, ExtraArguments} ->
            {error, {unexpected_arguments, ExtraArguments}}
    end.


-spec parse_options(rebar_state:t(), proplists:proplist()) -> {ok, map()} | {error, term()}.
parse_options(State, Arguments) ->
    Config = rebar_state:get(State, fuzzer, []),
    maybe
        {ok, Target} ?= target_value(Arguments, Config),
        ok ?= validate_target(Target),
        parse_mode(State, Arguments, Config, Target)
    end.


%% --repro が指定された場合は再現モード、それ以外は通常の fuzzing として扱う。
-spec parse_mode(rebar_state:t(), proplists:proplist(), proplists:proplist(), string()) ->
          {ok, map()} | {error, term()}.
parse_mode(State, Arguments, Config, Target) ->
    case option_value(repro, Arguments, Config, undefined) of
        undefined ->
            parse_fuzz_options(State, Arguments, Config, Target);
        Path ->
            {ok, #{
                   target => list_to_atom(Target),
                   repro => rebar_utils:to_list(Path)
                  }}
    end.


-spec parse_fuzz_options(rebar_state:t(),
                         proplists:proplist(),
                         proplists:proplist(),
                         string()) ->
          {ok, map()} | {error, term()}.
parse_fuzz_options(State, Arguments, Config, Target) ->
    maybe
        Runs = option_value(runs, Arguments, Config, 0),
        ok ?= validate_runs(Runs),
        MaxLength = option_value(max_length, Arguments, Config, 4096),
        ok ?= validate_max_length(MaxLength),
        Timeout = option_value(timeout, Arguments, Config, undefined),
        ok ?= validate_optional_pos_integer(timeout, Timeout),
        MaxTotalTime = option_value(max_total_time, Arguments, Config, undefined),
        ok ?= validate_optional_non_neg_integer(max_total_time, MaxTotalTime),
        Seed = option_value(seed, Arguments, Config, undefined),
        ok ?= validate_optional_non_neg_integer(seed, Seed),
        RssLimit = option_value(rss_limit_mb, Arguments, Config, undefined),
        ok ?= validate_optional_pos_integer(rss_limit_mb, RssLimit),
        {DefaultCorpus, DefaultArtifacts} = default_directories(State, Target),
        Corpus = option_path(corpus, Arguments, Config, DefaultCorpus, State),
        Artifacts = option_path(artifacts, Arguments, Config, DefaultArtifacts, State),
        Dict = option_absolute_path(option_value(dict, Arguments, Config, undefined), State),
        Cover = cover_value(Arguments, Config),
        Feedback = feedback_value(Arguments, Config),
        ok ?= validate_feedback_modules(Feedback),
        FeedbackMode = feedback_mode_value(Arguments, Config),
        ok ?= validate_feedback_mode(FeedbackMode),
        OnCrash = on_crash_value(Arguments, Config),
        ok ?= validate_on_crash(OnCrash),
        AutoDict = auto_dict_value(Arguments, Config),
        ok ?= validate_auto_dict(AutoDict),
        DictModules = dict_modules_value(Arguments, Config),
        ok ?= validate_dict_modules(DictModules),
        Jobs = option_value(jobs, Arguments, Config, 1),
        ok ?= validate_jobs(Jobs, Runs),
        {ok, #{
               target => list_to_atom(Target),
               runs => Runs,
               max_length => MaxLength,
               corpus => Corpus,
               artifacts => Artifacts,
               dict => Dict,
               timeout => Timeout,
               max_total_time => MaxTotalTime,
               seed => Seed,
               rss_limit_mb => RssLimit,
               cover => Cover,
               feedback => feedback_config(Feedback, FeedbackMode),
               on_crash => OnCrash,
               auto_dict => AutoDict,
               dict_modules => DictModules,
               jobs => Jobs
              }}
    end.


-spec target_value(proplists:proplist(), proplists:proplist()) ->
          {ok, string()} | {error, missing_target | {invalid_target, term()}}.
target_value(Arguments, Config) ->
    case option_value(target, Arguments, Config, undefined) of
        undefined ->
            {error, missing_target};
        Target when is_atom(Target) ->
            {ok, atom_to_list(Target)};
        Target when is_list(Target) ->
            {ok, Target};
        Target ->
            {error, {invalid_target, Target}}
    end.


-spec option_value(atom(), proplists:proplist(), proplists:proplist(), term()) -> term().
option_value(Key, Arguments, Config, Default) ->
    proplists:get_value(Key, Arguments, proplists:get_value(Key, Config, Default)).


-spec option_path(atom(), proplists:proplist(), proplists:proplist(), string(), rebar_state:t()) -> string().
option_path(Key, Arguments, Config, Default, State) ->
    Path = rebar_utils:to_list(option_value(Key, Arguments, Config, Default)),
    filename:absname(Path, rebar_dir:root_dir(State)).


-spec validate_target(string()) -> ok | {error, {invalid_target, string()}}.
validate_target(Target) ->
    case re:run(Target, "^[a-z][a-zA-Z0-9_@]*$", [{capture, none}]) of
        match ->
            ok;
        nomatch ->
            {error, {invalid_target, Target}}
    end.


-spec validate_runs(term()) -> ok | {error, {invalid_runs, term()}}.
validate_runs(Runs) when is_integer(Runs), Runs >= 0 ->
    ok;
validate_runs(Runs) ->
    {error, {invalid_runs, Runs}}.


-spec validate_optional_pos_integer(atom(), term()) -> ok | {error, {invalid_option, atom(), term()}}.
validate_optional_pos_integer(_Key, undefined) ->
    ok;
validate_optional_pos_integer(_Key, Value) when is_integer(Value), Value > 0 ->
    ok;
validate_optional_pos_integer(Key, Value) ->
    {error, {invalid_option, Key, Value}}.


-spec validate_optional_non_neg_integer(atom(), term()) ->
          ok | {error, {invalid_option, atom(), term()}}.
validate_optional_non_neg_integer(_Key, undefined) ->
    ok;
validate_optional_non_neg_integer(_Key, Value) when is_integer(Value), Value >= 0 ->
    ok;
validate_optional_non_neg_integer(Key, Value) ->
    {error, {invalid_option, Key, Value}}.


-spec validate_jobs(term(), term()) -> ok | {error, {invalid_jobs, term()}}.
validate_jobs(Jobs, _Runs) when is_integer(Jobs), Jobs =:= 1 ->
    ok;
validate_jobs(Jobs, Runs)
  when is_integer(Jobs), Jobs > 1, is_integer(Runs), Runs > 0 ->
    ok;
validate_jobs(Jobs, _Runs) ->
    {error, {invalid_jobs, Jobs}}.


-spec validate_max_length(term()) -> ok | {error, {invalid_max_length, term()}}.
validate_max_length(MaxLength) when is_integer(MaxLength), MaxLength > 0 ->
    ok;
validate_max_length(MaxLength) ->
    {error, {invalid_max_length, MaxLength}}.


-spec option_absolute_path(term(), rebar_state:t()) -> undefined | string().
option_absolute_path(undefined, _State) ->
    undefined;
option_absolute_path(Value, State) ->
    filename:absname(rebar_utils:to_list(Value), rebar_dir:root_dir(State)).


-spec cover_value(proplists:proplist(), proplists:proplist()) -> [module()].
cover_value(Arguments, Config) ->
    case option_value(cover, Arguments, Config, undefined) of
        undefined ->
            [];
        Value ->
            [ list_to_atom(string:trim(Module))
              || Module <:- string:split(rebar_utils:to_list(Value), ",", all),
                 string:trim(Module) =/= "" ]
    end.


%% --feedback で指定されたモジュールを解析する。
%%
%% コマンドラインではカンマ区切りの文字列、rebar.config ではモジュールのリストを
%% 受け付ける。空文字列や空リストは「フィードバックなし」を意味する。
-spec feedback_value(proplists:proplist(), proplists:proplist()) -> [module()].
feedback_value(Arguments, Config) ->
    case option_value(feedback, Arguments, Config, undefined) of
        undefined ->
            [];
        Value when is_list(Value) ->
            case io_lib:printable_unicode_list(Value) of
                true ->
                    [ list_to_atom(string:trim(Module))
                      || Module <:- string:split(Value, ",", all),
                         string:trim(Module) =/= "" ];
                false ->
                    [ feedback_module(Module) || Module <:- Value ]
            end;
        Value ->
            [feedback_module(Value)]
    end.


-spec feedback_module(term()) -> module().
feedback_module(Module) when is_atom(Module) ->
    Module;
feedback_module(Module) when is_binary(Module) ->
    try
        binary_to_atom(Module, utf8)
    catch
        error:badarg ->
            Module
    end;
feedback_module(Module) when is_list(Module) ->
    try
        list_to_atom(Module)
    catch
        error:badarg ->
            Module
    end;
feedback_module(Value) ->
    Value.


-spec validate_feedback_modules([module()]) ->
          ok | {error, {invalid_feedback, term()}}.
validate_feedback_modules(Modules) ->
    lists:foldl(fun(_Module, {error, _Reason} = Error) ->
                        Error;
                   (Module, ok) ->
                        validate_feedback_module(Module)
                end,
                ok,
                Modules).


-spec validate_feedback_module(term()) -> ok | {error, {invalid_feedback, term()}}.
validate_feedback_module(Module) when is_atom(Module) ->
    Name = atom_to_list(Module),
    case re:run(Name, "^[a-z][a-zA-Z0-9_@]*$", [{capture, none}]) of
        match ->
            ok;
        nomatch ->
            {error, {invalid_feedback, Module}}
    end;
validate_feedback_module(Value) ->
    {error, {invalid_feedback, Value}}.


%% --feedback-mode の値を line / clause のいずれかへ正規化する。
-spec feedback_mode_value(proplists:proplist(), proplists:proplist()) ->
          line | clause | {error, {invalid_feedback_mode, term()}}.
feedback_mode_value(Arguments, Config) ->
    case option_value(feedback_mode, Arguments, Config, line) of
        line ->
            line;
        clause ->
            clause;
        Value when is_list(Value) ->
            feedback_mode_string(string:lowercase(string:trim(Value)));
        Value when is_binary(Value) ->
            feedback_mode_string(string:lowercase(binary_to_list(Value)));
        Value ->
            {error, {invalid_feedback_mode, Value}}
    end.


-spec feedback_mode_string(string()) ->
          line | clause | {error, {invalid_feedback_mode, string()}}.
feedback_mode_string("line") ->
    line;
feedback_mode_string("clause") ->
    clause;
feedback_mode_string(Value) ->
    {error, {invalid_feedback_mode, Value}}.


-spec validate_feedback_mode(line | clause | {error, term()}) ->
          ok | {error, term()}.
validate_feedback_mode(line) ->
    ok;
validate_feedback_mode(clause) ->
    ok;
validate_feedback_mode({error, _Reason} = Error) ->
    Error.


%% --auto-dict の値を真偽値へ正規化する。
-spec auto_dict_value(proplists:proplist(), proplists:proplist()) ->
          boolean() | {error, {invalid_auto_dict, term()}}.
auto_dict_value(Arguments, Config) ->
    case option_value(auto_dict, Arguments, Config, true) of
        true ->
            true;
        false ->
            false;
        Value when is_list(Value) ->
            auto_dict_string(string:lowercase(string:trim(Value)));
        Value when is_binary(Value) ->
            auto_dict_string(string:lowercase(binary_to_list(Value)));
        Value ->
            {error, {invalid_auto_dict, Value}}
    end.


-spec auto_dict_string(string()) -> boolean() | {error, {invalid_auto_dict, string()}}.
auto_dict_string("true") ->
    true;
auto_dict_string("false") ->
    false;
auto_dict_string(Value) ->
    {error, {invalid_auto_dict, Value}}.


-spec validate_auto_dict(boolean() | {error, term()}) -> ok | {error, term()}.
validate_auto_dict(true) ->
    ok;
validate_auto_dict(false) ->
    ok;
validate_auto_dict({error, _Reason} = Error) ->
    Error.


%% --dict-modules で指定されたモジュールを解析する。
%%
%% コマンドラインではカンマ区切りの文字列、rebar.config ではモジュールのリストを
%% 受け付ける。空文字列や空リストは「target と feedback から生成する」を意味する。
-spec dict_modules_value(proplists:proplist(), proplists:proplist()) -> [module()].
dict_modules_value(Arguments, Config) ->
    case option_value(dict_modules, Arguments, Config, undefined) of
        undefined ->
            [];
        Value when is_list(Value) ->
            case io_lib:printable_unicode_list(Value) of
                true ->
                    [ list_to_atom(string:trim(Module))
                      || Module <:- string:split(Value, ",", all),
                         string:trim(Module) =/= "" ];
                false ->
                    [ feedback_module(Module) || Module <:- Value ]
            end;
        Value ->
            [feedback_module(Value)]
    end.


-spec validate_dict_modules([module()]) ->
          ok | {error, {invalid_dict_modules, term()}}.
validate_dict_modules(Modules) ->
    lists:foldl(fun(_Module, {error, _Reason} = Error) ->
                        Error;
                   (Module, ok) ->
                        validate_dict_module(Module)
                end,
                ok,
                Modules).


-spec validate_dict_module(term()) -> ok | {error, {invalid_dict_modules, term()}}.
validate_dict_module(Module) when is_atom(Module) ->
    Name = atom_to_list(Module),
    case re:run(Name, "^[a-z][a-zA-Z0-9_@]*$", [{capture, none}]) of
        match ->
            ok;
        nomatch ->
            {error, {invalid_dict_modules, Module}}
    end;
validate_dict_module(Value) ->
    {error, {invalid_dict_modules, Value}}.


%% --on-crash の値を abort / continue へ正規化する。
-spec on_crash_value(proplists:proplist(), proplists:proplist()) ->
          abort | continue | {error, {invalid_on_crash, term()}}.
on_crash_value(Arguments, Config) ->
    case option_value(on_crash, Arguments, Config, abort) of
        abort ->
            abort;
        continue ->
            continue;
        Value when is_list(Value) ->
            on_crash_string(string:lowercase(string:trim(Value)));
        Value when is_binary(Value) ->
            on_crash_string(string:lowercase(binary_to_list(Value)));
        Value ->
            {error, {invalid_on_crash, Value}}
    end.


-spec on_crash_string(string()) ->
          abort | continue | {error, {invalid_on_crash, string()}}.
on_crash_string("abort") ->
    abort;
on_crash_string("continue") ->
    continue;
on_crash_string(Value) ->
    {error, {invalid_on_crash, Value}}.


-spec validate_on_crash(abort | continue | {error, term()}) -> ok | {error, term()}.
validate_on_crash(abort) ->
    ok;
validate_on_crash(continue) ->
    ok;
validate_on_crash({error, _Reason} = Error) ->
    Error.


%% rebar3 から fuzzer:run/1 へ渡す feedback オプションを組み立てる。
%%
%% モジュールが指定されていない場合は、fuzzer 側の既定値と同じ空リストにする。
-spec feedback_config([module()], line | clause) ->
          [] | #{modules := [module()], mode := line | clause}.
feedback_config([], _Mode) ->
    [];
feedback_config(Modules, Mode) ->
    #{modules => Modules, mode => Mode}.


-spec default_directories(rebar_state:t(), string()) -> {string(), string()}.
default_directories(State, Target) ->
    RootDir = rebar_dir:root_dir(State),
    BaseDir = filename:absname(rebar_dir:base_dir(State), RootDir),
    TargetDir = filename:join([filename:dirname(BaseDir), "fuzz", Target]),
    {filename:join(TargetDir, "corpus"), filename:join(TargetDir, "artifacts")}.


-spec find_fuzzer_app(rebar_state:t()) -> {ok, rebar_app_info:t()} | {error, fuzzer_app_not_found}.
find_fuzzer_app(State) ->
    Apps = rebar_state:project_apps(State) ++ rebar_state:all_deps(State),
    case lists:search(fun(App) -> rebar_app_info:name(App) =:= <<"fuzzer">> end, Apps) of
        {value, App} ->
            {ok, App};
        false ->
            {error, fuzzer_app_not_found}
    end.


-spec ensure_directories(map()) -> ok | {error, term()}.
ensure_directories(#{corpus := Corpus, artifacts := Artifacts}) ->
    maybe
        ok ?= ensure_directory(Corpus),
        ok ?= ensure_directory(Artifacts),
        ok
    end.


-spec ensure_directory(string()) -> ok | {error, {directory_error, string(), term()}}.
ensure_directory(Path) ->
    case filelib:ensure_dir(filename:join(Path, ".keep")) of
        ok ->
            ok;
        {error, Reason} ->
            {error, {directory_error, Path, Reason}}
    end.


-spec build_nif(rebar_state:t(), rebar_app_info:t()) -> ok | {error, term()}.
build_nif(State, FuzzerApp) ->
    RootDir = rebar_dir:root_dir(State),
    SourceDir = filename:absname(rebar_app_info:dir(FuzzerApp), RootDir),
    OutDir = filename:absname(rebar_app_info:out_dir(FuzzerApp), RootDir),
    Makefile = filename:join(SourceDir, "Makefile"),
    case filelib:is_regular(Makefile) of
        true ->
            NifPath = filename:join([OutDir, "priv", "fuzzer_nif.so"]),
            maybe
                ok ?= ensure_directory(filename:dirname(NifPath)),
                ok ?= run_make(SourceDir, NifPath),
                ok
            end;
        false ->
            {error, {makefile_not_found, Makefile}}
    end.


-spec run_make(string(), string()) -> ok | {error, {nif_build_failed, integer()}}.
run_make(SourceDir, NifPath) ->
    Command = "make nif NIF=" ++ rebar_utils:escape_chars(NifPath),
    case rebar_utils:sh(Command, [{cd, SourceDir}, use_stdout, return_on_error]) of
        {ok, _Output} ->
            ok;
        {error, {Status, _Output}} ->
            {error, {nif_build_failed, Status}}
    end.


-spec run_fuzzer(rebar_state:t(), map()) -> ok | {error, term()}.
run_fuzzer(State, Options) ->
    case maps:get(jobs, Options, 1) of
        1 ->
            run_single(State, maps:remove(jobs, Options));
        Jobs ->
            run_jobs(State, Options, Jobs)
    end.


%% 1 ジョブの場合は従来どおり 1 個の erl を起動する。
-spec run_single(rebar_state:t(), map()) -> ok | {error, term()}.
run_single(State, Options) ->
    case os:find_executable("erl") of
        false ->
            {error, erl_not_found};
        Erl ->
            run_command(Erl, code_paths(State), Options, rebar_dir:root_dir(State))
    end.


%% 複数ジョブを並列実行し、終了後にコーパスと artifact をマージする。
-spec run_jobs(rebar_state:t(), map(), pos_integer()) -> ok | {error, term()}.
run_jobs(State, Options, Jobs) ->
    case os:find_executable("erl") of
        false ->
            {error, erl_not_found};
        Erl ->
            maybe
                RootDir = rebar_dir:root_dir(State),
                {ok, JobDirs} ?= prepare_jobs(Options, Jobs),
                Results =
                    run_jobs_parallel(Erl, code_paths(State), Options, JobDirs, RootDir),
                ok ?= merge_jobs(Options, JobDirs),
                case lists:search(fun({_Index, Status}) -> Status =/= 0 end,
                                  Results) of
                    {value, {_Index, Status}} ->
                        {error, {fuzzer_exit, Status}};
                    false ->
                        ok
                end
            end
    end.


%% ジョブごとのコーパスと artifact ディレクトリーを用意し、シードを複製する。
-spec prepare_jobs(map(), pos_integer()) ->
          {ok, [{pos_integer(), string(), string()}]} | {error, term()}.
prepare_jobs(Options, Jobs) ->
    BaseCorpus = maps:get(corpus, Options),
    BaseArtifacts = maps:get(artifacts, Options),
    prepare_jobs(BaseCorpus, BaseArtifacts, lists:seq(1, Jobs), []).


-spec prepare_jobs(string(), string(), [pos_integer()], [{pos_integer(), string(), string()}]) ->
          {ok, [{pos_integer(), string(), string()}]} | {error, term()}.
prepare_jobs(_BaseCorpus, _BaseArtifacts, [], Acc) ->
    {ok, lists:reverse(Acc)};
prepare_jobs(BaseCorpus, BaseArtifacts, [Index | Rest], Acc) ->
    Name = "job-" ++ integer_to_list(Index),
    JobCorpus = filename:join(BaseCorpus, Name),
    JobArtifacts = filename:join(BaseArtifacts, Name),
    maybe
        ok ?= ensure_directory(JobCorpus),
        ok ?= ensure_directory(JobArtifacts),
        ok ?= copy_seed_corpus(BaseCorpus, JobCorpus),
        prepare_jobs(BaseCorpus,
                     BaseArtifacts,
                     Rest,
                     [{Index, JobCorpus, JobArtifacts} | Acc])
    end.


%% ベースコーパスの通常ファイルだけをジョブコーパスへ複製する。
-spec copy_seed_corpus(string(), string()) -> ok | {error, term()}.
copy_seed_corpus(BaseCorpus, JobCorpus) ->
    case file:list_dir(BaseCorpus) of
        {ok, Files} ->
            copy_seed_files(Files, BaseCorpus, JobCorpus);
        {error, enoent} ->
            ok;
        {error, Reason} ->
            {error, {directory_error, BaseCorpus, Reason}}
    end.


-spec copy_seed_files([string()], string(), string()) -> ok | {error, term()}.
copy_seed_files([], _BaseCorpus, _JobCorpus) ->
    ok;
copy_seed_files([File | Rest], BaseCorpus, JobCorpus) ->
    maybe
        ok ?= copy_file_if_regular(filename:join(BaseCorpus, File),
                                   filename:join(JobCorpus, File)),
        copy_seed_files(Rest, BaseCorpus, JobCorpus)
    end.


%% コピー元が通常ファイルのときだけ、コピー先に存在しない場合に複製する。
-spec copy_file_if_regular(string(), string()) -> ok | {error, term()}.
copy_file_if_regular(Source, Destination) ->
    case filelib:is_regular(Source) of
        true ->
            copy_file_if_absent(Source, Destination);
        false ->
            ok
    end.


-spec copy_file_if_absent(string(), string()) -> ok | {error, term()}.
copy_file_if_absent(Source, Destination) ->
    case filelib:is_regular(Destination) of
        true ->
            ok;
        false ->
            copy_new_file(Source, Destination)
    end.


-spec copy_new_file(string(), string()) -> ok | {error, term()}.
copy_new_file(Source, Destination) ->
    case file:copy(Source, Destination) of
        {ok, _Bytes} ->
            ok;
        {error, eexist} ->
            ok;
        {error, Reason} ->
            {error, {copy_error, Source, Destination, Reason}}
    end.


-spec run_jobs_parallel(string(),
                        [string()],
                        map(),
                        [{pos_integer(), string(), string()}],
                        string()) ->
          [{pos_integer(), integer()}].
run_jobs_parallel(Erl, CodePaths, Options, JobDirs, RootDir) ->
    Parent = self(),
    Workers =
        [ spawn(fun() ->
                        JobOptions =
                            maps:remove(jobs,
                                        Options#{
                                          corpus => JobCorpus,
                                          artifacts => JobArtifacts
                                         }),
                        Result =
                            try
                                run_command(Erl, CodePaths, JobOptions, RootDir)
                            catch
                                _:_ ->
                                    {error, job_crashed}
                            end,
                        Parent ! {job_done, Index, Result}
                end)
          || {Index, JobCorpus, JobArtifacts} <:- JobDirs ],
    [ receive
          {job_done, Index, Result} ->
              {Index, job_status(Result)}
      after
          3600000 ->
              {Index, 1}
      end
      || {Index, _Pid} <:- lists:zip([ I || {I, _C, _A} <:- JobDirs ], Workers) ].


-spec job_status(ok | {error, term()}) -> integer().
job_status(ok) ->
    0;
job_status({error, {fuzzer_exit, Status}}) ->
    Status;
job_status({error, _Reason}) ->
    1.


%% ジョブのコーパスと artifact をベースディレクトリーへマージする。
-spec merge_jobs(map(), [{pos_integer(), string(), string()}]) -> ok | {error, term()}.
merge_jobs(Options, JobDirs) ->
    BaseCorpus = maps:get(corpus, Options),
    BaseArtifacts = maps:get(artifacts, Options),
    maybe
        ok ?= merge_directories(BaseCorpus, [ C || {_I, C, _A} <:- JobDirs ]),
        ok ?= merge_directories(BaseArtifacts, [ A || {_I, _C, A} <:- JobDirs ]),
        ok
    end.


-spec merge_directories(string(), [string()]) -> ok | {error, term()}.
merge_directories(_Destination, []) ->
    ok;
merge_directories(Destination, [Source | Rest]) ->
    maybe
        ok ?= merge_directory(Destination, Source),
        merge_directories(Destination, Rest)
    end.


-spec merge_directory(string(), string()) -> ok | {error, term()}.
merge_directory(Destination, Source) ->
    case file:list_dir(Source) of
        {ok, Files} ->
            copy_files(Files, Source, Destination);
        {error, enoent} ->
            ok;
        {error, Reason} ->
            {error, {directory_error, Source, Reason}}
    end.


-spec copy_files([string()], string(), string()) -> ok | {error, term()}.
copy_files([], _Source, _Destination) ->
    ok;
copy_files([File | Rest], SourceDir, DestinationDir) ->
    maybe
        ok ?= copy_file_if_regular(filename:join(SourceDir, File),
                                   filename:join(DestinationDir, File)),
        copy_files(Rest, SourceDir, DestinationDir)
    end.


-spec run_command(string(), [string()], map(), string()) -> ok | {error, term()}.
run_command(Erl, CodePaths, Options, RootDir) ->
    Command = fuzzer_command(Erl, CodePaths, Options),
    case rebar_utils:sh(Command,
                        [{cd, RootDir}, use_stdout, return_on_error]) of
        {ok, _Output} ->
            ok;
        {error, {Status, _Output}} ->
            {error, {fuzzer_exit, Status}}
    end.


-spec code_paths(rebar_state:t()) -> [string()].
code_paths(State) ->
    RootDir = rebar_dir:root_dir(State),
    Apps = rebar_state:project_apps(State) ++ rebar_state:all_deps(State),
    lists:usort([ filename:absname(rebar_app_info:ebin_dir(App), RootDir) || App <:- Apps ]).


-spec fuzzer_command(string(), [string()], map()) -> string().
fuzzer_command(Erl, CodePaths, Options) ->
    Eval = fuzzer_eval(Options),
    Arguments = [Erl, "-noshell"] ++
        lists:append([ ["-pa", Path] || Path <:- CodePaths ]) ++
        ["-eval", Eval],
    lists:flatten(lists:join(" ", [ rebar_utils:escape_chars(Argument) || Argument <:- Arguments ])).


-spec fuzzer_eval(map()) -> string().
fuzzer_eval(#{repro := Path, target := Target}) ->
    Encoded = base64:encode(term_to_binary({Target, Path})),
    lists:flatten(io_lib:format("fuzzer_cli:reproduce(<<\"~ts\">>).", [Encoded]));
fuzzer_eval(Options) ->
    Encoded = base64:encode(term_to_binary(Options)),
    lists:flatten(io_lib:format("fuzzer_cli:run(<<\"~ts\">>).", [Encoded])).


-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").


validate_target_test_() ->
    [?_assertEqual(ok, validate_target("example_fuzz_target")),
     ?_assertMatch({error, {invalid_target, _}}, validate_target("Example")),
     ?_assertMatch({error, {invalid_target, _}}, validate_target("../example"))].


validate_runs_test_() ->
    [?_assertEqual(ok, validate_runs(0)),
     ?_assertEqual(ok, validate_runs(1000)),
     ?_assertEqual({error, {invalid_runs, -1}}, validate_runs(-1))].


validate_max_length_test_() ->
    [?_assertEqual(ok, validate_max_length(1)),
     ?_assertEqual({error, {invalid_max_length, 0}}, validate_max_length(0))].


validate_jobs_test_() ->
    [?_assertEqual(ok, validate_jobs(1, 0)),
     ?_assertEqual(ok, validate_jobs(2, 100)),
     ?_assertMatch({error, {invalid_jobs, 2}}, validate_jobs(2, 0)),
     ?_assertMatch({error, {invalid_jobs, 0}}, validate_jobs(0, 100))].


validate_optional_pos_integer_test_() ->
    [?_assertEqual(ok, validate_optional_pos_integer(timeout, undefined)),
     ?_assertEqual(ok, validate_optional_pos_integer(timeout, 1)),
     ?_assertMatch({error, {invalid_option, timeout, _}},
                   validate_optional_pos_integer(timeout, 0))].


validate_optional_non_neg_integer_test_() ->
    [?_assertEqual(ok, validate_optional_non_neg_integer(seed, undefined)),
     ?_assertEqual(ok, validate_optional_non_neg_integer(seed, 0)),
     ?_assertMatch({error, {invalid_option, seed, _}},
                   validate_optional_non_neg_integer(seed, -1))].


cover_value_test_() ->
    [?_assertEqual([], cover_value([], [])),
     ?_assertEqual([], cover_value([], [{cover, ""}])),
     ?_assertEqual([rtp, sdp], cover_value([], [{cover, "rtp, sdp"}]))].


feedback_value_test_() ->
    [?_assertEqual([], feedback_value([], [])),
     ?_assertEqual([], feedback_value([], [{feedback, ""}])),
     ?_assertEqual([rtp, sdp], feedback_value([], [{feedback, "rtp, sdp"}])),
     ?_assertEqual([rtp, sdp], feedback_value([], [{feedback, [rtp, sdp]}])),
     ?_assertEqual([rtp], feedback_value([{feedback, "rtp"}], []))].


validate_feedback_modules_test_() ->
    [?_assertEqual(ok, validate_feedback_modules([rtp, sdp])),
     ?_assertMatch({error, {invalid_feedback, _}},
                   validate_feedback_modules(["Bad"])),
     ?_assertMatch({error, {invalid_feedback, _}},
                   validate_feedback_modules([123]))].


feedback_mode_value_test_() ->
    [?_assertEqual(line, feedback_mode_value([], [])),
     ?_assertEqual(clause, feedback_mode_value([], [{feedback_mode, clause}])),
     ?_assertEqual(clause, feedback_mode_value([{feedback_mode, "CLAUSE"}], [])),
     ?_assertMatch({error, {invalid_feedback_mode, _}},
                   feedback_mode_value([], [{feedback_mode, invalid}]))].


feedback_config_test_() ->
    [?_assertEqual([], feedback_config([], line)),
     ?_assertEqual(#{modules => [rtp], mode => clause},
                   feedback_config([rtp], clause))].


on_crash_value_test_() ->
    [?_assertEqual(abort, on_crash_value([], [])),
     ?_assertEqual(continue, on_crash_value([{on_crash, "CONTINUE"}], [])),
     ?_assertEqual(continue, on_crash_value([], [{on_crash, continue}])),
     ?_assertMatch({error, {invalid_on_crash, _}},
                   on_crash_value([], [{on_crash, invalid}]))].


auto_dict_value_test_() ->
    [?_assertEqual(true, auto_dict_value([], [])),
     ?_assertEqual(false, auto_dict_value([{auto_dict, "FALSE"}], [])),
     ?_assertEqual(false, auto_dict_value([], [{auto_dict, false}])),
     ?_assertMatch({error, {invalid_auto_dict, _}},
                   auto_dict_value([], [{auto_dict, invalid}]))].


dict_modules_value_test_() ->
    [?_assertEqual([], dict_modules_value([], [])),
     ?_assertEqual([], dict_modules_value([], [{dict_modules, ""}])),
     ?_assertEqual([parser, sdp],
                   dict_modules_value([], [{dict_modules, "parser, sdp"}])),
     ?_assertEqual([parser, sdp],
                   dict_modules_value([], [{dict_modules, [parser, sdp]}])),
     ?_assertEqual([], dict_modules_value([], [{dict_modules, undefined}]))].


validate_dict_modules_test_() ->
    [?_assertEqual(ok, validate_dict_modules([])),
     ?_assertEqual(ok, validate_dict_modules([parser, sdp])),
     ?_assertMatch({error, {invalid_dict_modules, _}},
                   validate_dict_modules([<<"parser">>])),
     ?_assertMatch({error, {invalid_dict_modules, _}},
                   validate_dict_modules(["parser"]))].


fuzzer_eval_test() ->
    Options =
        #{
          target => example_fuzz_target,
          runs => 1,
          max_length => 2,
          corpus => "/tmp/corpus",
          artifacts => "/tmp/artifacts",
          dict => undefined,
          timeout => undefined,
          max_total_time => undefined,
          seed => undefined,
          rss_limit_mb => undefined,
          cover => []
         },
    Eval = fuzzer_eval(Options),
    {ok, Tokens, _EndLocation} = erl_scan:string(Eval),
    {ok, _Expressions} = erl_parse:parse_exprs(Tokens).


fuzzer_eval_repro_test() ->
    Eval =
        fuzzer_eval(#{
                      target => example_fuzz_target,
                      repro => "/tmp/example/crash-artifact"
                     }),
    {ok, Tokens, _EndLocation} = erl_scan:string(Eval),
    {ok, _Expressions} = erl_parse:parse_exprs(Tokens).


-endif.
