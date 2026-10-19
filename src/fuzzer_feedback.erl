%% libFuzzer へ渡す Erlang コードのフィードバックカバレッジ。
%%
%% feedback オプションで指定したモジュールを、計測用にコンパイルし直して
%% ロードする。入力の評価が終わるたびにカウンターを読み出し、1 バイトずつの
%% カウンター列として NIF へ渡す。NIF はその列を libFuzzer のカウンターへ
%% コピーするため、行や節の到達がそのまま libFuzzer の feature になる。
%%
%% モード:
%%   line   - OTP の native coverage (line_counters) を使う。行単位。
%%   clause - parse transform で全節の本体先頭に計測呼び出しを挿入する。節単位。
%%
%% モジュールを計測用にロードし直すため、fuzzing 中は対象モジュールを
%% リロードしないこと。run/1 の終了時には元のコードへ戻す。
-module(fuzzer_feedback).

-export([setup/1,
         teardown/1,
         reset/1,
         read/1, read/2,
         counter_count/1]).

%% セットアップ中に登録した後始末を保持するプロセス辞書のキー。
-define(CLEANUPS_KEY, {?MODULE, cleanups}).
%% 同時に feedback をセットアップしないための global ロックのリソース ID。
-define(LOCK_ID, ?MODULE).

-type mode() :: line | clause.
-type config() ::
        #{
          modules := [module()],
          mode := mode()
         }.
-type original() ::
        {loaded, binary(), file:filename_all()} | not_loaded.
-type state() ::
        #{
          line := [{module(), non_neg_integer()}],
          clause_ref := undefined | reference(),
          clause_count := non_neg_integer(),
          total := non_neg_integer(),
          cleanups := [fun(() -> ok)]
         }.

-export_type([mode/0, state/0]).


%% フィードバック計測の準備を行う。
%%
%% モジュールを 1 つも指定していない場合は undefined を返す。成功した場合は
%% teardown/1 に渡す状態を返す。失敗した場合は、それまでにロードしたモジュール
%% や変更した coverage mode を元へ戻してから例外を送出する。
-spec setup(config()) -> undefined | state().
setup(#{modules := []}) ->
    undefined;
setup(#{modules := Modules, mode := Mode}) ->
    ok = validate_mode(Mode),
    ok = ensure_supported(Mode),
    ok = acquire_lock(),
    put(?CLEANUPS_KEY, []),
    try
        add_cleanup(fun release_lock/0),
        Originals = capture_originals(Modules),
        lists:foreach(fun({Module, Original}) ->
                              add_cleanup(fun() -> restore_original(Module, Original) end)
                      end,
                      Originals),
        {Compiled, ClauseCount} = compile_modules(Modules, Mode),
        OldCoverageMode = set_coverage_mode(Mode),
        add_cleanup(fun() -> restore_coverage_mode(OldCoverageMode) end),
        {ok, ClauseRef} = fuzzer_coverage:init(ClauseCount),
        add_cleanup(fun() -> fuzzer_coverage:stop() end),
        ok = load_modules(Compiled),
        LineModules = line_modules(Compiled, Mode),
        Total = line_counter_count(LineModules) + ClauseCount,
        MaxCounters = fuzzer:max_feedback_counters(),
        ok = validate_counter_count(Total, MaxCounters),
        #{
          line => LineModules,
          clause_ref => ClauseRef,
          clause_count => ClauseCount,
          total => Total,
          cleanups => get(?CLEANUPS_KEY)
         }
    catch
        Class:Reason:Stacktrace ->
            run_cleanups(get(?CLEANUPS_KEY)),
            erlang:raise(Class, Reason, Stacktrace)
    after
        erase(?CLEANUPS_KEY)
    end.


%% 計測用にロードしたモジュールと coverage mode を元へ戻す。
-spec teardown(undefined | state()) -> ok.
teardown(undefined) ->
    ok;
teardown(#{cleanups := Cleanups}) ->
    run_cleanups(Cleanups).


%% fuzz target の reset/0 が実行した分を除外するため、カウンターを 0 に戻す。
-spec reset(state()) -> ok.
reset(State) ->
    ok = reset_line_counters(State),
    fuzzer_coverage:reset().


-spec reset_line_counters(state()) -> ok.
reset_line_counters(State) ->
    lists:foreach(fun({Module, _Count}) ->
                          case code:reset_coverage(Module) of
                              ok ->
                                  ok;
                              Other ->
                                  erlang:error({feedback,
                                                {reset_failed, Module, Other}})
                          end
                  end,
                  maps:get(line, State)).


%% 1 入力分のカウンターを読み出し、1 バイトずつのバイナリーにする。
%%
%% 行カウンターは 255 で飽和させる。libFuzzer はカウンターを 1, 2, 3, 4-7, ...
%% の段階に分けて feature にするため、これ以上の精度は探索に寄与しない。
-spec read(state()) -> binary().
read(State) ->
    read(State, true).


%% 1 入力分のカウンターを読み出す。
%%
%% ResetLine が true の場合、読み出し後に行カウンターを 0 に戻す。
%% target が reset/0 を持たない場合は true にして、次の入力の評価前に
%% 改めてリセットする処理を省略する。reset/0 を持つ場合は false にし、
%% reset/0 の実行後に行カウンターを 0 に戻す。
-spec read(state(), boolean()) -> binary().
read(State, ResetLine) ->
    LineBytes =
        [ read_line_counters(Module, Count)
          || {Module, Count} <:- maps:get(line, State) ],
    ClauseCounters =
        fuzzer_coverage:read_and_reset(maps:get(clause_ref, State),
                                       maps:get(clause_count, State)),
    ClauseBytes = [ min(Count, 255) || Count <:- ClauseCounters ],
    Counters = iolist_to_binary([LineBytes, ClauseBytes]),
    case ResetLine of
        true ->
            ok = reset_line_counters(State);
        false ->
            ok
    end,
    Counters.


%% この実行で NIF に登録するカウンターの総数を返す。
-spec counter_count(state()) -> non_neg_integer().
counter_count(State) ->
    maps:get(total, State).


%% native coverage を使うモードでは、実行環境が対応しているか確認する。
-spec ensure_supported(mode()) -> ok.
ensure_supported(clause) ->
    ok;
ensure_supported(_Mode) ->
    case code:coverage_support() of
        true ->
            ok;
        false ->
            erlang:error({feedback, native_coverage_unsupported})
    end.


%% 同じ BEAM で feedback のセットアップが同時に走らないようにする。
%%
%% モジュールのロードと coverage mode の変更はプロセスをまたいで共有されるため、
%% NIF の busy 検査より前に直列化する必要がある。ロックはプロセスが終了すると
%% global が自動的に解放する。
-spec acquire_lock() -> ok.
acquire_lock() ->
    case global:set_lock({?LOCK_ID, self()}, [node()], 0) of
        true ->
            ok;
        false ->
            erlang:error({feedback, already_running})
    end.


-spec release_lock() -> ok.
release_lock() ->
    _ = global:del_lock({?LOCK_ID, self()}, [node()]),
    ok.


%% 計測対象モジュールの元のコードを、ロード前に控える。
-spec capture_originals([module()]) -> [{module(), original()}].
capture_originals(Modules) ->
    [ {Module, capture_original(Module)} || Module <:- Modules ].


-spec capture_original(module()) -> original().
capture_original(Module) ->
    case code:get_object_code(Module) of
        {Module, Binary, Filename} ->
            {loaded, Binary, Filename};
        error ->
            not_loaded
    end.


%% 全モジュールを計測用にコンパイルする。
%%
%% コンパイルはすべてのモジュールについて先に済ませ、その後でまとめてロードする。
%% これにより、on_load が別の計測対象モジュールを呼んだ場合でも、計測用コードと
%% 元のコードが混ざった状態でロードされることを避ける。
-spec compile_modules([module()], mode()) ->
          {[{module(), file:filename_all(), binary()}], non_neg_integer()}.
compile_modules(Modules, Mode) ->
    {Compiled, ClauseCount} =
        lists:foldl(fun(Module, {Acc, Base}) ->
                            {Beam, Binary, Count} = compile_module(Module, Mode, Base),
                            {[{Module, Beam, Binary} | Acc], Base + Count}
                    end,
                    {[], 0},
                    Modules),
    {lists:reverse(Compiled), ClauseCount}.


-spec compile_module(module(), mode(), non_neg_integer()) ->
          {file:filename_all(), binary(), non_neg_integer()}.
compile_module(Module, Mode, Base) ->
    Beam = beam_path(Module),
    Forms = abstract_forms(Module, Beam),
    {Forms2, ClauseCount} = instrument_forms(Forms, Mode, Base),
    case compile:forms(Forms2, compile_options(Mode, Beam)) of
        {ok, Module, Binary} ->
            {Beam, Binary, ClauseCount};
        {ok, Module, Binary, _Warnings} ->
            {Beam, Binary, ClauseCount};
        {error, Errors, Warnings} ->
            erlang:error({feedback,
                          {compile_failed, Module, Errors, Warnings}})
    end.


%% clause モードのときだけ abstract code へ計測呼び出しを挿入する。
-spec instrument_forms([term()], mode(), non_neg_integer()) ->
          {[term()], non_neg_integer()}.
instrument_forms(Forms, line, _Base) ->
    {Forms, 0};
instrument_forms(Forms, clause, Base) ->
    fuzzer_coverage:instrument(Forms, Base).


%% line モードでは行カウンターを有効にするため line_coverage を付ける。
%%
%% 元の beam の compile_info から、コードの意味を変えるオプションだけを引き継ぐ。
%% export_all や tuple_calls を落とすと、再コンパイル後のモジュールで
%% 元は公開されていた関数が非公開になり、target が undef でクラッシュする。
-spec compile_options(mode(), file:filename_all()) -> [compile:option()].
compile_options(line, Beam) ->
    common_compile_options() ++ [line_coverage] ++ preserved_compile_options(Beam);
compile_options(clause, Beam) ->
    common_compile_options() ++ preserved_compile_options(Beam).


-spec common_compile_options() -> [compile:option()].
common_compile_options() ->
    [binary, debug_info, return_errors, return_warnings].


%% 元の beam の compile_info から、abstract code の再コンパイルに必要な
%% オプションを取り出す。include パスとマクロ定義は abstract code の時点で
%% 展開済みなので引き継がない。
-spec preserved_compile_options(file:filename_all()) -> [compile:option()].
preserved_compile_options(Beam) ->
    case beam_lib:chunks(Beam, [compile_info]) of
        {ok, {_Module, [{compile_info, CompileInfo}]}} ->
            case lists:keyfind(options, 1, CompileInfo) of
                {options, Options} when is_list(Options) ->
                    [ Option
                      || Option <:- Options,
                         keep_compile_option(Option) ];
                _ ->
                    []
            end;
        _ ->
            []
    end.


-spec keep_compile_option(term()) -> boolean().
keep_compile_option(export_all) ->
    true;
keep_compile_option(tuple_calls) ->
    true;
keep_compile_option({feature, _Feature, enable}) ->
    true;
keep_compile_option({feature, _Feature, disable}) ->
    true;
keep_compile_option(_Option) ->
    false.


%% モジュールの beam ファイルの場所を返す。
-spec beam_path(module()) -> file:filename_all().
beam_path(Module) ->
    case code:which(Module) of
        Path when is_list(Path), Path =/= [] ->
            case filelib:is_regular(Path) of
                true ->
                    Path;
                false ->
                    erlang:error({feedback, {beam_not_found, Module, Path}})
            end;
        Path when is_binary(Path) ->
            case filelib:is_regular(Path) of
                true ->
                    Path;
                false ->
                    erlang:error({feedback, {beam_not_found, Module, Path}})
            end;
        Other ->
            erlang:error({feedback, {module_not_found, Module, Other}})
    end.


%% beam ファイルから abstract code を取り出す。
%%
%% debug_info がないモジュールは再コンパイルできないため、明確に失敗させる。
-spec abstract_forms(module(), file:filename_all()) -> [term()].
abstract_forms(Module, Beam) ->
    case beam_lib:chunks(Beam, [abstract_code]) of
        {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} ->
            Forms;
        {ok, {Module, [{abstract_code, no_abstract_code}]}} ->
            erlang:error({feedback, {no_debug_info, Module}});
        {ok, {Module, [{abstract_code, {debug_info_v1, _Backend, _Data}}]}} ->
            erlang:error({feedback, {unsupported_debug_info, Module}});
        {ok, {Module, [{abstract_code, Other}]}} ->
            erlang:error({feedback, {unsupported_abstract_code, Module, Other}});
        {error, Reason} ->
            erlang:error({feedback, {beam_read_failed, Module, Reason}})
    end.


%% line モードでは、計測用コードをロードする前に coverage mode を
%% line_counters にする。すでに設定されていた mode は終了時に戻す。
-spec set_coverage_mode(mode()) -> undefined | code:coverage_mode().
set_coverage_mode(clause) ->
    undefined;
set_coverage_mode(_Mode) ->
    try code:set_coverage_mode(line_counters) of
        OldMode ->
            OldMode
    catch
        error:badarg ->
            erlang:error({feedback, native_coverage_unsupported})
    end.


%% 元の coverage mode へ戻す。
-spec restore_coverage_mode(undefined | code:coverage_mode()) -> ok.
restore_coverage_mode(undefined) ->
    ok;
restore_coverage_mode(Mode) ->
    case code:set_coverage_mode(Mode) of
        _OldMode ->
            ok
    end.


%% 計測用にコンパイルしたモジュールをまとめてロードする。
-spec load_modules([{module(), file:filename_all(), binary()}]) -> ok.
load_modules(Compiled) ->
    lists:foreach(fun({Module, Beam, Binary}) ->
                          case code:load_binary(Module, Beam, Binary) of
                              {module, Module} ->
                                  ok;
                              {error, Reason} ->
                                  erlang:error({feedback,
                                                {load_failed, Module, Reason}})
                          end
                  end,
                  Compiled).


%% 行カウンターを読む対象モジュールと、セットアップ時点のカウンター数を返す。
%%
%% get_coverage(line, Module) は行テーブルの順に結果を返す。モジュールを
%% リロードしない限りこの並びと数は変わらないため、セットアップ時の数だけを
%% 保存し、入力ごとの結果と突き合わせる。行番号のリスト全体を毎回作るより軽い。
-spec line_modules([{module(), file:filename_all(), binary()}], mode()) ->
          [{module(), non_neg_integer()}].
line_modules(_Compiled, clause) ->
    [];
line_modules(Compiled, _Mode) ->
    [ {Module, initial_line_count(Module)} || {Module, _Beam, _Binary} <:- Compiled ].


-spec initial_line_count(module()) -> non_neg_integer().
initial_line_count(Module) ->
    case code:get_coverage_mode(Module) of
        line_counters ->
            try code:get_coverage(line, Module) of
                Coverage ->
                    length(Coverage)
            catch
                error:badarg ->
                    erlang:error({feedback, {line_coverage_unavailable, Module}})
            end;
        Other ->
            erlang:error({feedback, {coverage_mode, Module, Other}})
    end.


%% 1 モジュール分の行カウンターを読み、保存したカウンター数と一致するか確認する。
-spec read_line_counters(module(), non_neg_integer()) -> [byte()].
read_line_counters(Module, ExpectedCount) ->
    Coverage = code:get_coverage(line, Module),
    case length(Coverage) of
        ExpectedCount ->
            [ min(Count, 255) || {_Line, Count} <:- Coverage ];
        ActualCount ->
            erlang:error({feedback,
                          {line_layout_changed,
                           Module,
                           ExpectedCount,
                           ActualCount}})
    end.


-spec validate_counter_count(non_neg_integer(), pos_integer()) -> ok.
validate_counter_count(Total, MaxCounters) when Total =< MaxCounters ->
    ok;
validate_counter_count(Total, MaxCounters) ->
    erlang:error({feedback, {too_many_counters, Total, MaxCounters}}).


-spec line_counter_count([{module(), non_neg_integer()}]) -> non_neg_integer().
line_counter_count(LineModules) ->
    lists:sum([ Count || {_Module, Count} <:- LineModules ]).


-spec validate_mode(term()) -> ok.
validate_mode(line) ->
    ok;
validate_mode(clause) ->
    ok;
validate_mode(Value) ->
    erlang:error({invalid_option, {feedback, {mode, Value}}}).


%% セットアップ中に実行する後始末を登録する。
-spec add_cleanup(fun(() -> ok)) -> ok.
add_cleanup(Cleanup) ->
    put(?CLEANUPS_KEY, [Cleanup | get(?CLEANUPS_KEY)]),
    ok.


%% 登録した後始末を、登録した順の逆に実行する。
%% 1 個が失敗しても残りを実行し、警告だけを残す。
-spec run_cleanups([fun(() -> ok)]) -> ok.
run_cleanups([]) ->
    ok;
run_cleanups([Cleanup | Rest]) ->
    try Cleanup() of
        _ ->
            ok
    catch
        Class:Reason:Stacktrace ->
            logger:warning("Failed to clean up fuzzer feedback: ~p",
                           [{Class, Reason, Stacktrace}])
    end,
    run_cleanups(Rest).


%% 計測用にロードしたモジュールを、セットアップ前の状態へ戻す。
-spec restore_original(module(), original()) -> ok.
restore_original(Module, {loaded, Binary, Filename}) ->
    case code:load_binary(Module, Filename, Binary) of
        {module, Module} ->
            ok;
        {error, Reason} ->
            erlang:error({restore_failed, Module, Reason})
    end;
restore_original(Module, not_loaded) ->
    _ = code:delete(Module),
    _ = code:purge(Module),
    ok.
