%% クラッシュの同一性を表す識別子。
%%
%% 同じ原因で起きたクラッシュを同じものとして扱うため、入力そのものではなく
%% 例外の種類、例外の理由のタグ、function_clause のアリティ、OTP 外の最初の
%% スタックトレースフレームを使う。
%%
%% この識別子は、同じ BEAM での継続時の重複除外と、クラッシュ入力の最小化で
%% 共通に使う。
-module(fuzzer_crash).

-export([id/3, id_from_report/1]).
-export_type([crash_id/0]).

-type crash_id() ::
        #{
          class := atom(),
          reason := atom() | other,
          reason_arity := undefined | non_neg_integer(),
          frame := undefined | {module(), atom(), non_neg_integer(), non_neg_integer()}
         }.


%% 例外の種類、理由、スタックトレースからクラッシュ識別子を作る。
%%
%% フレームは OTP のモジュールを飛ばし、利用者のコードで最初に現れるものを
%% 採用する。行番号も含めるため、同じ関数の別の行で起きたクラッシュは区別できる。
-spec id(atom(), term(), [term()]) -> crash_id().
id(Class, Reason, Stacktrace) ->
    Frame = first_frame(Stacktrace),
    #{
      class => Class,
      reason => reason_tag(Reason),
      reason_arity => reason_arity(Reason, Frame),
      frame => Frame
     }.


%% クラッシュレポートからクラッシュ識別子を作る。
%%
%% 例外のレポートは reason が {Class, Reason}、stacktrace が入っている。
%% それ以外のクラッシュ (timeout、feedback_failure など) は理由のタグだけを使う。
-spec id_from_report(map()) -> crash_id().
id_from_report(#{reason := {Class, Reason}, stacktrace := Stacktrace})
  when Class =:= error; Class =:= exit; Class =:= throw ->
    id(Class, Reason, Stacktrace);
id_from_report(#{reason := Reason}) ->
    #{
      class => crash,
      reason => reason_tag(Reason),
      reason_arity => undefined,
      frame => undefined
     }.


%% 例外の理由から、値に依存しないタグを取り出す。
-spec reason_tag(term()) -> atom() | other.
reason_tag(Reason) when is_atom(Reason) ->
    Reason;
reason_tag(Reason) when is_tuple(Reason) ->
    case tuple_to_list(Reason) of
        [Tag | _Rest] when is_atom(Tag) ->
            Tag;
        _ ->
            other
    end;
reason_tag(_Reason) ->
    other.


%% function_clause の引数は入力ごとに変わるため、アリティだけを残す。
-spec reason_arity(term(), undefined | {module(), atom(), non_neg_integer(), non_neg_integer()}) ->
          undefined | non_neg_integer().
reason_arity({function_clause, Arguments}, _Frame) when is_list(Arguments) ->
    length(Arguments);
reason_arity(Reason, Frame) ->
    % VM によっては function_clause の理由がアトムになる。その場合はフレームの
    % アリティを使う。
    case reason_tag(Reason) of
        function_clause ->
            frame_arity(Frame);
        _ ->
            undefined
    end.


%% スタックトレースを先頭から走査し、OTP 外の最初のフレームを返す。
%%
%% 行番号はコードの変更でずれるが、同じ実行中のクラッシュを区別するために含める。
-spec first_frame([term()]) ->
          undefined | {module(), atom(), non_neg_integer(), non_neg_integer()}.
first_frame(Stacktrace) when is_list(Stacktrace) ->
    first_frame_1(Stacktrace);
first_frame(_Stacktrace) ->
    undefined.


-spec first_frame_1([term()]) ->
          undefined | {module(), atom(), non_neg_integer(), non_neg_integer()}.
first_frame_1([{Module, Function, Arity, Location} | Rest]) ->
    case is_otp_module(Module) of
        false ->
            case frame_arity({Module, Function, Arity, Location}) of
                undefined ->
                    first_frame_1(Rest);
                NormalizedArity ->
                    {Module, Function, NormalizedArity, frame_line(Location)}
            end;
        true ->
            first_frame_1(Rest)
    end;
first_frame_1([_Other | Rest]) ->
    first_frame_1(Rest);
first_frame_1([]) ->
    undefined.


%% フレームが OTP のモジュールかどうかを返す。
%%
%% code:which/1 が OTP のインストールディレクトリ配下を指す場合は OTP とみなす。
-spec is_otp_module(module()) -> boolean().
is_otp_module(Module) ->
    case code:which(Module) of
        preloaded ->
            true;
        Path when is_list(Path); is_binary(Path) ->
            Root = code:root_dir(),
            Lib = filename:join(Root, "lib"),
            Erts = filename:join(Root, "erts-" ++ erlang:system_info(version)),
            path_under(Path, Lib) orelse path_under(Path, Erts);
        _ ->
            false
    end.


-spec path_under(file:filename_all(), file:filename_all()) -> boolean().
path_under(Path, Directory) ->
    PathString = unicode:characters_to_list(Path),
    DirectoryString = unicode:characters_to_list(Directory),
    lists:prefix(DirectoryString ++ "/", PathString) orelse
    PathString =:= DirectoryString.


%% フレームのアリティを整数へ正規化する。
-spec frame_arity(term()) -> undefined | non_neg_integer().
frame_arity({_Module, _Function, Arity, _Location}) ->
    normalize_arity(Arity);
frame_arity(_Other) ->
    undefined.


-spec normalize_arity(term()) -> undefined | non_neg_integer().
normalize_arity(Arity) when is_integer(Arity), Arity >= 0 ->
    Arity;
normalize_arity(Arguments) when is_list(Arguments) ->
    length(Arguments);
normalize_arity(_Other) ->
    undefined.


%% スタックトレースの位置情報から行番号を取り出す。
-spec frame_line(term()) -> non_neg_integer().
frame_line(Location) when is_list(Location) ->
    case lists:keyfind(line, 1, Location) of
        {line, Line} when is_integer(Line), Line >= 0 ->
            Line;
        _ ->
            0
    end;
frame_line(_Location) ->
    0.
