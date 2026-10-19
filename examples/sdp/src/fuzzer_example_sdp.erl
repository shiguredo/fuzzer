-module(fuzzer_example_sdp).

-export([decode/1]).

-type field_type() ::
        version |
        origin |
        session_name |
        session_information |
        uri |
        email |
        phone |
        connection |
        bandwidth |
        timing |
        repeat |
        time_zone |
        encryption_key |
        attribute |
        media.
-type description() ::
        #{
          version := 0,
          origin := binary(),
          session_name := binary(),
          fields := [{field_type(), binary()}],
          media_count := non_neg_integer()
         }.
-type decode_error() ::
        empty |
        invalid_line_ending |
        malformed_line |
        unknown_field |
        invalid_version |
        missing_required |
        missing_timing.

-export_type([description/0, decode_error/0]).


-spec decode(binary()) -> {ok, description()} | {error, decode_error()}.
decode(<<>>) ->
    {error, empty};
decode(Data) ->
    maybe
        {ok, Lines} ?= split_lines(Data),
        {ok, Fields} ?= parse_lines(Lines, []),
        validate_fields(Fields)
    else
        {error, _Reason} = Error ->
            Error
    end.


-spec split_lines(binary()) -> {ok, [binary()]} | {error, invalid_line_ending}.
split_lines(Data) ->
    case binary:split(Data, <<"\r\n">>, [global]) of
        [_Only] ->
            {error, invalid_line_ending};
        Parts ->
            split_line_parts(Parts)
    end.


-spec split_line_parts([binary()]) -> {ok, [binary()]} | {error, invalid_line_ending}.
split_line_parts(Parts) ->
    % 最後の要素が空で、途中の行に改行が残っていない場合だけ行分割に成功する
    maybe
        <<>> ?= lists:last(Parts),
        Lines = lists:droplast(Parts),
        false ?= lists:any(fun has_line_break/1, Lines),
        {ok, Lines}
    else
        _ ->
            {error, invalid_line_ending}
    end.


-spec has_line_break(binary()) -> boolean().
has_line_break(Line) ->
    binary:match(Line, [<<"\r">>, <<"\n">>]) =/= nomatch.


-spec parse_lines([binary()], [{field_type(), binary()}]) ->
          {ok, [{field_type(), binary()}]} | {error, malformed_line | unknown_field}.
parse_lines([], Acc) ->
    {ok, lists:reverse(Acc)};
parse_lines([<<Type, $=, Value/binary>> | Rest], Acc) ->
    case field_type(Type) of
        unknown ->
            {error, unknown_field};
        FieldType ->
            parse_lines(Rest, [{FieldType, Value} | Acc])
    end;
parse_lines(_Lines, _Acc) ->
    {error, malformed_line}.


-spec field_type(byte()) -> field_type() | unknown.
field_type($v) ->
    version;
field_type($o) ->
    origin;
field_type($s) ->
    session_name;
field_type($i) ->
    session_information;
field_type($u) ->
    uri;
field_type($e) ->
    email;
field_type($p) ->
    phone;
field_type($c) ->
    connection;
field_type($b) ->
    bandwidth;
field_type($t) ->
    timing;
field_type($r) ->
    repeat;
field_type($z) ->
    time_zone;
field_type($k) ->
    encryption_key;
field_type($a) ->
    attribute;
field_type($m) ->
    media;
field_type(_Type) ->
    unknown.


-spec validate_fields([{field_type(), binary()}]) ->
          {ok, description()} | {error, invalid_version | missing_required | missing_timing}.
validate_fields([{version, <<"0">>}, {origin, Origin}, {session_name, SessionName} | Rest]) ->
    case lists:keymember(timing, 1, Rest) of
        true ->
            % Rest には media 以外のフィールドも含まれるため、型を束縛して明示的に絞り込む
            MediaCount = length([ ok || {Type, _Value} <:- Rest, Type =:= media ]),
            {ok,
             #{
               version => 0,
               origin => Origin,
               session_name => SessionName,
               fields => Rest,
               media_count => MediaCount
              }};
        false ->
            {error, missing_timing}
    end;
validate_fields([{version, Version} | _Rest]) when Version =/= <<"0">> ->
    {error, invalid_version};
validate_fields(_Fields) ->
    {error, missing_required}.
