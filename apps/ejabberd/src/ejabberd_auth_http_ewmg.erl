%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_http.erl
%%% Author  : Piotr Nosek <piotr.nosek@erlang-solutions.com>
%%% Purpose : Authentication via HTTP request
%%% Created : 23 Sep 2013 by Piotr Nosek <piotr.nosek@erlang-solutions.com>
%%%----------------------------------------------------------------------

-module(ejabberd_auth_http_ewmg).
-author('piotr.nosek@erlang-solutions.com').

-behaviour(ejabberd_gen_auth).

%% External exports
-export([start/1,
         set_password/3,
         authorize/1,
         try_register/3,
         dirty_get_registered_users/0,
         get_vh_registered_users/1,
         get_vh_registered_users/2,
         get_vh_registered_users_number/1,
         get_vh_registered_users_number/2,
         get_password/2,
         get_password_s/2,
         does_user_exist/2,
         remove_user/2,
         remove_user/3,
         store_type/1,
         stop/1]).

%% Pre-mongoose_credentials API
-export([check_password/3
         %check_password/5
]).

-include("ejabberd.hrl").

-type http_error_atom() :: conflict | not_found | not_authorized | not_allowed.

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

-spec start(binary()) -> ok.
start(Host) ->
    ejabberd_auth_http:start(Host),
    ok.


-spec store_type(binary()) -> plain | scram.
store_type(Server) ->
    % ???
    ejabberd_auth_http:store_type(Server).

-spec authorize(mongoose_credentials:t()) -> {ok, mongoose_credentials:t()}
                                           | {error, any()}.
authorize(Creds) ->
    ejabberd_auth:authorize_with_check_password(?MODULE, Creds).

-spec check_password(ejabberd:luser(), ejabberd:lserver(), binary()) -> boolean().
check_password(LUser, LServer, Password) ->
    case scram:enabled(LServer) of
        false ->
            case make_req(get, LUser, LServer, Password) of
                {ok, _} -> true;
                _ ->
                    false
            end;
        true ->
            throw(scram_enabled_not_supported)
    end.

-spec set_password(ejabberd:luser(), ejabberd:lserver(), binary()) -> ok | {error, not_allowed}.
set_password(_LUser, _LServer, _Password) ->
    {error, not_allowed}.

-spec try_register(ejabberd:luser(), ejabberd:lserver(), binary()) ->
    ok | {error, exists | not_allowed}.
try_register(_LUser, _LServer, _Password) ->
    {error, not_allowed}.

-spec dirty_get_registered_users() -> [].
dirty_get_registered_users() ->
    [].

-spec get_vh_registered_users(ejabberd:lserver()) -> [].
get_vh_registered_users(_Server) ->
    [].

-spec get_vh_registered_users(ejabberd:lserver(), list()) -> [].
get_vh_registered_users(_Server, _Opts) ->
    [].

-spec get_vh_registered_users_number(binary()) -> 0.
get_vh_registered_users_number(_Server) ->
    0.

-spec get_vh_registered_users_number(ejabberd:lserver(), list()) -> 0.
get_vh_registered_users_number(_Server, _Opts) ->
    0.

-spec get_password(ejabberd:luser(), ejabberd:lserver()) -> ejabberd_auth:passwordlike() | false.
get_password(_LUser, _LServer) ->
    false.

-spec get_password_s(ejabberd:luser(), ejabberd:lserver()) -> binary().
get_password_s(_User, _Server) ->
    <<>>.

-spec does_user_exist(ejabberd:luser(), ejabberd:lserver()) -> boolean().
does_user_exist(_LUser, _LServer) ->
    true.

-spec remove_user(ejabberd:luser(), ejabberd:lserver()) ->
    ok | {error, not_allowed}.
remove_user(_LUser, _LServer) ->
    {error, not_allowed}.

-spec remove_user(ejabberd:luser(), ejabberd:lserver(), binary()) ->
    ok | {error, not_allowed | not_exists | bad_request}.
remove_user(_LUser, _LServer, _Password) ->
    {error, not_allowed}.


%%%----------------------------------------------------------------------
%%% Request maker
%%%----------------------------------------------------------------------

-spec make_req(post | get, binary(), binary(), binary()) ->
    {ok, BodyOrCreated :: binary() | created} | {error, invalid_jid | http_error_atom() | binary()}.
make_req(_, LUser, LServer, _) when LUser == error orelse LServer == error ->
    {error, invalid_jid};
make_req(post, _, _, _) ->
    {error, not_allowed}; % should be 405 method_not_allowed
make_req(Method, LUser, LServer, Password) ->
    AuthOpts = ejabberd_config:get_local_option(auth_opts, LServer),
    PathPrefix = case lists:keyfind(path_prefix, 1, AuthOpts) of
                     {_, Prefix} -> ejabberd_binary:string_to_binary(Prefix);
                     false -> <<"/">>
                 end,
    Secret = ejabberd_binary:string_to_binary(proplists:get_value(server_secret, AuthOpts)),
    LUserE = list_to_binary(http_uri:encode(binary_to_list(LUser))),
    PasswordE = list_to_binary(http_uri:encode(binary_to_list(Password))),
    Query = <<"access_token=", PasswordE/binary, "&server_secret=", Secret/binary>>,
    Header = [],
    FullPath = <<PathPrefix/binary, "profiles/", LUserE/binary, "/verifytoken">>,
    ?DEBUG("Making request '~s' for user ~s@~s...", [FullPath, LUser, LServer]),
    make_http_req(LServer, Method, FullPath, Query, Header).

make_http_req(LServer, Method, FullPath, Query, Header) ->
    Connection = cuesport:get_worker(existing_pool_name(LServer)),

    {ok, {{Code, Reason}, RespHeaders, RespBody, _, _}} = case Method of
        get -> fusco:request(Connection, <<FullPath/binary, "?", Query/binary>>,
                             "GET", Header, "", 2, 5000);
        post -> fusco:request(Connection, FullPath,
                              "POST", Header, Query, 2, 5000)
    end,

    ?DEBUG("Request result: ~s: ~p", [Code, RespBody]),
    NCode = fix_code(Code, RespHeaders),
    case NCode of
        <<"409">> -> {error, conflict};
        <<"404">> -> {error, not_found};
        <<"401">> -> {error, not_authorized};
        <<"403">> -> {error, not_allowed};
        <<"400">> -> {error, RespBody};
        <<"204">> -> {ok, <<"">>};
        <<"201">> -> {ok, created};
        <<"200">> -> {ok, RespBody}
    end.

%% @doc temporary - because they reply in a strange way
fix_code(<<"200">>, RespHeaders) ->
    case proplists:get_value(<<"0">>, RespHeaders) of
        <<"HTTP/1.1 401 Unauthorized">> ->
           <<"401">>;
        undefined ->
            <<"200">>
    end;
fix_code(Code, _) ->
    Code.

%%%----------------------------------------------------------------------
%%% Other internal functions
%%%----------------------------------------------------------------------
%%-spec pool_name(binary()) -> atom().
%%pool_name(Host) ->
%%    list_to_atom("ejabberd_auth_http_" ++ binary_to_list(Host)).

-spec existing_pool_name(binary()) -> atom().
existing_pool_name(Host) ->
    list_to_existing_atom("ejabberd_auth_http_" ++ binary_to_list(Host)).

stop(Host) ->
    Id = {ejabberd_auth_http_sup, Host},
    supervisor:terminate_child(ejabberd_sup, Id),
    supervisor:delete_child(ejabberd_sup, Id),
    ok.

