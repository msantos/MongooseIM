%%==============================================================================
%% Copyright 2014 Erlang Solutions Ltd.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%==============================================================================

-module(ewmg_auth_http_SUITE).
-compile(export_all).

-include_lib("common_test/include/ct.hrl").

-define(DOMAIN1, <<"localhost">>).
-define(DOMAIN2, <<"localhost2">>).
-define(AUTH_HOST, "http://esl.core.ggdev.xyz").
-define(BASIC_AUTH, "softkitty:purrpurrpurr").
-define(PATH_PREFIX, "/api/v1/").
-define(PROFILE, <<"57f24a8d17238107630680">>).
-define(TOKEN, <<"Xgw8xLhto3zICLcH9Tw1RDv0LiwsGYYxt4zLDHTu">>).
-define(SECRET, "secret").

%%--------------------------------------------------------------------
%% Suite configuration
%%--------------------------------------------------------------------

all() ->
    [{group, auth_requests_plain}].

groups() ->
    [
     {auth_requests_plain, [sequence], all_tests()}
    ].

all_tests() ->
    [
     check_password
    ].

suite() ->
    [].

%%--------------------------------------------------------------------
%% Init & teardown
%%--------------------------------------------------------------------

init_per_suite(Config) ->
    application:start(stringprep),
    meck_config(Config),
    mim_ct_rest:start(?BASIC_AUTH, Config),
    % Separate process needs to do this, because this one will terminate
    % so will supervisor and children and ETS tables
    mim_ct_rest:do(fun() ->
                           mim_ct_sup:start_link(ejabberd_sup),
                           ejabberd_auth_http_ewmg:start(?DOMAIN1),
                           %% confirms compatibility with multi-domain cluster
                           ejabberd_auth_http_ewmg:start(?DOMAIN2)
                   end),
    meck_cleanup(),
    Config.

end_per_suite(Config) ->
    ejabberd_auth_http_ewmg:stop(?DOMAIN1),
    ejabberd_auth_http_ewmg:stop(?DOMAIN2),
    exit(whereis(ejabberd_sup), kill),
    Config.

init_per_testcase(_CaseName, Config) ->
    meck_config(Config),
    Config.

end_per_testcase(_CaseName, Config) ->
    meck_cleanup(),
    Config.

%%--------------------------------------------------------------------
%% Authentication tests
%%--------------------------------------------------------------------

check_password(_Config) ->
    true = ejabberd_auth_http_ewmg:check_password(?PROFILE,
                                                  ?DOMAIN1,
                                                  ?TOKEN),
    false = ejabberd_auth_http_ewmg:check_password(?PROFILE,
                                                   ?DOMAIN1,
                                                   <<"invalid_token">>),
    ok.


%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

meck_config(Config) ->
    ScramOpts = case lists:keyfind(scram_group, 1, Config) of
                    {_, true} -> [{password_format, scram}];
                    _ -> []
                end,
    meck:new(ejabberd_config),
    meck:expect(ejabberd_config, get_local_option,
                fun(auth_opts, _Host) ->
                        [
                         {host, ?AUTH_HOST},
                         {path_prefix, ?PATH_PREFIX},
                         {server_secret, ?SECRET},
                         {basic_auth, ?BASIC_AUTH}
                        ] ++ ScramOpts
                end).

meck_cleanup() ->
    meck:validate(ejabberd_config),
    meck:unload(ejabberd_config).

do_scram(Pass, Config) ->
    case lists:keyfind(scram_group, 1, Config) of
        {_, true} ->
            scram:serialize(scram:password_to_scram(Pass, scram:iterations(?DOMAIN1)));
        _ ->
            Pass
    end.

