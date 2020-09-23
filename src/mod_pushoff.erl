%%%
%%% Copyright (C) 2015  Christian Ulrich
%%% Copyright (C) 2016  Vlad Ki
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

-module(mod_pushoff).

-author('christian@rechenwerk.net').
-author('proger@wilab.org.ua').
-author('dimskii123@gmail.com').

-behaviour(gen_mod).

-compile(export_all).
-export([start/2, stop/1, reload/3, depends/2, mod_opt_type/1, parse_backends/1,
         offline_message/1, adhoc_local_commands/4, remove_user/2,
         health/0]).
-export([register_fcm_token/2, register_fcm_token/3, get_fcm_tokens/1, fcm_test/1]).

-include("logger.hrl").
-include("xmpp.hrl").
-include("adhoc.hrl").
-include("ejabberd_commands.hrl").

-include("mod_pushoff.hrl").

-define(MODULE_APNS, mod_pushoff_apns).
-define(MODULE_FCM, mod_pushoff_fcm).
-define(OFFLINE_HOOK_PRIO, 1). % must fire before mod_offline (which has 50)

%
% types
%

-record(apns_config,
        {certfile = <<"">> :: binary(),
         gateway = <<"">> :: binary()}).

-record(fcm_config,
        {gateway = <<"">> :: binary(),
         api_key = <<"">> :: binary()}).

-type apns_config() :: #apns_config{}.
-type fcm_config() :: #fcm_config{}.

-record(backend_config,
        {ref :: backend_ref(),
         config :: apns_config() | fcm_config()}).

-type backend_config() :: #backend_config{}.

%
% dispatch to workers
%

-spec(stanza_to_payload(message()) -> [{atom(), any()}]).

stanza_to_payload(#message{id = Id}) -> [{id, Id}];
stanza_to_payload(_) -> [].

-spec(dispatch(pushoff_registration(), [{atom(), any()}]) -> ok).

dispatch(#pushoff_registration{bare_jid = UserBare, token = Token, timestamp = Timestamp,
                               backend_id = BackendId},
         Payload) ->
    DisableArgs = {UserBare, Timestamp},
    gen_server:cast(backend_worker(BackendId),
                    {dispatch, UserBare, Payload, Token, DisableArgs}),
    ok.


%
% ejabberd hooks
%

-spec(offline_message({atom(), message()}) -> {atom(), message()}).

offline_message({_, #message{to = To} = Stanza} = Acc) ->
    Payload = stanza_to_payload(Stanza),
    case mod_pushoff_mnesia:list_registrations(To) of
        {registrations, []} ->
            ?DEBUG("~p is not_subscribed", [To]),
            Acc;
        {registrations, Rs} ->
            [dispatch(R, Payload) || R <- Rs],
            Acc;
        {error, _} -> Acc
    end.


-spec(remove_user(User :: binary(), Server :: binary()) ->
             {error, stanza_error()} |
             {unregistered, [pushoff_registration()]}).

remove_user(User, Server) ->
    mod_pushoff_mnesia:unregister_client({User, Server}, '_').


-spec adhoc_local_commands(Acc :: empty | adhoc_command(),
                           From :: jid(),
                           To :: jid(),
                           Request :: adhoc_command()) ->
                                  adhoc_command() |
                                  {error, stanza_error()}.

adhoc_local_commands(Acc, From, To, #adhoc_command{node = Command, action = execute, xdata = XData} = Req) ->
    Host = To#jid.lserver,
    Access = gen_mod:get_module_opt(Host, ?MODULE, access_backends,
                                    fun(A) when is_atom(A) -> A end, all),
    Result = case acl:match_rule(Host, Access, From) of
        deny -> {error, xmpp:err_forbidden()};
        allow -> adhoc_perform_action(Command, From, XData)
    end,

    case Result of
        unknown -> Acc;
        {error, Error} -> {error, Error};

        {registered, ok} ->
            xmpp_util:make_adhoc_response(Req, #adhoc_command{status = completed});

        {unregistered, Regs} ->
            X = xmpp_util:set_xdata_field(#xdata_field{var = <<"removed-registrations">>,
                                                       values = [T || #pushoff_registration{token=T} <- Regs]}, #xdata{}),
            xmpp_util:make_adhoc_response(Req, #adhoc_command{status = completed, xdata = X});

        {registrations, Regs} ->
            X = xmpp_util:set_xdata_field(#xdata_field{var = <<"registrations">>,
                                                       values = [T || #pushoff_registration{token=T} <- Regs]}, #xdata{}),
            xmpp_util:make_adhoc_response(Req, #adhoc_command{status = completed, xdata = X})
    end;
adhoc_local_commands(Acc, _From, _To, _Request) ->
    Acc.


adhoc_perform_action(<<"register-push-apns">>, #jid{lserver = LServer} = From, XData) ->
    BackendRef = case xmpp_util:get_xdata_values(<<"backend_ref">>, XData) of
        [Key] -> {apns, Key};
        _ -> apns
    end,
    case validate_backend_ref(LServer, BackendRef) of
        {error, E} -> {error, E};
        {ok, BackendRef} ->
            case xmpp_util:get_xdata_values(<<"token">>, XData) of
                [Base64Token] ->
                    case catch base64:decode(Base64Token) of
                        {'EXIT', _} -> {error, xmpp:err_bad_request()};
                        Token -> mod_pushoff_mnesia:register_client(From, {LServer, BackendRef}, Token)
                    end;
                _ -> {error, xmpp:err_bad_request()}
            end
    end;
adhoc_perform_action(<<"register-push-fcm">>, #jid{lserver = LServer} = From, XData) ->
    BackendRef = case xmpp_util:get_xdata_values(<<"backend_ref">>, XData) of
        [Key] -> {fcm, Key};
        _ -> fcm
    end,
    case validate_backend_ref(LServer, BackendRef) of
        {error, E} -> {error, E};
        {ok, BackendRef} ->
            case xmpp_util:get_xdata_values(<<"token">>, XData) of
                [AsciiToken] -> mod_pushoff_mnesia:register_client(From, {LServer, BackendRef}, AsciiToken);
                _ -> {error, xmpp:err_bad_request()}
            end
    end;
adhoc_perform_action(<<"unregister-push">>, From, _) ->
    mod_pushoff_mnesia:unregister_client(From, undefined);
adhoc_perform_action(<<"list-push-registrations">>, From, _) ->
    mod_pushoff_mnesia:list_registrations(From);
adhoc_perform_action(_, _, _) ->
    unknown.

%
% ejabberd gen_mod callbacks and configuration
%

-spec(start(Host :: binary(), Opts :: [any()]) -> any()).

start(Host, Opts) ->
    mod_pushoff_mnesia:create(),

    ok = ejabberd_hooks:add(remove_user, Host, ?MODULE, remove_user, 50),
    % ok = ejabberd_hooks:add(offline_message_hook, Host, ?MODULE, offline_message, ?OFFLINE_HOOK_PRIO),
    ok = ejabberd_hooks:add(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 75),
    ejabberd_commands:register_commands(get_commands_spec()),

    Results = [start_worker(Host, B) || B <- proplists:get_value(backends, Opts)],
    ?INFO_MSG("mod_pushoff workers: ~p", [Results]),
    ok.

-spec(stop(Host :: binary()) -> any()).

stop(Host) ->
    ?DEBUG("mod_pushoff:stop(~p), pid=~p", [Host, self()]),
    case gen_mod:is_loaded_elsewhere(Host, ?MODULE) of
        false ->
            ejabberd_commands:unregister_commands(get_commands_spec());
        true ->
            ok
    end,
    ok = ejabberd_hooks:delete(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 75),
    % ok = ejabberd_hooks:delete(offline_message_hook, Host, ?MODULE, offline_message, ?OFFLINE_HOOK_PRIO),
    ok = ejabberd_hooks:delete(remove_user, Host, ?MODULE, remove_user, 50),

    [begin
         Worker = backend_worker({Host, Ref}),
         supervisor:terminate_child(ejabberd_gen_mod_sup, Worker),
         supervisor:delete_child(ejabberd_gen_mod_sup, Worker)
     end || #backend_config{ref=Ref} <- backend_configs(Host)],
    ok.

reload(Host, NewOpts, _OldOpts) ->
    stop(Host),
    start(Host, NewOpts),
    ok.

depends(_, _) ->
    [{mod_offline, soft}, {mod_adhoc, soft}].

%%%
%%% Register commands
%%%

get_commands_spec() -> 
    [#ejabberd_commands{name = register_fcm_token_with_backend, tags = [fcm],
	            		desc = "Register an FCM token with backend",
                        module = ?MODULE, function = register_fcm_token,
                        args_desc = ["User JID", "FCM token", "Backend ref"],
                        args_example = ["tom@localhost", "f8D1rsA_TteUp_de5A5KZO:APA91bHLBqJgebUBgzrIJfmmtGXivLPOuivuIoMq2XRslxhqKPLdW4E6Ms1is9WYx-sJU-sbeFKywptVnrilv2yiiKK5TFQdA_tBzCd_sg625NEfQ-0ZqQXnrF530dvxVqxdUmAAbCI-", "fcm-prod"],
                        result_desc = "List of registered FCM tokens",
                        result_example = ["f8D1rsA_TteUp_de5A5KZO:APA91bHLBqJgebUBgzrIJfmmtGXivLPOuivuIoMq2XRslxhqKPLdW4E6Ms1is9WYx-sJU-sbeFKywptVnrilv2yiiKK5TFQdA_tBzCd_sg625NEfQ-0ZqQXnrF530dvxVqxdUmAAbCI-",
                            "c6-D5hdMRwyDQRwBneLX-B:APA91bGnlPEf6ESXcFDHUV1lP1koek4GUeYkbc0Ni788eZgtT0GNc5_-PxqacNTC-dYCGK-HY-KTRWnSo5oOKKLpvwgajCmY0GVkuVIADfHuuxJYuILKxtvUSYLaK8ckcivN0moW_3u3"],
                        args = [{jid, binary}, {token, binary}, {backend_ref, binary}],
                        result = {fcm_tokens, {list, {fcm_token, string}}}},
     #ejabberd_commands{name = register_fcm_token, tags = [fcm],
	            		desc = "Register an FCM token",
                        module = ?MODULE, function = register_fcm_token,
                        args_desc = ["User JID", "FCM token"],
                        args_example = ["tom@localhost", "f8D1rsA_TteUp_de5A5KZO:APA91bHLBqJgebUBgzrIJfmmtGXivLPOuivuIoMq2XRslxhqKPLdW4E6Ms1is9WYx-sJU-sbeFKywptVnrilv2yiiKK5TFQdA_tBzCd_sg625NEfQ-0ZqQXnrF530dvxVqxdUmAAbCI-"],
                        result_desc = "List of registered FCM tokens",
                        result_example = ["f8D1rsA_TteUp_de5A5KZO:APA91bHLBqJgebUBgzrIJfmmtGXivLPOuivuIoMq2XRslxhqKPLdW4E6Ms1is9WYx-sJU-sbeFKywptVnrilv2yiiKK5TFQdA_tBzCd_sg625NEfQ-0ZqQXnrF530dvxVqxdUmAAbCI-",
                            "c6-D5hdMRwyDQRwBneLX-B:APA91bGnlPEf6ESXcFDHUV1lP1koek4GUeYkbc0Ni788eZgtT0GNc5_-PxqacNTC-dYCGK-HY-KTRWnSo5oOKKLpvwgajCmY0GVkuVIADfHuuxJYuILKxtvUSYLaK8ckcivN0moW_3u3"],
                        args = [{jid, binary}, {token, binary}],
                        result = {fcm_tokens, {list, {fcm_token, string}}}},
     #ejabberd_commands{name = registered_fcm_tokens, tags = [fcm],
	            		desc = "Get list of FCM token",
                        module = ?MODULE, function = get_fcm_tokens,
                        args_desc = ["User JID"],
                        args_example = ["tom@localhost"],
                        result_desc = "List of registered FCM tokens",
                        result_example = ["f8D1rsA_TteUp_de5A5KZO:APA91bHLBqJgebUBgzrIJfmmtGXivLPOuivuIoMq2XRslxhqKPLdW4E6Ms1is9WYx-sJU-sbeFKywptVnrilv2yiiKK5TFQdA_tBzCd_sg625NEfQ-0ZqQXnrF530dvxVqxdUmAAbCI-",
                            "c6-D5hdMRwyDQRwBneLX-B:APA91bGnlPEf6ESXcFDHUV1lP1koek4GUeYkbc0Ni788eZgtT0GNc5_-PxqacNTC-dYCGK-HY-KTRWnSo5oOKKLpvwgajCmY0GVkuVIADfHuuxJYuILKxtvUSYLaK8ckcivN0moW_3u3"],
                        args = [{jid, binary}],
                        result = {fcm_tokens, {list, {fcm_token, string}}}},
     #ejabberd_commands{name = test_fcm, tags = [fcm],
	            		desc = "Send FCM test message to a user",
                        module = ?MODULE, function = fcm_test,
                        args_desc = ["User JID"],
                        args_example = ["tom@localhost"],
                        args = [{jid, binary}],
                        result = {res, rescode}}
        ].

% commands
register_fcm_token(JIDBinary, Token) when is_binary(JIDBinary), is_binary(Token) ->
    register_fcm_token(JIDBinary, Token, no_backend).
register_fcm_token(JIDBinary, Token, BackendRef) when is_binary(JIDBinary), is_binary(Token) ->
    #jid{lserver = LServer} = JID = jid:decode(JIDBinary),
    Ref = if
        is_binary(BackendRef) -> {fcm, BackendRef};
        true -> fcm
    end,
    case validate_backend_ref(LServer, Ref) of
        {error, E} ->
            {error, "Backend not valid"};
        {ok, Ref} ->
            case mod_pushoff_mnesia:register_client(JID, {LServer, Ref}, Token) of
                {registered, _} ->
                    get_fcm_tokens(JID);
                Error ->
                    Error
            end
    end.

get_fcm_tokens(JID) when is_binary(JID) ->
    get_fcm_tokens(jid:decode(JID));
get_fcm_tokens(#jid{} = JID) ->
    case mod_pushoff_mnesia:list_registrations(JID) of
        {registrations, RL} ->
            [T || #pushoff_registration{token = T} <- RL];
        Error ->
            Error
    end.

fcm_test(JIDBinary) when is_binary(JIDBinary) ->
    JID = jid:decode(JIDBinary),
    RegistrationList = mod_pushoff_mnesia:list_registrations(JID),
    case RegistrationList of
        {registrations, []} ->
            {ok, "No FCM token found"};
        {registrations, Rs} ->
            Payload = [{title, <<"Test message">>}, {body, <<"This is a test message from XMPP server.">>}],
            [dispatch(R, Payload) || R <- Rs],
            {ok, "Sent"};
        _ ->
            {error, "Error retrieving tokens"}
    end;
fcm_test(_) ->
    {error, "Invalid JID"}.

mod_opt_type(backends) -> fun ?MODULE:parse_backends/1;
mod_opt_type(_) -> [backends].

validate_backend_ref(Host, Ref) ->
    case [R || #backend_config{ref=R} <- backend_configs(Host), R == Ref] of
        [R] -> {ok, R};
        _ -> {error, xmpp:err_bad_request()}
    end.

backend_ref(apns, undefined) -> apns;
backend_ref(fcm, undefined) -> fcm;
backend_ref(apns, K) -> {apns, K};
backend_ref(fcm, K) -> {fcm, K}.

backend_type({Type, _}) -> Type;
backend_type(Type) -> Type.

parse_backends(Plists) ->
    [parse_backend(Plist) || Plist <- Plists].

parse_backend(Opts) ->
    Ref = backend_ref(proplists:get_value(type, Opts), proplists:get_value(backend_ref, Opts)),
    #backend_config{
       ref = Ref,
       config =
           case backend_type(Ref) of
               apns ->
                   #apns_config{certfile = proplists:get_value(certfile, Opts), gateway = proplists:get_value(gateway, Opts)};
               fcm ->
                   #fcm_config{gateway = proplists:get_value(gateway, Opts), api_key = proplists:get_value(api_key, Opts)}
           end
      }.


%
% workers
%

-spec(backend_worker(backend_id()) -> atom()).

backend_worker({Host, {T, R}}) -> gen_mod:get_module_proc(Host, binary_to_atom(<<(erlang:atom_to_binary(T, latin1))/binary, "_", R/binary>>, latin1));
backend_worker({Host, Ref}) -> gen_mod:get_module_proc(Host, Ref).

backend_configs(Host) ->
    gen_mod:get_module_opt(Host, ?MODULE, backends,
                           fun(O) when is_list(O) -> O end, []).

backend_module(apns) -> ?MODULE_APNS;
backend_module(fcm) -> ?MODULE_FCM.

-spec(start_worker(Host :: binary(), Backend :: backend_config()) -> ok).

start_worker(Host, #backend_config{ref = Ref, config = Config}) ->
    Worker = backend_worker({Host, Ref}),
    BackendSpec =
    case backend_type(Ref) of
        apns ->
                  {Worker,
                   {gen_server, start_link,
                    [{local, Worker}, backend_module(backend_type(Ref)),
                     [Config#apns_config.certfile, Config#apns_config.gateway], []]},
                   permanent, 1000, worker, [?MODULE]};
        fcm ->
                  {Worker,
                   {gen_server, start_link,
                    [{local, Worker}, backend_module(backend_type(Ref)),
                     [Config#fcm_config.gateway, Config#fcm_config.api_key], []]},
                   permanent, 1000, worker, [?MODULE]}
    end,

    supervisor:start_child(ejabberd_gen_mod_sup, BackendSpec).

%
% operations
%

health() ->
    Hosts = ejabberd_config:get_myhosts(),
    [{offline_message_hook, [ets:lookup(hooks, {offline_message_hook, H}) || H <- Hosts]},
     {adhoc_local_commands, [ets:lookup(hooks, {adhoc_local_commands, H}) || H <- Hosts]},
     {mnesia, mod_pushoff_mnesia:health()}].
