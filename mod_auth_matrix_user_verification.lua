-- Copyright 2021 Kommunales Rechenzentrum Niederrhein
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Based upon https://github.com/matrix-org/prosody-mod-auth-matrix-user-verification

local formdecode = require "util.http".formdecode;
local generate_uuid = require "util.uuid".generate;
local jid = require "util.jid";
local jwt = require "luajwtjitsi";
local new_sasl = require "util.sasl".new;
local sasl = require "util.sasl";
local sessions = prosody.full_sessions;
local basexx = require "basexx";
local http_request = require "http.request";
local json = require "util.json";
local rex = require "rex_posix";

local homserver_hostname_pattern_str = module:get_option("matrix_homeserver_hostname_pattern", nil);
if homserver_hostname_pattern_str == nil then
   module:log("warn", "No matrix_homeserver_hostname_pattern supplied, disabling matrix user verification");
   return;
end

local status, homserver_hostname_pattern = pcall(rex.new, homserver_hostname_pattern_str);
if not status then
   module:log("warn", string.format("Failed to compile homserver_hostname_pattern \"%s\": %s. Disabling matrix user verification", 
      homserver_hostname_pattern_str, homserver_hostname_pattern));
   return;
end

-- define auth provider
local provider = {};

local host = module.host;

-- Extract 'token' param from URL when session is created
function init_session(event)
	local session, request = event.session, event.request;
	local query = request.url.query;

	if query ~= nil then
        local params = formdecode(query);

        -- token containing the information we need: openid token and room ID
        session.auth_token = query and params.token or nil;

        -- previd is used together with https://modules.prosody.im/mod_smacks.html
        -- the param is used to find resumed session and re-use anonymous(random) user id
        -- (see get_username_from_token)
        session.previd = query and params.previd or nil;

        -- The room name
        session.jitsi_room = params.room;
    end
end

module:hook_global("bosh-session", init_session);
module:hook_global("websocket-session", init_session);

function provider.test_password(username, password)
	return nil, "Password based auth not supported";
end

function provider.get_password(username)
	return nil;
end

function provider.set_password(username, password)
	return nil, "Set password not supported";
end

function provider.user_exists(username)
	return nil;
end

function provider.create_user(username, password)
	return nil;
end

function provider.delete_user(username)
	return nil;
end

local function get_userinfo(hostname, token)
    local uri = string.format("https://%s/_matrix/federation/v1/openid/userinfo?access_token=%s", hostname, token)
    local request = http_request.new_from_uri(uri);
    local headers, stream = assert(request:go());
    local body = assert(stream:get_body_as_string());
    local status = headers:get(":status");
    if status == "200" then
       return json.decode(body);
    else
       module:log("warn", "Request at %s failed with status %s", uri, status);
    end           
    -- TODO add some error handling
    return nil;
end
    
function provider.get_sasl_handler(session)
       local room_id = basexx.from_base32(session.jitsi_room);

       local function check_access_token(self, message)
       if session.auth_token == nil then
          module:log("warn", "No JWT token provided")
          return false, "bad-request", "No JWT token provided";
       end

       local data, msg = jwt.decode(session.auth_token);
       if data == nil then
           module:log("warn", "JWT token cannot be decoded")
           return false, "bad-request", "JWT token cannot be decoded";
       end

       if data.context == nil or data.context.matrix == nil or data.context.matrix.server_name == nil then
          module:log("warn", "Missing field .context.matrix.server_name in JWT token")
          return false, "bad-request", "Missing field .context.matrix.server_name in JWT token"
       end

       local match_start, match_end = homserver_hostname_pattern:exec(data.context.matrix.server_name)
       if match_start == 1 and match_end == string.len(data.context.matrix.server_name) then 
          if data.context.matrix.token == nil then
             module:log("warn", "Missing field .context.matrix.token in JWT token")
             return false, "bad-request", "Missing field .context.matrix.token in JWT token"
          end

          local userinfo = get_userinfo(data.context.matrix.server_name, data.context.matrix.token);
          if userinfo then
             if userinfo.room_powerlevels then
                local power_level = userinfo.room_powerlevels[room_id];
                if power_level ~= nil then
                   session.jitsi_meet_context_user = { id = userinfo.sub };
                   if userinfo.name then
                      session.name = userinfo.name;
                   else
                      module:log("warn", "Matrix openid userinfo did not contain name field")
                   end
                   if power_level >= 50 then
                      session.auth_matrix_user_verification_is_owner = true;
                   end
                   return true;
                else
                   module:log("warn", string.format("Authentication for user %s in room %s failed, user is not a member of the room", 
                      userinfo.sub, room_id));
                end
             else
                module:log("warn", "Matrix openid userinfo did not contain power_levels field")
             end        
          end
       else
          module:log("warn", string.format("Homserver name \"%s\" does not match pattern of allowed hostnames", 
             data.context.matrix.server_name))
       end
            
       return false, "unauthorized", "Authentication failed"
    end

    return new_sasl(session.orig_to or host, { anonymous = check_access_token });
end

module:provides("auth", provider);

local function anonymous(self, message)

	local username = generate_uuid();

        -- This calls the handler created in 'provider.get_sasl_handler(session)'
        module:log("info", "anonymous realm %s", self.realm);
	
	local result, err, msg = self.profile.anonymous(self, username, self.realm);

	if result == true then
		if (self.username == nil) then
			self.username = username;
		end
		module:log("info", "REQUEST_COMPLETE reason:ok")
		return "success";
	else
		return "failure", err, msg;
	end
end

sasl.registerMechanism("ANONYMOUS", {"anonymous"}, anonymous);
