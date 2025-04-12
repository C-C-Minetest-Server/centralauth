-- centralauth/centralauth/src/api.lua
-- Suppliment operation on the CentralAuth DB
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local _int = centralauth.internal
local logger = _int.logger:sublogger("api")
local S = core.get_translator("centralauth")

function centralauth.check_player_global_privs(name, ...)
    if core.is_player(name) then
        name = name:get_player_name()
    elseif type(name) ~= "string" then
        logger:raise("centralauth.check_player_global_privs expects a player or playername as " ..
            "argument.", 2)
    end

    local requested_privs = { ... }
    local player_privs = centralauth.get_global_user_privilege_by_name(name)
    local missing_privileges = {}

    if type(requested_privs[1]) == "table" then
        -- We were provided with a table like { privA = true, privB = true }.
        for priv, value in pairs(requested_privs[1]) do
            if value and not player_privs[priv] then
                missing_privileges[#missing_privileges + 1] = priv
            end
        end
    else
        -- Only a list, we can process it directly.
        for _, priv in pairs(requested_privs) do
            if not player_privs[priv] then
                missing_privileges[#missing_privileges + 1] = priv
            end
        end
    end

    if #missing_privileges > 0 then
        return false, missing_privileges
    end

    return true, ""
end

centralauth.registered_global_privileges = {}

function centralauth.register_global_privilege(name, def)
    logger:assert(type(name) == "string", "name must be a string")
    if type(def) == "string" then
        def = { description = def }
    end
    logger:assert(type(def) == "table", "def must be a table or string")

    centralauth.registered_global_privileges[name] = def
end

centralauth.register_global_privilege("staff", {
    description = S("Operators of the server"),
    granted_by = { staff = true },
    revoked_by = { staff = true },
    self_revokable = true,
    root_access = true,
})

centralauth.register_global_privilege("globallock", {
    description = S("Apply global locks on accounts"),
    self_revokable = true,
})

centralauth.register_global_privilege("antispoof_init", {
    description = S("Can run /centralauth-antispoof-init"),
    self_revokable = true,
})
