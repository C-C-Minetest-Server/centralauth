-- centralauth/centralauth/src/chatcommands.lua
-- Suppliment operation on the CentralAuth DB
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local S = core.get_translator("centralauth")

local TAB = "  "
local TABTAB = TAB .. TAB
local TABTABTAB = TAB .. TAB .. TAB

core.register_chatcommand("centralauth", {
    description = S("Get global user information of a player or yourself"),
    params = S("[<name>|#<id>]"),
    func = function(name, target)
        local global_user
        if target == "" then
            global_user = centralauth.get_global_user_by_name(name)
        elseif target:sub(1, 1) == "#" then
            local target_id = tonumber(target:sub(2))
            global_user = centralauth.get_global_user_by_id(target_id)
        else
            global_user = centralauth.get_global_user_by_name(target)
        end

        if not global_user then
            return false, S("Global user not found for @1", target)
        end

        local global_privileges = centralauth.get_global_user_privilege_by_id(global_user.id)

        local msg = {}

        msg[#msg + 1] = S("Global user information of @1:", global_user.name)
        msg[#msg + 1] = TAB .. S("User ID: @1", global_user.id)
        msg[#msg + 1] = TAB .. S("Registered: @1",
            global_user.registered and os.date("%Y-%m-%d %H:%M:%S", global_user.registered) or S("no record"))
        msg[#msg + 1] = TAB .. S("Home server: @1", global_user.home_server)
        msg[#msg + 1] = TAB .. S("Last login (globally): @1 (on @2)",
            global_user.last_login and os.date("%Y-%m-%d %H:%M:%S", global_user.last_login) or S("no record"),
            global_user.last_login_on or S("no record"))

        if global_user.locked then
            local locked_by_global_user = centralauth.get_global_user_by_id(global_user.locked_by)
            msg[#msg + 1] = TAB .. S("Locked: Yes (by @1)", locked_by_global_user.name)
            msg[#msg + 1] = TAB .. S("Locked on: @1", os.date("%Y-%m-%d %H:%M:%S", global_user.locked_on))
            msg[#msg + 1] = TAB .. S("Lock reason: @1", global_user.locked_reason)
        else
            msg[#msg + 1] = TAB .. S("Locked: No")
        end

        msg[#msg+1] = TAB .. S("Local accounts:")

        for _, server_id in ipairs(centralauth.settings.server_list) do
            local local_user = centralauth.get_local_user_on_server_by_id(server_id, global_user.id)
            if local_user then
                local local_privs = centralauth.get_local_user_privilege_on_server_by_id(server_id, local_user.id)
                msg[#msg + 1] = TABTAB .. S("Server @1:", server_id)
                msg[#msg + 1] = TABTABTAB .. S("Last login: @1",
                    local_user.last_login and os.date("%Y-%m-%d %H:%M:%S", local_user.last_login) or S("no record"))
                local local_privs_list = {}
                for privilege in pairs(local_privs) do
                    local_privs_list[#local_privs_list + 1] = privilege
                end
                msg[#msg + 1] = TABTABTAB .. S("Privileges: @1", table.concat(local_privs_list, ", "))
            end
        end

        local privileges_list = {}
        for privilege in pairs(global_privileges) do
            privileges_list[#privileges_list + 1] = privilege
        end
        msg[#msg + 1] = TAB .. S("Global privileges: @1", table.concat(privileges_list, ", "))

        return true, table.concat(msg, "\n")
    end,
})

local function handle_grant_command(caller, grantname, grantprivstr)
    local target_global_user = centralauth.get_global_user_by_name(grantname)
    if not target_global_user then
        return false, S("Global user not found for @1", grantname)
    end

    local granter_user = centralauth.get_global_user_by_name(caller)
    if not granter_user then
        return false, S("Global user not found for @1", caller)
    end
    local granterprivs = centralauth.get_global_user_privilege_by_id(granter_user.id)
    local grantprivs = core.string_to_privs(grantprivstr)
    local privs = (caller == grantname)
        and table.copy(granterprivs)
        or centralauth.get_global_user_privilege_by_id(target_global_user.id)
    for priv in pairs(grantprivs) do
        local priv_def = centralauth.registered_global_privileges[priv]
        local can_grant = false

        for granter_priv in pairs(granterprivs) do
            local granter_priv_def = centralauth.registered_global_privileges[granter_priv]
            if (priv_def and priv_def.granted_by and priv_def.granted_by[granter_priv])
                or (granter_priv_def and granter_priv_def.root_access) then
                can_grant = true
                break
            end
        end

        if not can_grant then
            return false, priv_def and priv_def.granted_by
                and S("You cannot grant @1 to other players. " ..
                    "Players with any of the following privileges can grant it: @2",
                    priv, core.privs_to_string(priv_def.granted_by))
                or S("You cannot grant @1 to other players. Only the staffs can grant this privilege.", priv)
        end

        privs[priv] = true
    end

    centralauth.set_global_user_privilege(target_global_user.id, privs)
    centralauth.write_log("globalprivs", "grant", granter_user.id, target_global_user.id, "", {
        granted = grantprivs,
        revoked = {},
    })
    return true, S("Granted @1 to @2", core.privs_to_string(grantprivs), target_global_user.name)
end

core.register_chatcommand("grantglobal", {
    description = S("Grant global privileges to a player"),
    params = S("<name> (<privilege> [, <privilege2> [<...>]])"),
    func = function(name, param)
        local grantname, grantprivstr = string.match(param, "([^ ]+) (.+)")
        if not grantname or not grantprivstr then
            return false, S("Invalid parameters (see /help grant).")
        end
        return handle_grant_command(name, grantname, grantprivstr)
    end,
})

core.register_chatcommand("grantmeglobal", {
    description = S("Grant global privileges to yoursellf"),
    params = S("<privilege> [, <privilege2> [<...>]]"),
    func = function(name, param)
        if param == "" then
            return false
        end
        return handle_grant_command(name, name, param)
    end,
})

local function handle_revoke_command(caller, revokename, revokeprivstr)
    local target_global_user = centralauth.get_global_user_by_name(revokename)
    if not target_global_user then
        return false, S("Global user not found for @1", revokename)
    end

    local revoker_user = centralauth.get_global_user_by_name(caller)
    if not revoker_user then
        return false, S("Global user not found for @1", caller)
    end
    local revokerprivs = centralauth.get_global_user_privilege_by_id(revoker_user.id)
    local revokeprivs = core.string_to_privs(revokeprivstr)
    local privs = (caller == revokename)
        and table.copy(revokerprivs)
        or centralauth.get_global_user_privilege_by_id(target_global_user.id)
    for priv in pairs(revokeprivs) do
        local priv_def = centralauth.registered_global_privileges[priv]
        local can_revoke = false

        if priv_def and priv_def.self_revokable and caller == revokename then
            can_revoke = true
        else
            for revoker_priv in pairs(revokerprivs) do
                local revoker_priv_def = centralauth.registered_global_privileges[revoker_priv]
                if (priv_def and priv_def.revoked_by and priv_def.revoked_by[revoker_priv])
                    or (revoker_priv_def and revoker_priv_def.root_access) then
                    can_revoke = true
                    break
                end
            end
        end

        if not can_revoke then
            return false, priv_def and priv_def.revoked_by
                and S("You cannot revoke @1 from other players. " ..
                    "Players with any of the following privileges can revoke it: @2",
                    priv, core.privs_to_string(priv_def.revoked_by))
                or S("You cannot revoke @1 from other players. Only the staffs can revoke this privilege.", priv)
        end

        privs[priv] = nil
    end

    if caller == revokename then
        centralauth.write_log("globalprivs", "revoke", revoker_user.id, target_global_user.id, "", {
            granted = {},
            revoked = revokeprivs,
        })
    end
    centralauth.set_global_user_privilege(target_global_user.id, privs)
    return true, S("Revoked @1 from @2", core.privs_to_string(revokeprivs), target_global_user.name)
end

core.register_chatcommand("revokeglobal", {
    description = S("Revoke global privileges from a player"),
    params = S("<name> (<privilege> [, <privilege2> [<...>]])"),
    func = function(name, param)
        local revokename, revokeprivstr = string.match(param, "([^ ]+) (.+)")
        if not revokename or not revokeprivstr then
            return false, S("Invalid parameters (see /help revoke).")
        end
        return handle_revoke_command(name, revokename, revokeprivstr)
    end,
})

core.register_chatcommand("revokemeglobal", {
    description = S("Revoke global privileges from yourself"),
    params = S("<privilege> [, <privilege2> [<...>]]"),
    func = function(name, param)
        if param == "" then
            return false
        end
        return handle_revoke_command(name, name, param)
    end,
})

core.register_chatcommand("globallock", {
    description = S("Globally lock or unlock an account"),
    params = S("(lock|unlock) <username> [<reason>]"),
    func = function(name, params)
        local operation, target_name, reason = string.match(params, "(%S+) (%S+) ?(.*)")
        if not operation or not target_name then
            return false
        end

        local operator_global_user = centralauth.get_global_user_by_name(name)
        if not operator_global_user then
            return false, S("Global user not found for @1", name)
        end
        local operator_global_privs = centralauth.get_global_user_privilege_by_id(operator_global_user.id)
        if not operator_global_privs.globallock then
            return false, S("You do not have permission to use this command.")
        end

        local target_global_user = centralauth.get_global_user_by_name(target_name)
        if not target_global_user then
            return false, S("Global user not found for @1", target_name)
        end

        if operation == "lock" then
            if target_global_user.locked then
                return false, S("User @1 is already locked.", target_name)
            end

            centralauth.lock_user(target_global_user.id, operator_global_user.id, reason)
            centralauth.write_log("globallock", "lock", operator_global_user.id, target_global_user.id,
                reason or "", {})

            return true, S("User @1 has been locked.", target_name)
        elseif operation == "unlock" then
            if not target_global_user.locked then
                return false, S("User @1 is not locked.", target_name)
            end

            centralauth.unlock_user(target_global_user.id, operator_global_user.id)
            centralauth.write_log("globallock", "unlock", operator_global_user.id, target_global_user.id,
                reason or "", {})

            return true, S("User @1 has been unlocked.", target_name)
        else
            return false
        end
    end,
})

core.register_chatcommand("centralauth-antispoof-init", {
    description = S("Regenerate AntiSpoof data"),
    func = function(name)
        local operator_global_user = centralauth.get_global_user_by_name(name)
        if not operator_global_user then
            return false, S("Global user not found for @1", name)
        end
        local operator_global_privs = centralauth.get_global_user_privilege_by_id(operator_global_user.id)
        if not operator_global_privs.antispoof_init then
            return false, S("You do not have permission to use this command.")
        end

        core.chat_send_all(S("Regenerating AntiSpoof data, expect lag.."))
        centralauth.regenerate_antispoof_data()
        core.chat_send_all(S("AntiSpoof data regenerated."))
        return true
    end,
})

-- Check logs
core.register_chatcommand("centralauth-logs", {
    description = S("View CentralAuth logs"),
    func = function()
        local rtn = {}
        for _, log in ipairs(centralauth.get_logs({})) do
            local log_type = log.type
            local log_action = log.action
            local actor_name = log.actor_name
            local target_name = log.target_name
            local description = log.description
            local timestamp = os.date("%Y-%m-%d %H:%M:%S", log.timestamp)

            table.insert(rtn, string.format(
                "%s: %s by %s on %s (%s) - %s",
                log_type, log_action, actor_name, target_name, timestamp, description))
        end
        if #rtn == 0 then
            return false, S("No logs found.")
        end
        return true, table.concat(rtn, "\n")
    end,
})