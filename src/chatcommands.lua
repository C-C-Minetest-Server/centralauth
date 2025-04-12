-- centralauth/src/chatcommands.lua
-- Suppliment operation on the CentralAuth DB
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local S = core.get_translator("centralauth")

local TAB = "    "

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

        msg[#msg + 1] = S("Global user information for @1:", global_user.name)
        msg[#msg + 1] = TAB .. S("User ID: @1", global_user.id)
        msg[#msg + 1] = TAB .. S("Registered: @1", os.date("%Y-%m-%d %H:%M:%S", global_user.registered))
        msg[#msg + 1] = TAB .. S("Home server: @1", global_user.home_server)
        msg[#msg + 1] = TAB .. S("Last login (globally): @1 (on @2)",
            os.date("%Y-%m-%d %H:%M:%S", global_user.last_login), global_user.last_login_on)

        if global_user.locked then
            msg[#msg + 1] = TAB .. S("Locked: Yes (by @1)", global_user.locked_by)
            msg[#msg + 1] = TAB .. S("Lock reason: @1", global_user.locked_reason)
        else
            msg[#msg + 1] = TAB .. S("Locked: No")
        end

        local privileges_list = {}
        for privilege in pairs(global_privileges) do
            privileges_list[#privileges_list + 1] = privilege
        end
        msg[#msg + 1] = TAB .. S("Globall privileges: @1", table.concat(privileges_list, ", "))

        return true, table.concat(msg, "\n")
    end,
})

local function handle_grant_command(caller, grantname, grantprivstr)
    local target_global_user = centralauth.get_global_user_by_name(grantname)
    if not target_global_user then
        return false, S("Global user not found for @1", grantname)
    end

    local granterprivs = centralauth.get_global_user_privilege_by_name(caller) or {}
    local grantprivs = core.string_to_privs(grantprivstr)
    local privs = (caller == grantname)
        and table.copy(granterprivs)
        or centralauth.get_global_user_privilege_by_id(target_global_user.id)
    for priv in pairs(grantprivs) do
        local priv_def = centralauth.registered_global_privileges[priv]
        local can_grant = false

        if priv_def and priv_def.granted_by then
            for granter_priv in pairs(granterprivs) do
                local granter_priv_def = centralauth.registered_global_privileges[granter_priv]
                if priv_def.granted_by[granter_priv] or granter_priv_def.root_access then
                    can_grant = true
                    break
                end
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

    local revokerprivs = centralauth.get_global_user_privilege_by_name(caller) or {}
    local revokeprivs = core.string_to_privs(revokeprivstr)
    local privs = (caller == revokename)
        and table.copy(revokerprivs)
        or centralauth.get_global_user_privilege_by_id(target_global_user.id)
    for priv in pairs(revokeprivs) do
        local priv_def = centralauth.registered_global_privileges[priv]
        local can_revoke = false

        if priv_def and priv_def.self_revokable and caller == revokename then
            can_revoke = true
        elseif priv_def and priv_def.revoked_by then
            for revoker_priv in pairs(revokerprivs) do
                local revoker_priv_def = centralauth.registered_global_privileges[revoker_priv]
                if priv_def.revoked_by[revoker_priv] or revoker_priv_def.root_access then
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
