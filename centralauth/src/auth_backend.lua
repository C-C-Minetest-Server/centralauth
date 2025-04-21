-- centralauth/centralauth/src/db_api.lua
-- higher-level operation on the CentralAuth DB
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local _int = centralauth.internal
local logger = _int.logger:sublogger("auth_backend")
local SERVER_ID = centralauth.settings.server_db_id

local auth = {}
function auth.get_auth(name)
    assert(type(name) == "string")

    -- Not having a global user is fatal here
    local global_user = centralauth.get_global_user_by_name(name)
    if not global_user then
        return nil
    end

    local user_data = {
        password = global_user.password,
    }

    local privs_changed = false

    -- If no local user, create immediately
    local local_user = centralauth.get_local_user_by_id(global_user.id)
    if local_user then
        user_data.last_login = local_user.last_login
        user_data.privileges = centralauth.get_local_user_privilege_by_id(global_user.id)
    else
        user_data.last_login = -1
        user_data.privileges = core.string_to_privs(core.settings:get("default_privs"))
        centralauth.create_local_user(global_user.id)
        privs_changed = true
        centralauth.write_log("newusers", "autocreateaccount", global_user.id, global_user.id, "", nil)
        centralauth.write_log("globalprivs", "autogrant", global_user.id, global_user.id, "", {
            granted = table.copy(user_data.privileges),
            revoked = {},
        })
    end

    local old_privileges = table.copy(user_data.privileges)

    if name == core.settings:get("name") then
        -- For the admin, give everything
        -- We don't have to care about singleplayer as that's banned
        for priv, def in pairs(core.registered_privileges) do
            if def.give_to_admin then
                user_data.privileges[priv] = true
            end
        end
    end

    local global_privs = centralauth.get_global_user_privilege_by_id(global_user.id)
    for priv in pairs(global_privs) do
        if centralauth.registered_global_privileges[priv]
            and centralauth.registered_global_privileges[priv].root_access then
            user_data.privileges.privs = true
            break
        end
    end

    local granted_privs = {}
    for priv, value in pairs(user_data.privileges) do
        if value and not old_privileges[priv] then
            granted_privs[priv] = true
        end
    end

    if next(granted_privs) then
        centralauth.write_log("globalprivs", "autogrant", global_user.id, global_user.id, "", {
            granted = granted_privs,
            revoked = {},
        })
        privs_changed = true
    end

    if privs_changed then
        centralauth.set_local_user_privilege(global_user.id, user_data.privileges)
    end

    return user_data
end

function auth.create_auth(name, password)
    assert(type(name) == "string")
    assert(type(password) == "string")

    logger:info("CentralAuth adding player '%s'", name)

    -- Get global user, and if not exist, create one
    local global_user = centralauth.get_global_user_by_name(name)
    if not global_user then
        local global_user_id = centralauth.create_global_user(name, password, SERVER_ID)
        global_user = centralauth.get_global_user_by_id(global_user_id)

        if not global_user then
            logger:raise("Failed to create global user '%s'", name)
        end
    end

    local privileges = core.string_to_privs(core.settings:get("default_privs"))
    centralauth.create_local_user(global_user.id, password)
    centralauth.set_local_user_privilege(global_user.id, privileges)
    centralauth.write_log("globalprivs", "autogrant", global_user.id, global_user.id, "", {
        granted = privileges,
        revoked = {},
    })

    centralauth.write_log("newusers", "createaccount", global_user.id, global_user.id, "", nil)
end

function auth.delete_auth(name)
    assert(type(name) == "string")

    local global_user = centralauth.get_global_user_by_name(name)
    if not global_user then
        return nil
    end

    logger:info("CentralAuth deleting player '%s'", name)
    centralauth.delete_auth_by_id(global_user.id)
end

function auth.set_password(name, password)
    assert(type(name) == "string")
    assert(type(password) == "string")

    local global_user = centralauth.get_global_user_by_name(name)
    if not global_user then
        return auth.create_auth(name, password)
    end

    logger:info("CentralAuth setting password for player '%s'", name)
    return centralauth.update_password(global_user.id, password)
end

function auth.set_privileges(name, privileges)
    assert(type(name) == "string")
    assert(type(privileges) == "table")

    local global_user = centralauth.get_global_user_by_name(name)
    if not global_user then
        return nil
    end

    local prev_privs = centralauth.get_local_user_privilege_by_id(global_user.id)
    centralauth.set_local_user_privilege(global_user.id, privileges)

    for priv, value in pairs(privileges) do
        -- Warnings for improper API usage
        if value == false then
            logger:deprecated("`false` value given to `core.set_player_privs`, " ..
                "this is almost certainly a bug, " ..
                "granting a privilege rather than revoking it")
        elseif value ~= true then
            logger:deprecated("non-`true` value given to `core.set_player_privs`")
        end
        -- Run grant callbacks
        if prev_privs[priv] == nil then
            core.run_priv_callbacks(name, priv, nil, "grant")
        end
    end

    -- Run revoke callbacks
    for priv, _ in pairs(prev_privs) do
        if privileges[priv] == nil then
            core.run_priv_callbacks(name, priv, nil, "revoke")
        end
    end
    core.notify_authentication_modified(name)
end

function auth.reload()
    -- Hmm, no-op.
    return true
end

function auth.record_login(name)
    assert(type(name) == "string")

    local auth_data = auth.get_auth(name)
    if not auth_data then
        return nil
    end

    auth_data.last_login = os.time()
    centralauth.write_auth(name, auth_data)
end

auth.iterate = centralauth.iterate_all_global_user_names

core.register_authentication_handler(auth)
