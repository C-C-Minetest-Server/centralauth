-- centralauth/centralauth/src/db_api.lua
-- higher-level operation on the CentralAuth DB
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local _int = centralauth.internal
local logger = _int.logger:sublogger("db_api")
local _db = _int.database

local SERVER_ID = centralauth.settings.server_db_id

local function privilege_handler(ptype, func, field_name)
    return function(...)
        local res = func(...)

        if not res then
            logger:raise("Failed to get %s user privilege", ptype)
        end

        local privileges = {}
        for _, row in ipairs(res) do
            privileges[row[field_name]] = true
        end
        return privileges
    end
end

local function change_privilege_handler(ptype, wipe_func, add_func, privileges)
    local res = _int.query("BEGIN;")

    if not res then
        logger:raise("Failed to begin transaction")
    end

    res = wipe_func()

    if not res then
        _int.query("ROLLBACK;")
        logger:raise("Failed to wipe %s user privilege", ptype)
    end

    for privilege in pairs(privileges) do
        res = add_func(privilege)

        if not res then
            _int.query("ROLLBACK;")
            logger:raise("Failed to add %s user privilege", ptype)
        end
    end

    res = _int.query("COMMIT;")

    if not res then
        _int.query("ROLLBACK;")
        logger:raise("Failed to add %s user privilege", ptype)
    end
end

-- Global

local function global_user_data_handler(func)
    return function(...)
        local res = func(...)

        if not res or #res == 0 then
            return nil
        end

        local data = res[1]
        return {
            id = data.gu_id,
            name = data.gu_name,
            home_server = data.gu_home_server,
            email = data.gu_email,
            email_verified_on = data.gu_email_verified_on,
            password = data.gu_password,
            locked = data.gu_locked,
            locked_on = data.gu_locked_on,
            locked_by = data.gu_locked_by,
            locked_reason = data.gu_locked_reason,
            hidden_level = data.gu_hidden_level,
            created_at = data.gu_created_at,
            last_login = data.gu_last_login,
            last_login_on = data.gu_last_login_on,
            password_reset_key = data.gu_password_reset_key,
            password_reset_expiration = data.gu_password_reset_expiration,
        }
    end
end

centralauth.get_global_user_by_id = global_user_data_handler(_db.get_global_user_by_id)
centralauth.get_global_user_by_name = global_user_data_handler(_db.get_global_user_by_name)
centralauth.get_global_user_privilege_by_id =
    privilege_handler("global", _db.get_global_user_privilege_by_id, "gp_privilege")
centralauth.get_global_user_privilege_by_name =
    privilege_handler("global", _db.get_global_user_privilege_by_name, "gp_privilege")

centralauth.set_global_user_privilege = function(id, privileges)
    return change_privilege_handler(
        "global",
        function()
            return _db.wipe_global_user_privilege(id)
        end,
        function(privilege)
            return _db.add_global_user_privilege(id, privilege)
        end,
        privileges
    )
end

centralauth.get_user_names_by_normalized_name = function(name)
    assert(type(name) == "string")

    local res = _db.get_user_names_by_normalized_name(name)
    if not res then
        logger:raise("Failed to get users by normalized name")
    end

    local rtn = {}
    for _, row in ipairs(res) do
        table.insert(rtn, row.gu_name)
    end
    return rtn
end

centralauth.create_global_user = function(name, password, home_server)
    if not home_server then
        home_server = SERVER_ID
    end
    local res = _db.create_global_user(name, password, home_server)

    if not res then
        logger:raise("Failed to create global user")
    end

    return res[1].gu_id
end

centralauth.regenerate_antispoof_data = function()
    _int.postgres:settimeout()
    local res = _int.query("BEGIN;")
    if not res then
        _int.postgres:settimeout(2000)
        logger:raise("Failed to begin transaction")
    end

    local usernames_res = _db.get_all_global_user_names()
    if not usernames_res then
        _int.query("ROLLBACK;")
        _int.postgres:settimeout(2000)
        logger:raise("Failed to get all global user names")
    end

    for _, row in ipairs(usernames_res) do
        res = _db.write_antispoof_data(row.gu_name)
        if not res then
            _int.query("ROLLBACK;")
            _int.postgres:settimeout(2000)
            logger:raise("Failed to write antispoof data")
        end
    end

    res = _int.query("COMMIT;")
    if not res then
        _int.query("ROLLBACK;")
        _int.postgres:settimeout(2000)
        logger:raise("Failed to commit transaction")
    end

    _int.postgres:settimeout(2000)
end

centralauth.update_password = function(id, password)
    assert(type(id) == "number")
    assert(type(password) == "string")

    local res = _db.update_password(id, password)
    return res and true or false
end

centralauth.delete_auth_by_id = function(id)
    local res = _db.remove_auth_data_by_id(id)
    if not res then
        logger:raise("Failed to delete auth data")
    end
end

-- Deletion would cascade, deleting all auth data
centralauth.delete_auth_by_name = function(name)
    local res = _db.remove_auth_data_by_name(name)
    if not res then
        logger:raise("Failed to delete auth data")
    end
end

centralauth.lock_user = function(id, actor, reason)
    assert(type(id) == "number")
    assert(type(actor) == "number")
    assert(type(reason) == "string")

    local res = _db.lock_user(id, actor, reason)
    if not res then
        logger:raise("Failed to lock user")
    end
end

centralauth.unlock_user = function(id)
    assert(type(id) == "number")

    local res = _db.unlock_user(id)
    if not res then
        logger:raise("Failed to unlock user")
    end
end

-- Local

local function local_user_data_handler(func)
    return function(...)
        local res = func(...)

        if not res or #res == 0 then
            return nil
        end

        local data = res[1]
        return {
            id = data.lu_id,
            last_login = data.lu_last_login,
            created_at = data.lu_created_at,
        }
    end
end

centralauth.get_local_user_on_server_by_id = local_user_data_handler(_db.get_local_user_on_server_by_id)
centralauth.get_local_user_on_server_by_name = local_user_data_handler(_db.get_local_user_on_server_by_name)
centralauth.get_local_user_privilege_on_server_by_id =
    privilege_handler("local", _db.get_local_user_privilege_on_server_by_id, "lp_privilege")
centralauth.get_local_user_privilege_on_server_by_name =
    privilege_handler("local", _db.get_local_user_privilege_on_server_by_name, "lp_privilege")

centralauth.set_local_user_privilege_on_server = function(server_id, id, privileges)
    return change_privilege_handler(
        "local",
        function()
            return _db.wipe_local_user_privilege_on_server(server_id, id)
        end,
        function(privilege)
            return _db.add_local_user_privilege_on_server(server_id, id, privilege)
        end,
        privileges
    )
end

centralauth.create_local_user_on_server = function(server_id, name)
    local res = _db.create_local_user_on_server(server_id, name)

    if not res then
        logger:raise("Failed to create local user")
    end

    return res[1].lu_id
end

centralauth.iterate_all_global_user_names = function()
    local res = _db.get_all_global_user_names()
    if not res then
        logger:raise("Failed to get all global user names")
    end

    local i = 0
    return function()
        i = i + 1
        if res[i] then
            return res[i].gu_name
        end
    end
end

-- Cross-server

centralauth.write_auth_on = function(server_id, name, auth_data)
    local password = auth_data.password
    local last_login = auth_data.last_login

    local res = _int.query("BEGIN;")
    if not res then
        logger:raise("Failed to begin transaction")
    end

    res = _db.write_global_auth_data(name, password, last_login, server_id)
    if not res then
        _int.query("ROLLBACK;")
        logger:raise("Failed to write global auth data")
    end

    res = _db.write_local_auth_data(server_id, name, last_login)
    if not res then
        _int.query("ROLLBACK;")
        logger:raise("Failed to write local auth data")
    end

    res = _int.query("COMMIT;")
    if not res then
        _int.query("ROLLBACK;")
        logger:raise("Failed to write local auth data")
    end
end

-- This server specific

centralauth.get_local_user_by_id = function(id)
    return centralauth.get_local_user_on_server_by_id(SERVER_ID, id)
end
centralauth.get_local_user_by_name = function(name)
    return centralauth.get_local_user_on_server_by_name(SERVER_ID, name)
end
centralauth.get_local_user_privilege_by_id = function(id)
    return centralauth.get_local_user_privilege_on_server_by_id(SERVER_ID, id)
end
centralauth.get_local_user_privilege_by_name = function(name)
    return centralauth.get_local_user_privilege_on_server_by_name(SERVER_ID, name)
end
centralauth.set_local_user_privilege = function(id, privileges)
    return centralauth.set_local_user_privilege_on_server(SERVER_ID, id, privileges)
end
centralauth.create_local_user = function(id, password)
    return centralauth.create_local_user_on_server(SERVER_ID, id, password)
end
centralauth.write_auth = function(name, auth_data)
    return centralauth.write_auth_on(SERVER_ID, name, auth_data)
end

-- Logs

centralauth.write_log_on = function(log_type, action, server, actor, target, description, data)
    assert(type(log_type) == "string")
    assert(type(server) == "string")
    assert(type(action) == "string")
    assert(type(actor) == "number")
    assert(type(target) == "number")
    assert(type(description) == "string")

    local res = _db.write_log(log_type, action, server, actor, target, description, data)
    if not res or #res == 0 then
        return nil
    end
    return res[1].log_id
end

centralauth.write_log = function(log_type, action, actor, target, description, data)
    return centralauth.write_log_on(log_type, action, SERVER_ID, actor, target, description, data)
end

centralauth.get_logs = function(constraints)
    assert(type(constraints) == "table")

    local res = _db.get_logs(constraints)
    if not res then
        return {}
    end

    return res
end
