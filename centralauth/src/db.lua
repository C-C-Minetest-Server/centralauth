-- centralauth/centralauth/src/db.lua
-- Connect to the PostgreSQL database
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local _int = centralauth.internal
local _as = centralauth.antispoof
local logger = _int.logger:sublogger("db")
local pgmoon = _int.pgmoon
local f = string.format

local conn_options = {}
for key, value in string.gmatch(centralauth.settings.pg_connection, "(%w+)=([^%s]+)") do
    conn_options[key] = value
end

local postgres = _int.func_with_IE_env(pgmoon.new, conn_options)
_int.postgres = postgres

function _int.query(...)
    return _int.func_with_IE_env(postgres.query, postgres, ...)
end

do
    local success, err = _int.func_with_IE_env(postgres.connect, postgres)
    if not success then
        logger:raise("Connect to database failed: %s", err)
    end
end

local function e(...)
    return postgres:escape_literal(...)
end

postgres:settimeout(2000) -- 2 seconds

---Methods that directly read/write the database
---Use methods with caching capability whenever possible
---@class centralauth.internal.database table
local _db = {}
_int.database = _db

-- Global user operations

function _db.get_global_user_by_id(id)
    return _int.query(f("SELECT * FROM global_user WHERE gu_id = %d", id))
end

function _db.get_global_user_by_name(name)
    return _int.query(f("SELECT * FROM global_user WHERE gu_name = %s", e(name)))
end

function _db.get_global_user_privilege_by_id(id)
    return _int.query(f("SELECT * FROM global_user_privilege WHERE gp_id = %d", id))
end

function _db.get_global_user_privilege_by_name(name)
    return _int.query(f(
        "SELECT gp.* FROM global_user_privilege gp " ..
        "JOIN global_user gu ON gp.gp_id = gu.gu_id " ..
        "WHERE gu.gu_name = %s",
        e(name)
    ))
end

function _db.wipe_global_user_privilege(id)
    return _int.query(f(
        "DELETE FROM global_user_privilege " ..
        "WHERE gp_id = %d",
        id
    ))
end

function _db.add_global_user_privilege(id, privilege)
    return _int.query(f(
        "INSERT INTO global_user_privilege (gp_id, gp_privilege) " ..
        "VALUES (%d, %s)",
        id, e(privilege)
    ))
end

function _db.get_user_names_by_normalized_name(normalized)
    return _int.query(f(
        "SELECT gu_name FROM global_user " ..
        "WHERE gu_name_normalized = %s",
        e(normalized)
    ))
end

function _db.create_global_user(name, password, home_server)
    return _int.query(f(
        "INSERT INTO global_user (gu_name, gu_name_normalized, gu_password, gu_registered_at, gu_home_server) " ..
        "VALUES (%s, %s, %s, %d, %s) RETURNING gu_id",
        e(name), e(_as.normalize(name)), e(password), os.time(), e(home_server)
    ))
end

function _db.write_antispoof_data(name)
    return _int.query(f(
        "UPDATE global_user " ..
        "SET gu_name_normalized = %s " ..
        "WHERE gu_name = %s",
        e(_as.normalize(name)), e(name)
    ))
end

function _db.write_global_auth_data(name, password, last_login, last_login_on)
    return _int.query(f(
        "UPDATE global_user " ..
        "SET gu_password = %s, gu_last_login = %d, gu_last_login_on = %s " ..
        "WHERE gu_name = %s",
        e(password), last_login, e(last_login_on), e(name)
    ))
end

function _db.update_password(id, password)
    return _int.query(f(
        "UPDATE global_user " ..
        "SET gu_password = %s " ..
        "WHERE gu_id = %d",
        e(password), id
    ))
end

function _db.remove_auth_data_by_id(id)
    return _int.query(f(
        "DELETE FROM global_user " ..
        "WHERE gu_id = %d",
        id
    ))
end

function _db.remove_auth_data_by_name(name)
    return _int.query(f(
        "DELETE FROM global_user " ..
        "WHERE gu_name = %s",
        e(name)
    ))
end

function _db.lock_user(id, actor, reason)
    local locked_on = os.time()
    return _int.query(f(
        "UPDATE global_user " ..
        "SET gu_locked = true, gu_locked_on = %d, gu_locked_by = %d, gu_locked_reason = %s " ..
        "WHERE gu_id = %d",
        locked_on, actor, e(reason), id
    ))
end

function _db.unlock_user(id)
    return _int.query(f(
        "UPDATE global_user " ..
        "SET gu_locked = false, gu_locked_on = NULL, gu_locked_by = NULL, gu_locked_reason = NULL " ..
        "WHERE gu_id = %d",
        id
    ))
end

function _db.get_all_global_user_names()
    return _int.query("SELECT gu_name FROM global_user")
end

-- Local users

function _db.get_local_user_on_server_by_id(server_id, id)
    return _int.query(f(
        "SELECT lu.*, gu.gu_name FROM %s_local_user lu " ..
        "JOIN global_user gu ON lu.lu_id = gu.gu_id " ..
        "WHERE lu.lu_id = %d",
        server_id, id
    ))
end

function _db.get_local_user_on_server_by_name(server_id, name)
    return _int.query(f(
        "SELECT lu.*, gu.name FROM %s_local_user lu " ..
        "JOIN global_user gu ON lu.lu_id = gu.id " ..
        "WHERE gu.gu_name = %s",
        server_id, e(name)
    ))
end

function _db.get_local_user_privilege_on_server_by_id(server_id, id)
    return _int.query(f(
        "SELECT * FROM %s_local_user_privilege " ..
        "WHERE lp_id = %d",
        server_id, id
    ))
end

function _db.get_local_user_privilege_on_server_by_name(server_id, name)
    return _int.query(f(
        "SELECT lp.* FROM %s_local_user_privilege lp " ..
        "JOIN global_user gu ON lp.lp_id = gu.gu_id " ..
        "WHERE gu.gu_name = %s",
        server_id, e(name)
    ))
end

function _db.wipe_local_user_privilege_on_server(server_id, id)
    return _int.query(f(
        "DELETE FROM %s_local_user_privilege " ..
        "WHERE lp_id = %d",
        server_id, id
    ))
end

function _db.add_local_user_privilege_on_server(server_id, id, privilege)
    return _int.query(f(
        "INSERT INTO %s_local_user_privilege (lp_id, lp_privilege) " ..
        "VALUES (%d, %s)",
        server_id, id, e(privilege)
    ))
end

function _db.write_local_auth_data(server_id, name, last_login)
    return _int.query(f(
        "UPDATE %s_local_user " ..
        "SET lu_last_login = %d " ..
        "FROM global_user gu " ..
        "WHERE %s_local_user.lu_id = gu.gu_id AND gu.gu_name = %s",
        server_id, last_login, server_id, e(name)
    ))
end

function _db.create_local_user_on_server(server_id, id)
    return _int.query(f(
        "INSERT INTO %s_local_user (lu_id, lu_created_at) " ..
        "VALUES (%d, %d) RETURNING lu_id",
        server_id, id, os.time()
    ))
end

-- Log entries

function _db.write_log(log_type, action, server, actor, target, description, data)
    local timestamp = os.time()
    local data_json = core.write_json(data)
    return _int.query(f(
        "INSERT INTO global_user_log (log_type, log_action, log_server, log_actor, log_target, " ..
        "log_description, log_timestamp, log_data) " ..
        "VALUES (%s, %s, %s, %s, %s, %s, %d, %s)" ..
        "RETURNING log_id",
        e(log_type), e(action), e(server), e(actor), e(target), e(description), timestamp, e(data_json)
    ))
end

function _db.get_logs(constraints)
    local query = [[
        SELECT
            log_id as id,
            log_type as type,
            log_action as action,
            log_timestamp as timestamp,
            log_server as server,
            log_actor as actor,
            actor_user.gu_name as actor_name,
            log_target as target,
            target_user.gu_name as target_name,
            log_description as description,
            log_data as data,
            log_hidden_level as hidden_level
        FROM global_user_log, global_user actor_user, global_user target_user
        ]]

    -- WHERE clause constraints
    local constraints_sql = {}
    if constraints.type then
        constraints_sql[#constraints_sql + 1] = f("log_type = %s", e(constraints.type))
    end
    if constraints.action then
        constraints_sql[#constraints_sql + 1] = f("log_action = %s", e(constraints.action))
    end
    if constraints.timestart then
        constraints_sql[#constraints_sql + 1] = f("log_timestamp >= %d", constraints.timestart)
    end
    if constraints.timeend then
        constraints_sql[#constraints_sql + 1] = f("log_timestamp <= %d", constraints.timeend)
    end
    if constraints.server == false then
        constraints_sql[#constraints_sql + 1] = "log_server IS NULL"
    elseif constraints.server then
        constraints_sql[#constraints_sql + 1] = f("log_server = %s", e(constraints.server))
    end
    if constraints.actor then
        constraints_sql[#constraints_sql + 1] = f("log_actor = %d", constraints.actor)
    end
    if constraints.target then
        constraints_sql[#constraints_sql + 1] = f("log_target = %d", constraints.target)
    end
    if constraints.description_search then
        constraints_sql[#constraints_sql + 1] = f("log_description LIKE %%%s%%", e(constraints.description_search))
    end
    query = query .. " WHERE " .. table.concat(constraints_sql, " AND ")

    -- Select actor and target name
    query = query .. " actor_user.gu_id = log_actor AND target_user.gu_id = log_target"

    query = query .. " ORDER BY log_timestamp ASC"


    -- limit and offset
    query = query .. f(" LIMIT %d", constraints.limit or 50)
    if constraints.offset then
        query = query .. f(" OFFSET %d", constraints.offset)
    end

    return _int.query(query)
end
