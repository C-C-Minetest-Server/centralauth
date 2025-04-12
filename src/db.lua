-- centralauth/src/db.lua
-- Connect to the PostgreSQL database
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local _int = centralauth.internal
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

function _db.create_global_user(name, password, home_server)
    return _int.query(f(
        "INSERT INTO global_user (gu_name, gu_password, gu_registered_at, gu_home_server) " ..
        "VALUES (%s, %s, %d, %s) RETURNING gu_id",
        e(name), e(password), os.time(), e(home_server)
    ))
end

function _db.write_global_auth_data(name, password, last_login, last_login_on)
    return _int.query(f(
        "UPDATE global_user " ..
        "SET gu_name = %s, gu_password = %s, gu_last_login = %d, gu_last_login_on = %s " ..
        "WHERE gu_name = %s",
        e(name), e(password), last_login, e(last_login_on), e(name)
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

function _db.get_all_global_user_names()
    return _int.query("SELECT gu_name FROM global_user")
end

-- Local users

function _db.get_local_user_on_server_by_id(server_id, id)
    return _int.query(f(
        "SELECT * FROM %s_local_user " ..
        "WHERE lu_id = %d",
        server_id, id
    ))
end

function _db.get_local_user_on_server_by_name(server_id, name)
    return _int.query(f(
        "SELECT lu.* FROM %s_local_user lu " ..
        "JOIN global_user gu ON lu.lu_id = gu.id " ..
        "WHERE gu.name = %s",
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
    print(server_id, id, privilege)
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