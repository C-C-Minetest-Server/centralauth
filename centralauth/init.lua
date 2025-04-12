-- centralauth/centralauth/init.lua
-- Player account unification across Luanti servers
-- Copyright (C) 2025  1F616EMO
-- SPDX-License-Identifier: GPL-2.0-or-later

centralauth = {}
centralauth.internal = {}
centralauth.internal.logger = logging.logger("centralauth")

if core.is_singleplayer() then
    centralauth.internal.logger:raise("CentralAuth cannot be used in singleplayer.")
end

-- Read settings
local settings = {}
settings.pg_connection = core.settings:get("centralauth_pg_connection")
settings.server_db_id = core.settings:get("centralauth_server_db_id")
settings.global_lock_message = core.settings:get("centralauth_global_lock_message")
	or "This account is globally locked by %s on %s. You will not be able to log in to any Luanti servers in " ..
		"this CentralAuth system. Please contact the server administrators if you have any questions. " ..
		"The reason given is: %s"
settings.server_list = core.settings:get("centralauth_server_list")

if not settings.pg_connection then
    centralauth.internal.logger:raise("Missing setting `centralauth_pg_connection`.")
elseif not settings.server_db_id then
    centralauth.internal.logger:raise("Missing setting `centralauth_server_db_id`.")
end

if not settings.server_list then
	centralauth.internal.logger:warning("Missing setting `centralauth_server_list`. " ..
		"/centralauth and other operations with not show cross-server data.")
	settings.server_list = settings.server_db_id
end

settings.server_list = string.split(settings.server_list)
for i, v in ipairs(settings.server_list) do
	settings.server_list[i] = string.trim(v)
end

-- Set up insecure environment

local insecure = core.request_insecure_environment()
if not insecure then
	centralauth.internal.logger:raise("Please add `centralauth` into secure.trusted_mods.")
end

centralauth.settings = setmetatable({}, {
    __index = function(_, k)
        return settings[k]
    end,
    __newindex = function()
        centralauth.internal.logger:raise("Attempt to modify read-only settings.")
    end,
})

function centralauth.internal.func_with_IE_env(func, ...)
	-- be sure that there is no hook, otherwise one could get IE via getfenv
	insecure.debug.sethook()

	local old_thread_env = insecure.getfenv(0)
	local old_string_metatable = insecure.debug.getmetatable("")

	-- set env of thread
	-- (the loader used by insecure.require will probably use the thread env for
	-- the loaded functions)
	insecure.setfenv(0, insecure)

	-- also set the string metatable because the lib might use it while loading
	-- (actually, we probably have to do this every time we call a `require()`d
	-- function, but for performance reasons we only do it if the function
	-- uses the string metatable)
	-- (Maybe it would make sense to set the string metatable __index field
	-- to a function that grabs the string table from the thread env.)
	insecure.debug.setmetatable("", { __index = insecure.string })

	-- (insecure.require's env is neither _G, nor insecure. we need to leave it like this,
	-- otherwise it won't find the loaders (it uses the global `loaders`, not
	-- `package.loaders` btw. (see luajit/src/lib_package.c)))

	-- we might be pcall()ed, so we need to pcall to make sure that we reset
	-- the thread env afterwards
	local ok, ret = insecure.pcall(func, ...)

	-- reset env of thread
	insecure.setfenv(0, old_thread_env)

	-- also reset the string metatable
	insecure.debug.setmetatable("", old_string_metatable)

	if not ok then
		insecure.error(ret)
	end
	return ret
end

-- luacheck: ignore 211
local ngx = nil

---@module 'pgmoon'
centralauth.internal.pgmoon = centralauth.internal.func_with_IE_env(insecure.require, "pgmoon")

local MP = core.get_modpath("centralauth")
for _, name in ipairs({
	"antispoof",
	"db",
    "db_api",
    "auth_backend",
	"callbacks",
	"api",
	"chatcommands",
}) do
	dofile(MP .. DIR_DELIM .. "src" .. DIR_DELIM .. name .. ".lua")
end

centralauth.internal = nil