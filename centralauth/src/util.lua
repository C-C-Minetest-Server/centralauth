-- centralauth/centralauth/src/util.lua
-- Utility functions
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local S = core.get_translator("centralauth")

function centralauth.stringify_last_login(last_login)
    if last_login == nil then
        return S("no record")
    elseif last_login == -1 then
        return S("never")
    else
        return os.date("%Y-%m-%d %H:%M:%S", last_login)
    end
end
