-- centralauth/centralauth/src/antispoof.lua
-- Prevent users from registering accounts with names like another
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

local _as = {}
centralauth.antispoof = _as

-- Change this value every time the table below updates,
-- or the implentation of _as.normalize changes.
_as.flattern_map_ver = "1"

-- Usernames are all first converted to uppercase
-- Therefore, the sources and destinations should be uppercase.
_as.flattern_map = {
    ["0"] = "O",
    ["Q"] = "O",
    ["9"] = "O", -- 9 -> Q -> O

    ["1"] = "I",
    ["L"] = "I",

    ["2"] = "Z",

    ["5"] = "S",

    ["_"] = "",
    ["-"] = "",

    ["V"] = "U",
}

function _as.normalize(name)
    name = string.upper(name)

    -- Apply the flattern map
    for src, dst in pairs(_as.flattern_map) do
        name = string.gsub(name, src, dst)
    end

    return name
end