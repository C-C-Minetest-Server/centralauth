-- centralauth/antispoof/init.lua
-- Expose AntiSpoof functions into the globall table
-- Copyright (C) 2025  1F616EMO
-- SPDX-License-Identifier: GPL-2.0-or-later

antispoof = {}
local _as = antispoof
local _cas = centralauth.antispoof

_as.normalize = _cas.normalize

function _as.check_username(name)
    local nname = _as.normalize(name)
    return centralauth.get_user_names_by_normalized_name(nname)
end
