-- centralauth/src/callbacks.lua
-- Callbacks
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

core.register_on_prejoinplayer(function(name)
    local global_player = centralauth.get_global_user_by_name(name)
    if global_player and global_player.locked then
        local locked_by_player = centralauth.get_global_user_by_id(global_player.locked_by)
        local locked_on_string = os.date("%Y-%m-%d %H:%M:%S", global_player.locked_on)
        local locked_by_name = locked_by_player and locked_by_player.name or "#" .. global_player.locked_by
        local locked_reason = global_player.locked_reason or "No reason given."

        return string.format(centralauth.settings.global_lock_message,
            locked_by_name, locked_on_string, locked_reason)
    end
end)