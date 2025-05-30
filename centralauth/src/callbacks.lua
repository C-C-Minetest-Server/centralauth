-- centralauth/centralauth/src/callbacks.lua
-- Callbacks
-- Copyright (C) 2024  1F616EMO
-- SPDX-License-Identifier: GPL-3.0-or-later

core.register_on_prejoinplayer(function(name)
    local global_player = centralauth.get_global_user_by_name(name)
    if not global_player then
        if centralauth.settings.block_new_accounts then
            return centralauth.settings.block_new_accounts_reason
        end

        local normalized = centralauth.antispoof.normalize(name)
        local antispoof_names = centralauth.get_user_names_by_normalized_name(normalized)
        if #antispoof_names > 0 then
            return string.format(
                "Your username is too similar to the following existing username: %s",
                table.concat(antispoof_names, ", "))
        end
    elseif global_player.locked then
        local locked_by_player = centralauth.get_global_user_by_id(global_player.locked_by)
        local locked_on_string = os.date("%Y-%m-%d %H:%M:%S", global_player.locked_on)
        local locked_by_name = locked_by_player and locked_by_player.name or "#" .. global_player.locked_by
        local locked_reason = global_player.locked_reason or "No reason given."

        return string.format(centralauth.settings.global_lock_message,
            locked_by_name, locked_on_string, locked_reason)
    end
end)
