-- centralauth/centralauth/sql/server_init.sql
-- Per-server initilization SQL for CentralAuth
-- Copyright (C) 2025  1F616EMO
-- SPDX-License-Identifier: GPL-2.0-or-later

-- To run this per-server initilization SQL, replace all occurances of /* SERVERNAME */
-- with your server ID. Therefore, a server ID must be a valid SQL identifier.
-- The server ID must be unique across all servers.

CREATE table /* SERVERNAME */_local_user (
    lu_id INTEGER PRIMARY KEY,
    lu_last_login INTEGER NOT NULL DEFAULT -1,
    lu_created_at INTEGER,
    FOREIGN KEY (lu_id) REFERENCES global_user(gu_id) ON DELETE CASCADE
);

CREATE TABLE /* SERVERNAME */_local_user_privilege (
    lp_id INTEGER NOT NULL,
    lp_privilege VARCHAR(32) NOT NULL,
    PRIMARY KEY (lp_id, lp_privilege),
    FOREIGN KEY (lp_id) REFERENCES /* SERVERNAME */_local_user(lu_id) ON DELETE CASCADE
);
