-- centralauth/centralauth/sql/init.sql
-- Database initilization SQL for CentralAuth
-- Copyright (C) 2025  1F616EMO
-- SPDX-License-Identifier: GPL-2.0-or-later

/**
 * Store the main reference to a global user.
 */
CREATE TABLE global_user (
    gu_id SERIAL PRIMARY KEY,
    gu_name VARCHAR(20) NOT NULL UNIQUE,
    gu_name_normalized VARCHAR(20),
    gu_home_server VARCHAR(255),
    gu_email VARCHAR(255),
    gu_email_verified_on INTEGER,
    gu_password TEXT NOT NULL,
    gu_locked BOOLEAN DEFAULT FALSE,
    gu_locked_on INTEGER,
    gu_locked_by INTEGER,
    gu_locked_reason VARCHAR(255),
    gu_hidden_level SMALLINT DEFAULT 0,
    gu_registered_at INTEGER,
    gu_last_login INTEGER,
    gu_last_login_on VARCHAR(255),
    gu_password_reset_key VARCHAR(255),
    gu_password_reset_expiration INTEGER
);

/**
 * List all global user privilege.
 * These privilege are not used via built-in privilege system,
 * but are instead controlled by the CentralAuth mod.
 */
CREATE TABLE global_user_privilege (
    gp_id INTEGER NOT NULL,
    gp_privilege VARCHAR(32) NOT NULL,
    PRIMARY KEY (gp_id, gp_privilege),
    FOREIGN KEY (gp_id) REFERENCES global_user(gu_id) ON DELETE CASCADE
);

/**
 * Store logs of all global user actions.
 */
CREATE TABLE global_user_log (
    log_id BIGSERIAL PRIMARY KEY,
    log_type VARCHAR(32) NOT NULL,
    log_action VARCHAR(32) NOT NULL,
    log_timestamp INTEGER NOT NULL,
    log_server VARCHAR(255),
    log_actor INTEGER,
    log_target INTEGER,
    log_description TEXT NOT NULL DEFAULT '',
    log_data TEXT NOT NULL DEFAULT 'null',
    log_hidden_level SMALLINT DEFAULT 0,

    FOREIGN KEY (log_actor) REFERENCES global_user(gu_id) ON DELETE SET NULL,
    FOREIGN KEY (log_target) REFERENCES global_user(gu_id) ON DELETE SET NULL
);