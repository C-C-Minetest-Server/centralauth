-- centralauth/centralauth/sql/migrate.sql
-- Migrate an existing PostgreSQL-backed Luanti server to CentralAuth
-- Copyright (C) 2025  1F616EMO
-- SPDX-License-Identifier: GPL-2.0-or-later

/**
 * What this SQL can do:
 *  1. Move existing players on a server into the CentralAuth system, along with their privileges
 *     i.e. populating the CentralAuth database with players from the server
 *  2. Merge two servers that usernames were strictly synced manually.
 *     In this case, run this migration SQl on one server, then directly hook the another
 *     server to the CentralAuth system without migrating anything. You will have to restore the
 *     privileges manually.
 *  3. Forcefully merge a server into the CentralAuth system if you don't mine
 *     losing all authentication data on the server.
 * 
 * What this SQL CANNOT do:
 *  1. Merge two distinct traditionally-authed servers into the same CentralAuth system.
 *     This is impossible due to the lack of player renaming protocol within Luanti.
 *  2. Migrate a server that is not using PostgreSQL as the backend, 
 *     or not in the same database as the CentralAuth tables.
 *     Migrate the server to PostgresSQL and move the data into the same database before you proceed.
 */

-- Before you proceed, replace /* SERVERNAME */ with the server ID you want to migrate,
-- or the script will fail.

/*

Just keep in mind the structure of the original tables are as follows:

CREATE TABLE auth (
	id SERIAL,
	name TEXT UNIQUE,
	password TEXT,
	last_login INT NOT NULL DEFAULT 0,
	PRIMARY KEY (id)
);

CREATE TABLE user_privileges (
	id INT,
	privilege TEXT,
	PRIMARY KEY (id, privilege),
	CONSTRAINT fk_id FOREIGN KEY (id) REFERENCES auth (id) ON DELETE CASCADE
);

*/

-- Create a global user for each user in auth.
INSERT INTO global_user (gu_name, gu_password, gu_last_login, gu_last_login_on, gu_home_server)
SELECT name, password, last_login, '/* SERVERNAME */', '/* SERVERNAME */'
FROM auth;

-- Create a local user for each user in auth.
INSERT INTO /* SERVERNAME */_local_user (lu_id, lu_last_login)
SELECT gu.gu_id, last_login
FROM auth, global_user gu
WHERE gu.gu_name = auth.name;

-- Move local user privileges
INSERT INTO /* SERVERNAME */_local_user_privilege (lp_id, lp_privilege)
SELECT gu.gu_id, privilege
FROM user_privileges, global_user gu, auth
WHERE user_privileges.id = auth.id AND gu.gu_name = auth.name;
