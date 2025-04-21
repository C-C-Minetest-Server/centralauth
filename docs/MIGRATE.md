# CentralAuth Migration Guide

It is possible to migrate authentication data from one server onto the CentralAuth system.

## What migration can do

1. Move existing players on a server into the CentralAuth system, along with their privileges, i.e. populating the CentralAuth database with players from the server
2. Merge two servers that usernames were strictly synced manually.
    * In this case, run this migration SQL on one server, then directly hook the another server to the CentralAuth system without migrating anything. You will have to restore the privileges manually.
3. Forcefully merge a server into the CentralAuth system if you don't mind losing all authentication data on the server.

## What migration *can't* do

1. Merge two distinct traditionally-authed servers into the same CentralAuth system. This is impossible due to the lack of player renaming protocol within Luanti.
2. Migrate a server that is not using PostgreSQL as the backend, or not in the same database as the CentralAuth tables.
    * Migrate the server to PostgresSQL and move the data into the same database before you proceed.

## Step 1. Initialize the database

Follow step 1-2 on [`INSTALL.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/INSTALL.md) to create the global tables and local tables for the server to be migrated.

## Step 2. Run the migration script

Check [`migrate.sql`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/centralauth/sql/migrate.sql). Replace `/* SERVERNAME */` with your server's ID, which has to be a valid SQL table name, then run the modified SQL on the same database as the global tables.

For example, the SQLs of the server `survival` would look like this:

```sql
-- Create a global user for each user in auth.
INSERT INTO global_user (gu_name, gu_password, gu_last_login, gu_last_login_on, gu_home_server)
SELECT name, password, last_login, 'survival', 'survival'
FROM auth;

-- Create a local user for each user in auth.
INSERT INTO survival_local_user (lu_id, lu_last_login)
SELECT gu.gu_id, last_login
FROM auth, global_user gu
WHERE gu.gu_name = auth.name;

-- Move local user privileges
INSERT INTO survival_local_user_privilege (lp_id, lp_privilege)
SELECT gu.gu_id, privilege
FROM user_privileges, global_user gu, auth
WHERE user_privileges.id = auth.id AND gu.gu_name = auth.name;
```

## Step 3. Finish setting up the server

Follow step 4 and onwards on [`INSTALL.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/INSTALL.md) to finish setup on the migrated server.
