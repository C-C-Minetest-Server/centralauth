# CentralAuth Installation Guide

## Step 1. Create the database and global tables

Run [`init.sql`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/centralauth/sql/init.sql) on a PostgreSQL database the Luanti server would have access to. This creates the global user table, global user privileges table and the CentralAuth log table.

## Step 2. Create a server's local tables

Check [`server_init.sql`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/centralauth/sql/server_init.sql). Replace `/* SERVERNAME */` with your server's ID, which has to be a valid SQL table name, then run the modified SQL on the same database as the global tables.

For example, the local table creation SQLs of the server `survival` would look like this:

```sql
CREATE table survival_local_user (
    lu_id INTEGER PRIMARY KEY,
    lu_last_login INTEGER NOT NULL DEFAULT -1,
    lu_created_at INTEGER,
    FOREIGN KEY (lu_id) REFERENCES global_user(gu_id) ON DELETE CASCADE
);

CREATE TABLE survival_local_user_privilege (
    lp_id INTEGER NOT NULL,
    lp_privilege VARCHAR(32) NOT NULL,
    PRIMARY KEY (lp_id, lp_privilege),
    FOREIGN KEY (lp_id) REFERENCES survival_local_user(lu_id) ON DELETE CASCADE
);
```

## Step 3a. Migrate existing users

If you want to add an existing server (which has existing users) to this newly created CentralAuth system, follow the instructions in [`MIGRATE.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/MIGRATE.md). Check that documentation file for the steps and limitations.

## Step 3b. Grant yourself staff privilege globally

After replacing `/* USERNAME */` with your in-game player name, run the following SQL on the same database as the global tables:

```sql
INSERT INTO global_user_privilege
(gp_id, gp_privilege)
VALUES (
    SELECT gu_id FROM global_user WHERE gu_name = /* USERNAME */,
    'staff'
);
```

## Step 4. Configure server

Write database connection parameters to `centralauth_pg_connection` on `minetest.conf`. Check the [pgmoon documentation](https://github.com/leafo/pgmoon?tab=readme-ov-file#newoptions) for all possible options. For example, if you database is on localhost:

```text
# This is an example. DO NOT USE THIS PASSWORD!
centralauth_pg_connection = database=minetest host=127.0.0.1 port=5432 user=minetest password=minetest
```

After that, add `centralauth_server_db_id = /* SERVERNAME */`, where `/* SERVERNAME */` is your server's ID in step 2.

Populate `centralauth_server_list` with a comma-seperated list of servers in the same CentralAuth system. For exmaple, if two servers named `survival` and `creative` exists, the value of this configuration would be `survival,creative`.

The following configurations are optional:

* `centralauth_global_lock_message`: The formatting base of the message given to globally locked players. The name of staff who blocked the player, the time the player was blocked, and the reason are given as strings. It's recommended to modify this message to include way to appeal.
* `centralauth_block_new_accounts`: Whether to block new global account creation on this server, i.e. no accounts would have their home server set to this server. This might be useful if this server is not meant for new players, e.g. a sandbox server.
* `centralauth_block_new_accounts_reason`: If the above is enabled, this is the reason given to players attempting to create a new account. It's recommended to change this to a more specific reason.

## Step 5. Enable the mod

Add `load_mod_centralauth = true` to your `world.mt`. If you used [the original AntiSpoof mod](https://content.luanti.org/packages/Emojiminetest/antispoof/) before, either remove that old mod or replace `load_mod_antispoof = true` with `load_mod_antispoof = mods/centralauth/antispoof`.

As CentralAuth requires PostgreSQL connection, add `centralauth` to `secrue.trusted_mods`. You will also need to install pgmoon and its dependencies:

```bash
luarocks install luasocket
luarocks install pgmoon
luarocks install luabitop # If you don't use LuaJIT, not recommended
```

## Step 6. Populate AntiSpoof tables

After firing up the server with CentralAuth installed, you have to pre-populate the AntiSpoof data. This is required even if you had AntiSpoof installed before CentralAuth. Run `/centralauth-antispoof-init` to generate the data.
