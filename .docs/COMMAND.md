# CentralAuth chatcommand reference

## `/centralauth [<name>|#<id>]`

Get global user information of a player or yourself. If `#<id>` is provided, check the player with that ID; otherwise, look up account of that name.

Example:

```text
> /centralauth 1F616EMO
Global user information of 1F616EMO:
  User ID: 965
  Registered: no record
  Home server: twi
  Last login (globally): 2025-04-21 09:08:59 (on sandbox)
  Locked: No
  Local accounts:
    Server twi:
      Registered: no record
      Last login: 2025-04-21 09:06:17
      Privileges: shout, interact, home, privs
    Server sandbox:
      Registered: 2025-04-12 11:19:12
      Last login: 2025-04-21 09:08:59
      Privileges: settime, shout, interact, home, privs
  Global privileges: staff, globallock, antispoof_init
```

## `/grantglobal <name> <privs,privs,...>`, `/revokeglobal <name> <privs,privs,...>`

Similar to `/grant` and `/revoke`, but works on global privileges. Who can grant a privilege is defined in privilege definitions.

You can also use `/grantmeglobal` and `/revokemeglobal` if the target is yourself.

## `/globallock (lock|unlock) <username> [<reason>]`

*Requires global privilege: `globallock`*

Globally lock or unlock a user. Usually used on malicious username or cross-server griefers.

## `/centralauth-antispoof-init`

*Requires global privilege: `antispoof_init`*

Pre-populate AntiSpoof data with existing usernames. Only needed on first installation.

## `/centralauth-logs`

View CentralAuth logs.
