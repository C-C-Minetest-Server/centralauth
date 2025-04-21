# Unified Login System for Luanti

**WARNING: This mod is a work in progress. All changes will be backward-compatible in some way, but migration may involve sophisticated database mutations that require manual debugging.**

CentralAuth syncs usernames and password acorss Luanti servers. The following mods are included in this mod pack:

* `centralauth`, the core functionalities; and
* `antispoof`, exposes public APIs found in the [original AntiSpoof mod](https://content.luanti.org/packages/Emojiminetest/antispoof/) which has been replaced by CentralAuth implementations.

Documentations:

* [`INSTALL.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/INSTALL.md): How to initialize the CentralAuth database and add servers to the CentralAuth system.
* [`MIGRATE.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/MIGRATE.md): How to import users from an existing server.
* [`COMMAND.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/COMMAND.md): In-game commands.
* [`API.md`](https://github.com/C-C-Minetest-Server/centralauth/blob/main/docs/API.md): Public APIs that can be used by other mods.
