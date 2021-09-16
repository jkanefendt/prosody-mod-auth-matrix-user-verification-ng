# Prosody Auth Matrix User Verification

## Description

This prosody module implements authorization for Jitsi conferences based upon https://github.com/matrix-org/prosody-mod-auth-matrix-user-verification. Unlike prosody-mod-auth-matrix-user-verification, this module uses the extended OpenId user info described in [MSC3356](https://github.com/matrix-org/matrix-doc/pull/3356) for verifying the room membership of the user and does not rely on extra requests to Synapse-specific endpoints  (see https://github.com/matrix-org/synapse/blob/develop/docs/admin_api/rooms.md#room-state-api) as before.
As there is no more need to configure a token for accessing the Synapse-admin-API of a specific homeserver, this module enables a single Jitsi server to authorize users against multiple homeservers.

![](sequence.svg) 

## Prerequisites

The module depends on `luajwtjitsi=2.0-0`, `http=0.4-0` and `lrexlib-POSIX=2.9.1-1`.

```bash
$ luarocks install luajwtjitsi 2.0-0
$ luarocks install http 0.4-0
$ luarocks install lrexlib-POSIX 2.9.1-1
```

## Configuration

Copy [mod_auth_matrix_user_verification.lua](mod_auth_matrix_user_verification.lua) to the Prosody plugins folder.

Enable the module in the respective Prosody VirtualHost section. The set of authorized homeservers must be specified as a regular expression over the homeserver's hostname (option `matrix_homeserver_hostname_pattern`).

```lua
VirtualHost "example.com"
    -- Enable Matrix User Verification
    authentication = "matrix_user_verification"
    -- Restrict access to homeservers with a subdomain of example.com
    matrix_homeserver_hostname_pattern = "[^.]+\\.example\\.com"
```