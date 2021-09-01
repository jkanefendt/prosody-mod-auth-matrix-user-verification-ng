# Prosody Auth Matrix User Verification

## Description

_TBD_

![](sequence.svg) 

## Prerequisites

_TBD_

[Synapse - Extension of OpenID userinfo](https://github.com/matrix-org/synapse/pull/10384) (see [MSC3356](https://github.com/matrix-org/matrix-doc/pull/3356), https://github.com/matrix-org/matrix-doc/blob/4c415fb7bc2d991a4515820d8c4fda75e98ce94e/proposals/3356-add-openid-userinfo-fields.md)



```bash
$ luarocks install luajwtjitsi 2.0-0
$ luarocks install http 0.4-0
$ luarocks install lrexlib-POSIX 2.9.1-1
```

## Configuration

_TBD_

```lua
VirtualHost "example.com"
    -- Enable Matrix User Verification
    authentication = "matrix_user_verification"
    -- Restrict access to homeservers with a subdomain of example.com
    matrix_homeserver_hostname_pattern = "[^.]+\\.example\\.com"
```