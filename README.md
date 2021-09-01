# Prosody Auth Matrix User Verification

## Description

_TBD_

![](sequence.svg) 

## Prerequisites

_TBD_

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