# Project Moon Hermit

![nice gif](nice.gif)

Based on original *sbotc* by @Cel.

Uses Lua 5.3

This is a Lua interpreter that contains an SSB Client API.

## Attention

Only async methods implemented so far, the others will error out.


## Install

Install the dependencies: *sodium* and *lua 5.3*. On Debian: 

`sudo apt-get install libsodium-dev lua5.3 liblua5.3-dev`

Compile the interpreter:

```sh
make
```

## Compile options

To build a binary statically linked with libsodium, use `make STATIC=1`

## Usage

```sh
moonhermit [-j] [-l] [-r]
      [ [-c <cap>] [-k <key>] [-K <keypair_seed>] ]
      [ [-s <host>] [-p <port>] [ -4 | -6 ] | [-u <socket_path>] ]
      [ -a  luafile ]
```

The original `sbotc.c` is included.