# Project Moon Hermit

![nice gif](nice.gif)

Based on original _sbotc_ by @Cel.

Uses Lua 5.4

This is a Lua interpreter that contains an SSB Client API.

## Attention

Only async methods implemented so far, the others will error out.

## Build

I have vendored `lua-5.4.3` and `libsodium-1.0.18`. To build them:

```
make deps
```

If you want to build a shared version of moonhermit. To compile the interpreter:

```sh
make
```

## Compile options

To build a binary that uses shared libraries, use `make SHARED=1`

## Usage

```sh
moonhermit [-j] [-l] [-r]
      [ [-c <cap>] [-k <key>] [-K <keypair_seed>] ]
      [ [-s <host>] [-p <port>] [ -4 | -6 ] | [-u <socket_path>] ]
      [ -a  luafile ]
```

The original `sbotc.c` is included.
