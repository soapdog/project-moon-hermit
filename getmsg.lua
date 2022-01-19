#!./moonhermit

-- Requires "supernova" which can be installed from Luarocks
-- https://luarocks.org/modules/gbaptista/supernova

local utils = require 'utils'
local supernova = require 'supernova'

local msg, error = ssb:get({id = arg[1]})

if (not error) then
    print(supernova.italic.yellow('From: ') .. supernova.underline.color("ssb://feed/ed25519/" .. msg.author, '#e317e0'))
    print(supernova.italic.yellow('Date: ') .. supernova.underline.color(os.date('%A, %B %d %Y at %I:%M:%S %p\n', msg.timestamp//1000), '#e317e0'))

    print(supernova.gradient(
      utils.textwrap(msg.content.text),
      { '#FF0000', '#FFFF00', '#00FF00', '#0FF0FE', '#233CFE' }
    ))
else
    print(error)
end