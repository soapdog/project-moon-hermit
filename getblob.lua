#!./moonhermit -d 

-- Requires "supernova" which can be installed from Luarocks
-- https://luarocks.org/modules/gbaptista/supernova

local pprint = require "pprint"

local blob, error = ssb:blobs_get(arg[1])

if (not error) then
    pprint(blob)
else
    print(error)
end