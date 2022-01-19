#!./moonhermit

local pprint = require 'pprint'

local r, err = ssb:publish({
	type = "post",
	text = arg[1]
})

pprint(r)
pprint(err)

