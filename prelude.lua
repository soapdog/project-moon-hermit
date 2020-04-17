local json = require("json")
local pprint = require("pprint")

local mt = {
    __index = function(self, k)
        return function(s, ...)
            local res, err = false
            
            local ars = table.pack(...)
            
            if (#ars == 0) then
                ars = "[]"
            else
                ars = json.stringify({ars[1]})
            end 

            local status, retval = pcall(muxrpc, k, ars)

            if (status) then
                res = json.parse(retval)
                err = false
            else 
                res = false
                err = retval
            end 

            return res, err
        end 
    end
}
 
ssb = {}
setmetatable(ssb, mt)