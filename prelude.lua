local json = require("json")
local pprint = require("pprint")
local stream = require("stream")

function parseMsgs(arr) 
    local r = {}
    for i, msg in ipairs(arr) do
        r[i] = json.parse(msg)
    end
    return r
end

function lookup(t, ...)
    if t == nil then
        return nil
    end
    for _, k in ipairs{...} do
        t = t[k]
        if not t then
            return nil
        end
    end
    return t
end

local mt = {
    __index = function(self, k)
        return function(s, ...)
            local res, err = false
            
            local ars = table.pack(...)

            k = k:gsub("_",".")
            
            if (#ars == 0) then
                ars = "[]"
            else
                ars = json.stringify({ars[1]})
            end 

            local status, retval = pcall(muxrpc, k, ars)

            if (status) then
                if (type(retval) ~= "table") then
                    res = json.parse(retval)
                else
                    res = parseMsgs(retval)
                end
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