#!./moonhermit

--[[
This script does the following:

* Chooses a feed by either inspecting the first argument passed to it
or by finding out who the running user is.
* Gets the name for that feed.
* Finds all follows for that feed.
* Gets all pub annoucements
* Finds intersections between follows and pub announcements.
* Gets the name for all the feeds in the intersection.

Lots of muxrpc calls... 
]]

require "pl"


--[[ Figure out if the user passed a feed or if we need to check the running
user feed is
]]

local key = arg[1]

if key == nil then
    print "Finding who you are..."
    local whoami, err = ssb:whoami()
    if err then
        print("error:" .. err)
        exit(1)
    end
    key = whoami.id
else
    print(string.format("Finding pubs for feed: %s", key))
end


--[[
Helper functions to compute relationship table and pub announcement set.
]]

function justContacts(m)
    return lookup(m, "value", "content", "type") == "contact"
end

function justAbout(m)
    local c1 = lookup(m, "value", "content", "type") == "about"
    local c2 = lookup(m, "value", "author") == lookup(m, "value", "content", "about")

    return c1 and c2
end

function getName(feed)
    local s, err = ssb:createUserStream({
        id = feed
    })

    if err then
        return nil, err 
    end

    local a = stream(s).filter(justAbout).reverse().toarray()
    local name = lookup(a[1], "value", "content", "name")
    if name == nil then
        -- first message was not setting a name, look further...
        for i, v in pairs(a) do
            if lookup(v, "value", "content", "name") ~= nil then
                name = lookup(v, "value", "content", "name")
                break
            end
        end
    end
    return name, nil, a
end

local contacts = {}

function addToMap(m)
    local user = m.value.author
    local target = m.value.content.contact 
    local action = m.value.content.following and 1 or -1
    contacts[target] = (contacts[target] or 0) + action
end

local keyname = getName(key)


--[[ Get all pub messages, compute relationship graph ]]

print "Finding all pub announcement messages..."
local pubMsgs, err2 = ssb:messagesByType({
    type = "pub"
})

print("Looking up " .. keyname .. " history...")
local msgs, err1 = ssb:createHistoryStream({
    id = key
})

if (not err1) and (not err2) then
    -- compute contacts table
    stream(msgs).filter(justContacts).foreach(addToMap)

    -- rework pubMsgs table into a Set
    local allPubs = Set{}

    for i, v in pairs(pubMsgs) do 
        local k = lookup(v, "value", "content", "address", "key")
        --local k = lookup(v, "value", "author")
        allPubs = allPubs+Set{k}
    end

    -- output some cool information
    local contactMsgs = stream(msgs).filter(justContacts).toarray()
    print(string.format("\n%d contact msgs", #contactMsgs ))
    print(string.format("%d pub msgs", #pubMsgs ))
    print(string.format("%d unique pub ids\n", #allPubs ))
    
    -- find pubs in contacts table
    for feed, v in pairs(contacts) do
        if v == 1 then
            if allPubs[feed] then
                local name, _ = getName(feed)
                if name == nil then
                    name = "unknown name (maybe out of hops)"
                end
                print(string.format("%s follow pub %s known as %s", keyname, feed, name))
            end
        end
    end
else
    print(err1)
    print(err2)
end