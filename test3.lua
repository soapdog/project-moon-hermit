-- counts contact messages
local pprint = require("pprint")

function justContacts(m)
    return lookup(m, "value", "content", "type") == "contact"
end

function displayContactMsg(m)
    local user = m.value.author
    local target = m.value.content.contact 
    local action = m.value.content.following and "followed" or "unfollowed"
    print(string.format("%s %s %s", user, action, target))
end

local msgs, err = ssb:createHistoryStream({
    id = "@0xkjAty6RSr5uhbAvi0rbVR2g9Bz+89qiKth48ECQBE=.ed25519",
    limit = 50000
})

if (not err) then
    stream(msgs).filter(justContacts).foreach(displayContactMsg)
    local contactMsgs = stream(msgs).filter(justContacts).toarray()
    print(string.format("%d contact msgs", #contactMsgs ))
else
    print(err)
end