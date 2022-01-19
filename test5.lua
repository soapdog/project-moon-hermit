-- count all posts in db
local msgs, err = ssb:query_read({query = {{["$filter"] = {value = {content = {type = "post"}}}}}})

if (not err) then
    print(string.format("%d", #msgs ))
else
    print(err)
end