print("hello from " .. _VERSION)

local whoami, err = ssb:whoami()

if (not err) then
    print(string.format("you are %s", whoami.id))
else
    print(string.format("some error happened?! %s", err))
end

local result, err = ssb:latestSequence(whoami.id)

if (not err) then
    print(string.format("latest sequence is %d", result))
else
    print(string.format("some error happened?! %s", err))
end
