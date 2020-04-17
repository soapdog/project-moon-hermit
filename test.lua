print("hello from " .. _VERSION)

local whoami, error = ssb:whoami()

if (not error) then
    print(string.format("you are %s", whoami.id))
else
    print(string.format("some error happened?! %s", error))
end

local result, error = ssb:latestSequence(whoami.id)

if (not error) then
    print(string.format("latest sequence is %d", result))
else
    print(string.format("some error happened?! %s", error))
end
