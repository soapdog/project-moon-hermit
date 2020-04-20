local msg, error = ssb:get({id = "%W7j6VTDqzMyUc1z4HG+C5gny288CL9vmOPjt2qkFRCA=.sha256"})

if (not error) then
    -- pprint(msg)
    print("Author is: " .. msg.author)
    print("Text:\n" .. msg.content.text)
else
    print(error)
end