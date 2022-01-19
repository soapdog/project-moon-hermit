local utils = {
  _VERSION     = 'utils v1.0.0',
  _DESCRIPTION = 'misc utilities',
}


function splittokens(s)
    local res = {}
    for w in s:gmatch("[%S\n]+") do
        res[#res+1] = w
    end
    return res
end
 
utils.textwrap = function(text, linewidth)
    if not linewidth then
        linewidth = 75
    end
 
    local spaceleft = linewidth
    local res = {}
    local line = {}
 
    for _, word in ipairs(splittokens(text)) do
        if word:find("\n") then
            table.insert(line, word)
            goto continue
        end

        if #word + 1 > spaceleft then
            table.insert(res, table.concat(line, ' '))
            line = {word}
            spaceleft = linewidth - #word
        else
            table.insert(line, word)
            spaceleft = spaceleft - (#word + 1)
        end
        ::continue::
    end
 
    table.insert(res, table.concat(line, ' '))
    return table.concat(res, '\n')
end

return utils