local ngrok_url = "url"
local api_key = "f2f7d3a6e1b4c9a8f7e0b1c2d3a4e5f6"
verifiedHashes = {}
badHashes = {}
unknownHashes = {}
unknownScripts = {}
local hashesLoaded = false
local DEBUG = true
local HIDDEN_POSITION = {x = 0, y = -100, z = 0}

function debugPrint(message)
    if DEBUG then
        print(message)
    end
end

function getAllObjectScripts()
    local scripts = {}
    for _, obj in pairs(getAllObjects()) do
        local script = obj.getLuaScript()
        if script and script ~= '' then
            table.insert(scripts, {obj = obj, script = script})
        end
    end
    return scripts
end

function custom_hash(str)
    local hash = 0
    for i = 1, #str do
        local char = string.byte(str, i)
        hash = (hash * 31 + char) % 2^32
    end
    return hash
end

function to_8_char_hex(num)
    local hex = string.format("%08x", num)
    return hex
end

function generate_identifier(code_segment)
    local hash = custom_hash(code_segment)
    return to_8_char_hex(hash)
end

function createJsonPayload(script, hash)
    local payload = {
        hash = hash,
        script = script
    }
    return JSON.encode(payload)
end

function postScriptToServer(script, hash)
    local url = ngrok_url .. "/scripts"
    local headers = {
        ["Content-Type"] = "application/json",
        ["X-API-Key"] = api_key 
    }
    local payload = {
        scripts = {
            {
                hash = hash,
                script = script
            }
        }
    }
    local jsonData = JSON.encode(payload)
    WebRequest.custom(url, "POST", true, jsonData, headers, function(request)
        if request.is_error then
            debugPrint("Request failed: " .. request.error)
        else
            debugPrint("Response code: " .. request.response_code)
            debugPrint("Response text: " .. request.text)
        end
    end)
end

function getHashesFromServer(callback)
    local url = ngrok_url .. "/hashes"
    WebRequest.get(url, function(response)
        if response.is_error then
            debugPrint("Failed to retrieve hashes: " .. response.error)
        else
            local data = JSON.decode(response.text)
            if data then
                verifiedHashes = {}
                for _, hash in ipairs(data.verified_hashes) do
                    verifiedHashes[hash] = true
                end

                badHashes = {}
                for _, hash in ipairs(data.bad_hashes) do
                    badHashes[hash] = true
                end

                unknownHashes = {}
                for _, hash in ipairs(data.unknown_hashes) do
                    unknownHashes[hash] = true
                end

                hashesLoaded = true
                debugPrint("Hashes updated from server.")
                if callback then callback() end
            else
                debugPrint("Failed to parse server response.")
            end
        end
    end)
end

function postAllObjectScripts()
    local objects = getAllObjectScripts()
    for _, objData in ipairs(objects) do
        local script = objData.script:lower()
        local hash = generate_identifier(script)

        if badHashes[hash] then
            debugPrint("Bad hash detected, destroying object.")
            objData.obj.setVar("onDestroy", nil)
            objData.obj.setLuaScript("")
            objData.obj.destruct()
        elseif verifiedHashes[hash] then
            debugPrint("Verified script detected, no action needed.")
        elseif unknownHashes[hash] then
            debugPrint("Script with unknown hash already posted, no action needed.")
        else
            debugPrint("Unknown script detected, posting to server.")
            postScriptToServer(script, hash)
        end
    end
end

function onObjectSpawn(obj)
    local script = obj.getLuaScript():lower()
    if script == '' then
        debugPrint("Script is empty, skipping.")
        return
    end
    
    local hash = generate_identifier(script)
    
    if badHashes[hash] then
        debugPrint("Bad hash detected, destroying object.")
        obj.setVar("onDestroy", nil)
        obj.setLuaScript("")
        obj.destruct()
    elseif verifiedHashes[hash] then
        debugPrint("Verified script detected, no action needed.")
    elseif unknownHashes[hash] then
        debugPrint("Script with unknown hash already posted, no action needed.")
    else
        debugPrint("Unknown script detected, posting to server.")
        postScriptToServer(script, hash)
    end
    getHashesFromServer(function()
        if hashesLoaded then
            debugPrint("Hashes reloaded after object spawn.")
        else
            debugPrint("Hashes not loaded. Skipping.")
        end
    end)
end

function onLoad()
    debugPrint("onLoad: Starting script processing...")
    -- self.setPosition(HIDDEN_POSITION)
    -- self.setLock(true) 
    debugPrint("Moved the self object to a hidden location and locked it.")
    getHashesFromServer(function()
        if hashesLoaded then
            postAllObjectScripts()
        else
            debugPrint("Hashes not loaded.")
        end
    end)
end
