--[[
    >> Modules <<

    Description:
        - This file contains the modules for the NPC system.
        - Modules are pre written NpcsHandler to make it easier to make certain types of NPCs.
        - You can write your own modules and add them to the system.

    Functions:
        - NpcsHandler:travelTo(params)
]]

---@alias travelTo fun(self: NpcsHandler, params: table<string, table>)

-- This Module enables fast and easy creation of Travel NPCs
---@class travelParams
---@field position Position
---@field money number
---@field level number
---@field premium boolean
---@field storage table<string, any>
---@field item table<string, number>
---@field removeItem table<string, any>
---@field isPzLocked boolean
---@field isInfight boolean
---@param params table<string, travelParams>
function NpcsHandler:travelTo(params)
    local greet = self:keyword(self.greetWords)
    greet:setGreetResponse("Hello |PLAYERNAME| I can {travel} you to wherever you want, just tell me your {destination}")
    local traveling = greet:keyword("travel")
    traveling:respond("Where do you want to travel?")

    for name, dest in pairs(params) do
        local toDest = traveling:keyword(name)
        toDest:respond(string.format("Do you want to travel to {%s} for {%d} gold?", name, dest.money and dest.money or 0))

        local destinations = greet:keyword("destination")
        local words = {}
        for k, v in pairs(traveling:getKeywords()) do
            if k ~= "destination" then
                table.insert(words, "{".. k .."}")
            end
        end
        destinations:respond("Here are the destinations: " .. table.concat(words, ", "))

        local accept = toDest:keyword("yes")
        accept:respond("I will take you there!")
        accept:teleport(dest.position)

        local require = accept:requirements()
        if dest.isPzLocked then require:isPzLocked(dest.isPzLocked) else require:isPzLocked(false) end
        if dest.isInfight then require:isInfight(dest.isInfight) else require:isInfight(false) end
        if dest.money then require:removeMoney(dest.money) end
        if dest.level then require:level(dest.level) end
        if dest.premium ~= nil then require:premium(dest.premium) end
        if dest.storage then require:storage(dest.storage.key, dest.storage.value, dest.storage.operator ~= nil and dest.storage.operator) end
        if dest.item then require:item(dest.item.item, dest.item.count) end
        if dest.removeItem then require:removeItem(dest.removeItem.item, dest.removeItem.count, dest.removeItem.subType and dest.removeItem.subType or -1, dest.removeItem.ignoreEquipped and dest.removeItem.ignoreEquipped or true) end

        local decline = toDest:keyword("no")
        decline:respond("Ok, maybe next time.")
    end
end
