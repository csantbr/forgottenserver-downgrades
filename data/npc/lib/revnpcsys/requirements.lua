--[[
    >> NpcRequirements <<

    Description:
        This table stores the requirements for an NPC interaction.
        It provides functions to set various requirements such as storage, level, premium status, money, items, infight status, and PZ lock status.
        The init function checks if the player meets all the requirements specified and returns true if all requirements are met, otherwise false.

    Functions:
        NpcRequirements:storage(key, value, operator, value2, operator2)
        NpcRequirements:level(level, operator, level2, operator2)
        NpcRequirements:premium(premium)
        NpcRequirements:vocation(vocation)
        NpcRequirements:money(amount)
        NpcRequirements:removeMoney(amount)
        NpcRequirements:item(item, count)
        NpcRequirements:items(table)
        NpcRequirements:removeItem(item, count, subType, ignoreEquipped = true)
        NpcRequirements:removeItems(table)
        NpcRequirements:isInfight(infight)
        NpcRequirements:isPzLocked(pzLocked)
        NpcRequirements:failureRespond(message, requirementType)
        NpcRequirements:getFailureRespond(requirementType)

        NpcRequirements:init(player)
]]

---@class NpcRequirements
---@field requireStorage table<string, any>
---@field requireLevel table<string, any>
---@field requirePremium boolean
---@field requireMoney number
---@field requireRemoveMoney number
---@field requireItem table<string, any>
---@field requireRemoveItem table<string, any>
---@field requireInfight boolean
---@field requirePzLocked boolean
---@field init fun(player: Player): boolean, string?, number?
---@field storage fun(self: NpcRequirements, key: string, value: number, operator?: string, value2?: number, operator2?: string)
---@field level fun(self: NpcRequirements, level: number, operator?: string, level2?: number, operator2?: string)
---@field premium fun(self: NpcRequirements, premium: boolean)
---@field vocation fun(self: NpcRequirements, vocation: string|table<number, string>)
---@field money fun(self: NpcRequirements, amount: number)
---@field removeMoney fun(self: NpcRequirements, amount: number)
---@field item fun(self: NpcRequirements, item: number, count: number, subType?: number)
---@field items fun(self: NpcRequirements, table: table<number, table>)
---@field removeItem fun(self: NpcRequirements, item: number, count: number, subType: number|nil, ignoreEquipped: boolean|nil)
---@field removeItems fun(self: NpcRequirements, table: table<number, table>)
---@field isInfight fun(self: NpcRequirements, infight: boolean)
---@field isPzLocked fun(self: NpcRequirements, pzLocked: boolean)
---@field failureRespond fun(self: NpcRequirements, message: string, requirementType: number)
---@field getFailureRespond fun(self: NpcRequirements, requirementType: number): string|nil
---@field checkStorageValue fun(self: NpcRequirements, player: Player): boolean, string|nil
---@field checkLevel fun(self: NpcRequirements, player: Player): boolean, string|nil
---@type table<string, NpcRequirements>

-- Make sure we are not overloading on reload
if not NpcRequirements then
    NpcRequirements = {}

    -- Sets the storage requirement for a keyword.
    ---@param key string: The key of the storage value.
    ---@param value number: The required value of the storage.
    ---@param operator string (optional): The operator to use for the check. Defaults to "==". Possible values are "==", "~=", "<", ">", "<=", ">=".
    ---@param value2 number (optional): The second value to check for if you want to do a ranged check.
    ---@param operator2 string (optional): The operator to use for the second check range. "<", ">", "<=", ">=".
    function NpcRequirements:storage(key, value, operator, value2, operator2)
        operator = operator or "=="
        value2 = value2 or nil
        operator2 = operator2 or nil
        self.requireStorage = {key = key, value = value, operator = operator, value2 = value2, operator2 = operator2}
    end

    -- Sets the level requirement for a keyword.
    ---@param level number: The required level.
    ---@param operator string (optional): The operator to use for the check. Defaults to ">=". Possible values are "==", "~=", "<", ">", "<=", ">=".
    ---@param level2 number (optional): The second level to check for if you want to do a ranged check.
    ---@param operator2 string (optional): The operator to use for the second check range. "<", ">", "<=", ">=".
    function NpcRequirements:level(level, operator, level2, operator2)
        operator = operator or ">="
        level2 = level2 or nil
        operator2 = operator2 or nil
        self.requireLevel = {level = level, operator = operator, level2 = level2, operator2 = operator2}
    end

    -- Sets the premium requirement for a keyword.
    ---@param premium boolean: If true, the player must be premium to advance the talk state.
    function NpcRequirements:premium(premium)
        self.requirePremium = premium
    end

    -- Sets the vocation requirement for a keyword.
    ---@param vocation string|table<number, string>: The required vocation name.
    function NpcRequirements:vocation(vocation)
        if type(vocation) == "string" then
            vocation = {vocation}
        end
        self.requireVocation = vocation
    end

    -- Sets the money requirement for a keyword.
    ---@param amount number: The required amount of money.
    function NpcRequirements:money(amount)
        self.requireMoney = amount
    end

    -- Sets the money to remove for a keyword.
    ---@param amount number: The amount of money to remove.
    function NpcRequirements:removeMoney(amount)
        self.requireRemoveMoney = amount
    end

    -- Sets the item requirement for a keyword.
    ---@param item number: The item ID.
    ---@param count number (optional): The required amount of the item. Defaults to 1.
    ---@param subType number (optional): The subtype of the item. Defaults to -1.
    function NpcRequirements:item(item, count, subType)
        local count = count or 1
        local subType = subType or -1
        self.requireItem = {{item = item, count = count, subType = subType}}
    end

    -- Sets the items requirement for a keyword.
    ---@param table table<number, table>: The table of items to require.
    function NpcRequirements:items(table)
        self.requireItem = table
    end

    -- Sets the item to remove for a keyword.
    ---@param item number: The item ID.
    ---@param count number (optional): The amount of the item to remove. Defaults to 1.
    ---@param subType number (optional): The subtype of the item to remove. Defaults to -1.
    ---@param ignoreEquipped boolean (optional): If true, the item will not be removed even if it is equipped. Defaults to false.
    function NpcRequirements:removeItem(item, count, subType, ignoreEquipped)
        local count = count or 1
        local subType = subType or -1
        local ignoreEquipped = ignoreEquipped or true
        self.requireRemoveItem = {{item = item, count = count, subType = subType, ignoreEquipped = ignoreEquipped}}
    end

    -- Sets the items to remove for a keyword.
    ---@param table table<number, table>: The table of items to remove.
    function NpcRequirements:removeItems(table)
        self.requireRemoveItem = table
        for k, v in pairs(table) do
            table[k].ignoreEquipped = table[k].ignoreEquipped or true
        end
    end

    -- Sets the infight requirement for a keyword.
    ---@param infight boolean: If true, the player must be in a fight.
    function NpcRequirements:isInfight(infight)
        self.requireInfight = infight
    end

    -- Sets the PZ lock requirement for a keyword.
    ---@param pzLocked boolean: If true, the player must be PZ locked.
    function NpcRequirements:isPzLocked(pzLocked)
        self.requirePzLocked = pzLocked
    end

    -- Sets the failure respond for a requirement type.
    ---@param message string: The message to send to the player if the requirements are not met.
    ---@param requirementType number: The constant type of REQUIREMENT to set the failure respond for.
    function NpcRequirements:failureRespond(message, requirementType)
        if not self.requireFailureRespond then
            self.requireFailureRespond = {}
        end
        self.requireFailureRespond[requirementType] = message
    end

    -- Gets the failure respond for a requirement type.
    ---@param requirementType number: The constant type of REQUIREMENT to get the failure respond for.
    function NpcRequirements:getFailureRespond(requirementType)
        if self.requireFailureRespond then
            return self.requireFailureRespond[requirementType]
        end
    end

    -- Uses the correct operator on storage values, depending on string.
    ---@param player Player The player to check the storage value for.
    ---@return boolean The result of the storage value check.
    ---@return nil|string The message to send to the player if the requirements are not met.
    function NpcRequirements:checkStorageValue(player)
        local storage = self.requireStorage
        if storage.operator == "==" then
            return player:getStorageValue(storage.key) == storage.value, MESSAGE_LIST.storage:replaceTags({storage = {key = storage.key, value = storage.value}})
        elseif storage.operator == "~=" then
            return player:getStorageValue(storage.key) ~= storage.value, MESSAGE_LIST.storageNotEqual:replaceTags({storage = {key = storage.key, value = storage.value}})
        elseif storage.operator == "<" then
            if storage.value2 and storage.operator2 == ">" then
                return player:getStorageValue(storage.key) < storage.value and player:getStorageValue(storage.key) > storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            elseif storage.value2 and storage.operator2 == ">=" then
                return player:getStorageValue(storage.key) < storage.value and player:getStorageValue(storage.key) >= storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            end
            return player:getStorageValue(storage.key) < storage.value, MESSAGE_LIST.storageToLow:replaceTags({storage = {key = storage.key, value = storage.value}})
        elseif storage.operator == ">" then
            if storage.value2 and storage.operator2 == "<" then
                return player:getStorageValue(storage.key) > storage.value and player:getStorageValue(storage.key) < storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            elseif storage.value2 and storage.operator2 == "<=" then
                return player:getStorageValue(storage.key) > storage.value and player:getStorageValue(storage.key) <= storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            end
            return player:getStorageValue(storage.key) > storage.value, MESSAGE_LIST.storageToHigh:replaceTags({storage = {key = storage.key, value = storage.value}})
        elseif storage.operator == "<=" then
            if storage.value2 and storage.operator2 == ">" then
                return player:getStorageValue(storage.key) <= storage.value and player:getStorageValue(storage.key) > storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            elseif storage.value2 and storage.operator2 == ">=" then
                return player:getStorageValue(storage.key) <= storage.value and player:getStorageValue(storage.key) >= storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            end
            return player:getStorageValue(storage.key) <= storage.value, MESSAGE_LIST.storageToLow:replaceTags({storage = {key = storage.key, value = storage.value}})
        elseif storage.operator == ">=" then
            if storage.value2 and storage.operator2 == "<" then
                return player:getStorageValue(storage.key) >= storage.value and player:getStorageValue(storage.key) < storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            elseif storage.value2 and storage.operator2 == "<=" then
                return player:getStorageValue(storage.key) >= storage.value and player:getStorageValue(storage.key) <= storage.value2, MESSAGE_LIST.storageRange:replaceTags({storage = {key = storage.key, value = storage.value, value2 = storage.value2}})
            end
            return player:getStorageValue(storage.key) >= storage.value, MESSAGE_LIST.storageToHigh:replaceTags({storage = {key = storage.key, value = storage.value}})
        end
        print("[Warning - NpcRequirements:checkStorageValue] operator: ".. storage.operator .." does not exist.\n".. debug.getinfo(2).source:match("@?(.*)"))
        return false
    end

    -- Uses the correct operator on level, depending on string.
    ---@param player Player The player to check the storage value for.
    ---@return boolean The result of the storage value check.
    ---@return nil|string The message to send to the player if the requirements are not met.
    function NpcRequirements:checkLevel(player)
        local params = self.requireLevel
        if params.operator == "==" then
            return player:getLevel() == params.level, MESSAGE_LIST.level:replaceTags({playerLevel = params.level})
        elseif params.operator == "~=" then
            return player:getLevel() ~= params.level, MESSAGE_LIST.levelNotEqual:replaceTags({playerLevel = params.level})
        elseif params.operator == "<" then
            if params.level2 and params.operator2 == ">" then
                return player:getLevel() < params.level and player:getLevel() > params.level2, MESSAGE_LIST.levelRange1:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            elseif params.level2 and params.operator2 == ">=" then
                return player:getLevel() < params.level and player:getLevel() >= params.level2, MESSAGE_LIST.levelRange2:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            end
            return player:getLevel() < params.level, MESSAGE_LIST.levelToLow:replaceTags({playerLevel = params.level})
        elseif params.operator == ">" then
            if params.level2 and params.operator2 == "<" then
                return player:getLevel() > params.level and player:getLevel() < params.level2, MESSAGE_LIST.levelRange1:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            elseif params.level2 and params.operator2 == "<=" then
                return player:getLevel() > params.level and player:getLevel() <= params.level2, MESSAGE_LIST.levelRange3:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            end
            return player:getLevel() > params.level, MESSAGE_LIST.levelToHigh:replaceTags({playerLevel = params.level})
        elseif params.operator == "<=" then
            if params.level2 and params.operator2 == ">" then
                return player:getLevel() <= params.level and player:getLevel() > params.level2, MESSAGE_LIST.levelRange3:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            elseif params.level2 and params.operator2 == ">=" then
                return player:getLevel() <= params.level and player:getLevel() >= params.level2, MESSAGE_LIST.levelRange4:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            end
            return player:getLevel() <= params.level, MESSAGE_LIST.levelToLow:replaceTags({playerLevel = params.level})
        elseif params.operator == ">=" then
            if params.level2 and params.operator2 == "<" then
                return player:getLevel() >= params.level and player:getLevel() < params.level2, MESSAGE_LIST.levelRange2:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            elseif params.level2 and params.operator2 == "<=" then
                return player:getLevel() >= params.level and player:getLevel() <= params.level2, MESSAGE_LIST.levelRange4:replaceTags({playerLevel = params.level, playerLevel2 = params.level2})
            end
            return player:getLevel() >= params.level, MESSAGE_LIST.levelToHigh:replaceTags({playerLevel = params.level})
        end
        print("[Warning - NpcRequirements:checkLevel] operator: ".. params.operator .." does not exist.\n".. debug.getinfo(2).source:match("@?(.*)"))
        return false
    end

    -- Initializes the requirements for a player.
    ---@param player Player: The player to check the requirements for.
    ---@return boolean: True if the player meets all requirements, false otherwise.
    ---@return nil|string (optional): The message to send to the player if the requirements are not met.
    ---@return nil|number (optional): The REQUIREMENT constant which type of requirement we didn't met.
    function NpcRequirements:init(player)
        if self.requireStorage then
            local ret, msg = self:checkStorageValue(player)
            if not ret then
                return false, msg, REQUIREMENTS.storage
            end
        end

        if self.requireLevel then
            local ret, msg = self:checkLevel(player)
            if not ret then
                return false, msg, REQUIREMENTS.level
            end
        end

        if self.requirePremium then
            if not player:isPremium() then
                return false, MESSAGE_LIST.premium, REQUIREMENTS.premium
            end
        end

        if self.requireVocation then
            if not table.contains(self.requireVocation, player:getVocation():getName():lower()) and not table.contains(self.requireVocation, player:getVocation():getBase():getName():lower()) then
                return false, MESSAGE_LIST.vocation:replaceTags({vocation = table.concat(self.requireVocation, ", ")}), REQUIREMENTS.vocation
            end
        end

        if self.requireMoney then
            if player:getMoney() < self.requireMoney then
                return false, MESSAGE_LIST.money:replaceTags({total = self.requireMoney}), REQUIREMENTS.money
            end
        end

        if self.requireItem then
            for i = 1, #self.requireItem do
                local index = self.requireItem[i]
                local id = ItemType(index.item):getId()
                local name = ItemType(index.item):getName()
                if player:getItemCount(id, index.subType, index.ignoreEquipped) < index.count then
                    return false, MESSAGE_LIST.item:replaceTags({itemName = name, amount = index.count}), REQUIREMENTS.item
                end
            end
        end

        if self.requireInfight ~= nil then
            if self.requireInfight and not player:getCondition(CONDITION_INFIGHT, CONDITIONID_DEFAULT) and not player:getCondition(CONDITION_INFIGHT, CONDITIONID_COMBAT) then
                return false, MESSAGE_LIST.infight, REQUIREMENTS.inFight
            end
            if not self.requireInfight and player:getCondition(CONDITION_INFIGHT, CONDITIONID_DEFAULT) and player:getCondition(CONDITION_INFIGHT, CONDITIONID_COMBAT) then
                return false, MESSAGE_LIST.notInfight, REQUIREMENTS.inFight
            end
        end

        if self.requirePzLocked ~= nil then
            if self.requirePzLocked and not player:isPzLocked() then
                return false, MESSAGE_LIST.pzLocked, REQUIREMENTS.pzLocked
            end
            if not self.requirePzLocked and player:isPzLocked() then
                return false, MESSAGE_LIST.notPzLocked, REQUIREMENTS.pzLocked
            end
        end

        if self.requireRemoveMoney and self.requireRemoveItem then
            for i = 1, #self.requireRemoveItem do
                local index = self.requireRemoveItem[i]
                local id = ItemType(index.item):getId()
                local name = ItemType(index.item):getName()
                if player:getItemCount(id, index.subType, index.ignoreEquipped) < index.count then
                    return false, MESSAGE_LIST.item:replaceTags({itemName = name, amount = index.count}), REQUIREMENTS.item
                end
            end
            if player:getMoney() < self.requireRemoveMoney then
                return false, MESSAGE_LIST.money:replaceTags({total = self.requireRemoveMoney}), REQUIREMENTS.money
            end
        end

        if self.requireRemoveMoney then
            if not player:removeMoney(self.requireRemoveMoney) then
                return false, MESSAGE_LIST.money:replaceTags({total = self.requireRemoveMoney}), REQUIREMENTS.money
            end
        end

        if self.requireRemoveItem then
            for i = 1, #self.requireRemoveItem do
                local index = self.requireRemoveItem[i]
                local id = ItemType(index.item):getId()
                local name = ItemType(index.item):getName()
                if player:getItemCount(id, index.subType, index.ignoreEquipped) < index.count then
                    return false, MESSAGE_LIST.item:replaceTags({itemName = name, amount = index.count}), REQUIREMENTS.removeItem
                end
            end
            for i = 1, #self.requireRemoveItem do
                local index = self.requireRemoveItem[i]
                local id = ItemType(index.item):getId()
                local name = ItemType(index.item):getName()
                if not player:removeItem(id, index.count, index.subType, index.ignoreEquipped) then
                    return false, MESSAGE_LIST.item:replaceTags({itemName = name, amount = index.count}), REQUIREMENTS.removeItem
                end
            end
        end
        return true
    end
end
