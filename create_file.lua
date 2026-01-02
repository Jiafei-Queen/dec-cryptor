#!/usr/bin/env lua
local args = {...}
if #args ~= 1 then
    print("Usage: ~ [SIZE]")
    print("(~ = lua create_file.lua)")
    print("Example:")
    print("  ~ 500KB")
    print("  ~ 2GB")
    return
end

local size_str = args[1]

-- 单位定义
local units = {
    B  = 1,
    KB = 1024,
    MB = 1024 * 1024,
    GB = 1024 * 1024 * 1024
}

-- 提取数字和单位
local num = tonumber(size_str:match("([%d%.]+)"))
local unit = size_str:match("([A-Za-z]+)")
if unit then unit = unit:upper() end

if not num or not unit or not units[unit] then
    print("luacf: unit mismatch")
    return
end

local char_num = math.floor(num * units[unit])
local filename = string.format("%s.test", size_str)

-- 创建文件
local file = io.open(filename, "w")
if not file then
    print("> cannot create file")
    return
end

local block_size = 512 * units["KB"]
local block = string.rep("a", block_size)

local written = 0
while written < char_num do
    local remain = char_num - written
    local chunk_size = math.min(remain, #block)
    file:write(block:sub(1, chunk_size))
    written = written + chunk_size

    -- 每块更新一次进度
    local ratio = (written / char_num) * 100
    io.write(("\r> %0.2f%%"):format(ratio))
    io.flush()
end

print()

file:close()