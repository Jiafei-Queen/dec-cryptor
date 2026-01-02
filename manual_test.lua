#!/usr/bin/env lua
local size

local args = {...}
if #args == 0 then
    size = "500MB"
elseif #args == 1 then
    size = args[1]
else
    print("mt: Usage: ~ [SIZE]")
    return
end

local filename = size..".test"

print("------ [ 正在创建测试文件 ] ------")
os.execute("lua create_file.lua "..size)

print("------ [ 正在编译项目 ] ------")
os.execute("cargo build --release")

print("------ [ 加密测试 ] ------")
os.execute(string.format("./target/release/dec -e %s -p Password123! -q", filename))

print("------ [ 解密测试 ] ------")
os.execute(string.format("./target/release/dec -d %s -p Password123! -q", filename..".decx"))

os.execute("rm "..filename..".decx "..filename)