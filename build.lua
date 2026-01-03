#!/usr/bin/env lua
local function print_usage()
    print("Usage: ~ [OPTION]")
    print("Option:")
    print("  -n, --name\t\t\tset project_name")
    print("  -v, --version\t\tset version")
end


---- [ 获取版本 ] ----
local function get_version(handle)
    local version
    for line in handle:lines() do
        line = line:gsub(" ", "")
        if line:match("version=\"[%d%.]+\"") then
            version = line:gsub("version=", ""):gsub("\"", "")
        end
    end

    handle:close()

    if not version then
        print("cannot parse version tag, please enter it manually")
        io.write("> ")
        version = io.read()
    end

    return version
end

---- [ 获取项目名称 ] ----
local function get_name()
    local name
    local handle = io.popen("basename `pwd`")
    if handle then
        name = handle:read("*a")
        handle:close()
    end

    if not name then
        print("cannot parse project name, please enter it manually")
        io.write("> ")
        name = io.read()
    end

    return name
end

---- [ 检测 Cargo.toml ] ----
local handle = io.open("Cargo.toml", "r")
if not handle then
    io.stderr:write("build: Cargo.toml not found\n")
    return
end

---- [ 检测 7z 工具 ] ----
local z = io.popen("which 7z")
if not z or z:read("*a") == "" then
    io.stderr:write("build: 7z not found\n")
    return
end

---- [ 解析参数 ] ----
local name
local version

local args = {...}

local skip = false
for i,v in ipairs(args) do
    while true do
        if skip then skip=false break end
        if v == "-n" or v == "--name" then
            name = args[i+1]
            skip = true
        elseif v == "-v" or v == "--version" then
            version = args[i+1]
            skip = true
        else
            io.stderr:write("build: unknown arg: "..v)
            print_usage()
            return
        end
        break
    end
end

if not name then name = get_name() end
if not version then version = get_version(handle) end

---- [ 开始构建 ] ----
os.execute("cargo clean")

local targets = {
    "x86_64-pc-windows-gnu", "aarch64-apple-darwin",
    "x86_64-apple-darwin", "x86_64-unknown-linux-gnu"
}

local handle = io.popen("rustup target list")
for line in handle:lines() do
    line = line:gsub(" ", "")
    for _,target in ipairs(targets) do
        if line:find(target) then
            if line:sub(-11) ~= "(installed)" then
                io.stderr:write(
                    string.format(
                    "build: target not installed: %s\n", target
                    )
                )
                return
            end
        end
    end
end

for _,target in ipairs(targets) do
    print(string.format("\n---- [ 编译: `%s` ] ----\n", target))
    local ok = os.execute("cargo build --release --target "..target)
    if not ok then
        io.stderr:write("build: build stop\n")
        return
    end
end

local dir = name.."_"..version
os.execute("cp -r target "..dir)

os.execute(string.format("rm -rf %s/release %s/debug", dir, dir))

if io.popen("uname -a"):read("*a") == "Darwin" then
    os.execute("dot_clean "..dir)
end

os.execute(string.format("7z a %s.7z %s", dir, dir))
os.execute("rm -rf "..dir)
