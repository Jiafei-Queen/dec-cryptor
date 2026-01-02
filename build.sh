#!/bin/sh
cargo clean
echo "\n---- [ 正在编译 \`x86_64-pc-windows-gnu\` ] ----\n"
printf "> [ENTER]确认: "
read
cargo build --release --target x86_64-pc-windows-gnu

echo "\n---- [ 即将编译 \`aarch64-apple-darwin\` ] ----\n"
printf "> [ENTER]确认: "
read
cargo build --release --target aarch64-apple-darwin

echo "\n---- [ 正在编译 \`x86_64-apple-darwin\` ] ----\n"
printf "> [ENTER]确认: "
read
cargo build --release --target x86_64-apple-darwin

echo "\n---- [ 正在编译 \`x86_64-unknown-linux-gnu\` ] ----\n"
printf "> [ENTER]确认: "
read
cargo build --release --target x86_64-unknown-linux-gnu

rm -rf target/release
rm -rf target/debug

printf "> 请输入<版本号>: "
read version
name="dec-cryptor_"${version}

cp -r target $name

if [ $(uname -s) == "Darwin" ]; then
    dot_clean $name 
fi

7z a $name.7z $name

rm -rf $name

echo "build: 构建成功"
