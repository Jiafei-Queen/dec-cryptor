mod decryptor;
mod encryptor;
mod crypto_utils;
mod progress_utils;
mod hmac_validator;
mod key_derivation;
mod parallel_handler;

use std::io;
use std::env;
use std::io::Write;
use std::path::Path;
use rpassword::read_password;

const PREFIX: &str = "DEC!: ";

fn main() {
    // 收集参数
    let args: Vec<String> = env::args().collect();
    
    // 检查参数数量（允许 -O 标志）
    if args.len() < 2 || args.len() > 4 {
        print_usage();
        return;
    }
    
    // 参数分类
    let op_arg = args[1].as_str();
    let operation;

    match op_arg {
        "-v" | "--version" => { print_version(); return; }
        "-e" | "--encrypt" => { operation = "--enc"; }
        "-d" | "--decrypt" => { operation = "--dec"; }
        _ => { print_usage(); return; }
    }

    // 并行度：自动使用所有可用核心（内部会根据硬件并行度确定线程数）
    let parts = 0usize;
    let idx = 2usize;

    // 检查输入文件参数
    if args.len() <= idx {
        println!("{}no path input", PREFIX);
        print_usage();
        return;
    }

    let input_path = args[idx].clone();
    
    // 检查输入文件是否存在
    if !Path::new(&input_path).exists() {
        println!("{}no such file", PREFIX);
        return;
    }
    
    // 确定输出路径
    let output_path = if args.len() > idx + 1 {
        args[idx + 1].clone()
    } else {
        let mut output = input_path.clone();
        if operation == "--enc" {
            output.push_str(".decx");
        } else {
            // 对于解密，移除.decx扩展名
            if output.ends_with(".decx") {
                output = output[..output.len() - 5].to_string();
            } else {
                output.push_str(".decx");
            }
        }
        output
    };

    // 保存 parts 到环境中的静态传递通过闭包
    let optimization_parts = parts;

    // 检查输出文件是否已存在
    if Path::new(&output_path).exists() {
        print!("> output file already EXISTS, overwrite? [y/n]: ");
        io::stdout().flush().unwrap();
        if !confirm() { return; }
    }

    // 分配参数，进行下一步处理
    match operation {
        "--enc" => handle_encrypt(input_path, output_path, optimization_parts),
        "--dec" => handle_decrypt(input_path, output_path, optimization_parts),
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("Usage: dec [OPTION...] [INPUT_FILE]...");

    println!("\nExample:");
    println!("  # Encrypt `input_file.txt` and outputs `output_file.txt.decx`");
    println!("  dec -e input_file.txt output_file.txt.decx\n");

    println!("  # Encrypt `input.tar` (outputs `input.tar.decx`)");
    println!("  dec --encrypt input.tar\n");

    println!("  # Decrypt `example.tar.decx` (outputs `example.tar`)");
    println!("  dec -d example.tar.decx");

    println!("\nOperations:");
    println!("  -e, --encrypt\t\tencrypt a file");
    println!("  -d, --decrypt\t\tdecrypt a file");

    println!("\nOthers:");
    println!("  -v, --version\t\tshow version");
}

fn print_version() {
    println!(":: DEC! :: (v{})", env!("CARGO_PKG_VERSION"));
    println!("Copyright (C) 2026 jiafeiown.org, Jiafei");
}

fn handle_encrypt(input_path: String, output_path: String, parts: usize) {
    let password = get_password();
    if !confirm_password(&password) {
        println!("{}passwords do not match.", PREFIX);
        return;
    }

    match encryptor::encrypt_with_mode(&input_path, &output_path, &password, parts) {
        Ok(_) => {},
        Err(e) => println!("{}encryption failed: {}", PREFIX, e),
    }
}

fn handle_decrypt(input_path: String, output_path: String, parts: usize) {
    let password = get_password();
    
    // 检查文件版本
    match decryptor::check_version(&input_path) {
        Ok(_) => {},
        Err(e) => {
            println!("{}version mismatch: {}", PREFIX, e);
            return;
        }
    }
    
    match decryptor::decrypt_with_mode(&input_path, &output_path, &password, parts) {
        Ok(_) => {},
        Err(e) => println!("{}decryption failed: {}", PREFIX, e),
    }
}

fn get_password() -> String {
    print!("> password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    password
}

fn confirm_password(password: &String) -> bool {
    print!("> confirm password");
    io::stdout().flush().unwrap();
    let local_password = read_password().unwrap();
    password == &local_password
}

fn confirm() -> bool {
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if input.trim() == "y" {
            return true;
        } else if input.trim() == "n" {
            return false;
        } else {
            print!("> [y/n]!!!: ");
            io::stdout().flush().unwrap();
        }
    }
}
