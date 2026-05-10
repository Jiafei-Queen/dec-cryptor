mod decryptor;
mod encryptor;
mod crypto_utils;
mod progress_utils;
mod key_derivation;
mod args;

use args::*;
use rpassword::read_password;
use std::env;
use std::io;
use std::io::IsTerminal;
use std::io::Write;
use std::path::Path;

fn print_usage() {
    println!("Usage: dec [OPERATION] [INPUT_FILE] [OPTIONS]");

    println!("Example:");
    println!("  # Encrypt `input_file.txt` and outputs `input_file.txt.decx`");
    println!("  dec -e input_file.txt\n");

    println!("  # Encrypt `input.tar` (outputs `dec_file`)");
    println!("  dec --encrypt input.tar -o dec_file\n");

    println!("  # Decrypt `example.tar.decx` (outputs `example.tar`)");
    println!("  dec -d example.tar.decx");
    println!();
    println!("  # Encrypt from stdin to stdout");
    println!("  cat plain.txt | dec -e - -p secret --stdout > plain.txt.decx");

    println!("Operations:");
    println!("  -e, --encrypt\t\t\tencrypt a file");
    println!("  -d, --decrypt\t\t\tdecrypt a file");

    println!("Options:");
    println!("  -o, --output\t\t\tset output file name");
    println!("  -c, --stdout\t\t\twrite output stream to stdout");
    println!("  -p, --password\t\tset password");
    println!("  -q, --quiet\t\t\tno check");

    println!("Others:");
    println!("  -v, --version\t\t\tshow version");
}

fn print_version() {
    println!(":: DEC! :: (v{})", env!("CARGO_PKG_VERSION"));
    println!("Copyright (C) 2026 jiafeiown.org, Jiafei");
    println!("License: MIT");
}

const PREFIX: &str = "DEC!: ";
const RESET: &str = "\u{001B}[0m";
const BOLD: &str = "\u{001B}[1m";
const RED: &str = "\u{001B}[31m";

fn main() {
    // 收集参数
    let args: Vec<String> = env::args().skip(1).collect();

    // 打印版本
    if args.len() == 1 && (args[0] == "-v" || args[0] == "--version") {
        print_version(); return;
    }

    // 获得参数
    let args = parse_args(&args).unwrap_or_else(|e| {
        print_usage();
        eprintln!("---\n{}{}{}{}", PREFIX, RED, e, RESET);
        std::process::exit(1);
    });

    // 提取参数
    let op = args.op;
    let input_path = args.input_path;
    let output_path = args.output_path.clone();
    let password = args.password;
    let stdout_output = args.stdout;

    if stdout_output && io::stdout().is_terminal() {
        eprintln!(
            "{}{}refusing to write stream data to the terminal; redirect or pipe stdout{}",
            PREFIX, RED, RESET
        );
        std::process::exit(1);
    }

    // 检查输出文件是否已存在
    if !stdout_output && !args.quiet && Path::new(&output_path).exists() {
        eprint!("> output file already {}EXISTS{}, {}{}overwrite{}? [y/n]: ", BOLD, RESET, BOLD, RED, RESET);
        io::stderr().flush().unwrap();
        if !confirm() { return; }
    }

    // 分配参数，进行下一步处理
    let result = match op {
        Op::Enc => handle_encrypt(input_path, output_path, password),
        Op::Dec => handle_decrypt(input_path, output_path, password),
    };

    if result.is_err() {
        std::process::exit(1);
    }
}

/*
 * 接手加密
 */
fn handle_encrypt(input_path: String, output_path: String, mut password: Option<String>) -> Result<(), ()> {
    // `confirmed` 用来区分 参数 和 输入
    let mut confirmed = true;
    if password == None {
        password = Some(get_password());
        confirmed = false;
    }

    // 转换 password
    let password = match password {
        Some(p) => p,
        _ => unreachable!()
    };

    if !confirmed && !confirm_password(&password) {
        eprintln!("{}{}passwords mismatch{}", PREFIX, RED, RESET);
        return Err(());
    }

    match encryptor::encrypt_with_mode(&input_path, &output_path, &password) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("[{}ERROR{}]: encryption failed: {}{}{}", RED, RESET, e, RED, RESET);
            Err(())
        }
    }
}

/*
 * 接手解密
 */
fn handle_decrypt(input_path: String, output_path: String, mut password: Option<String>) -> Result<(), ()> {
    // 获取密码
    if password == None {
        password = Some(get_password());
    }

    // 转换 password
    let password = match password {
        Some(p) => p,
        _ => unreachable!()
    };

    // 检查文件版本
    if input_path != "-" {
        match decryptor::check_version(&input_path) {
            Ok(_) => {},
            Err(e) => {
                eprintln!("[{}ERROR{}]: version mismatch: {}{}{}", RED, RESET, e, RED, RESET);
                return Err(());
            }
        }
    }
    
    match decryptor::decrypt_with_mode(&input_path, &output_path, &password) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("[{}ERROR{}]: decryption failed: {}{}{}", RED, RESET, e, RED, RESET);
            Err(())
        }
    }
}

/*
 * 以下都是辅助函数
 */
fn get_password() -> String {
    eprint!("> {}password:{} ", BOLD, RESET);
    io::stderr().flush().unwrap();
    let password = read_password().unwrap();
    password
}

fn confirm_password(password: &String) -> bool {
    eprint!("> {}confirm password:{} ", BOLD, RESET);
    io::stderr().flush().unwrap();
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
            eprint!("> [y/n]!!!: ");
            io::stderr().flush().unwrap();
        }
    }
}
