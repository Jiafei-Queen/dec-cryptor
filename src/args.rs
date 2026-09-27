use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum Op { Enc, Dec }

#[derive(Debug)]
pub struct Args {
    pub op: Op,
    pub input_path: String,
    pub output_path: String,
    pub password: Option<String>,
    pub quiet: bool,
}

/// `-p` / `-o` 后面跟的是"值"还是"另一个选项"。
///
/// 只把**本程序自己认识的选项 token** 判定为 flag，而不是简单看首字符是否为 `-`：
/// 密码 / 文件名合法地可以以连字符开头（`-p -secret`），一刀切拒绝会造成回归。
/// 而 `dec -e file -o -q` 这种"忘了写值"的情况，如果照单全收就会静默地
/// 写进一个名为 `-q` 的文件 —— 那才是真正危险的静默行为。
fn is_option_flag(token: &str) -> bool {
    matches!(token, "-q" | "--quiet" | "-c" | "--stdout" | "-p" | "--password" | "-o" | "--output")
}

/// 取出 `flag` 后面跟的值，缺值时返回 `Err(flag)` 里描述的错误文案。
fn take_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a String, String> {
    match args.get(i + 1) {
        Some(v) if !is_option_flag(v) => Ok(v),
        _ => Err(format!("missing value for {}", flag)),
    }
}

pub fn parse_args(args: &Vec<String>) -> Result<Args, String> {
    if args.len() < 2 { return Err("arg too short".to_string()); }

    let op = match args[0].as_str() {
        "-e" | "--encrypt" => Op::Enc,
        "-d" | "--decrypt" => Op::Dec,
        _ => return Err("unknown operation".to_string()),
    };

    let input_path = args[1].clone();
    if input_path != "-" && !Path::new(&input_path).exists() { return Err("no such file".to_string()); }

    let mut quiet = false;
    let mut stdout = false;
    let mut output_path: Option<String> = None;
    let mut password: Option<String> = None;

    // 用显式游标 `i` 推进：带值的选项自己把游标 +2，其余 +1。
    // 之前这里用 `skip` 标志位 + 预置游标，`-p` / `-o` 落在末尾时
    // `args[i]` 会越界 panic；现在一律走 `take_value`，缺值返回 Err，
    // 由 main 打印 usage + 错误信息，不再崩溃。
    let mut i: usize = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-q" | "--quiet" => { quiet = true; i += 1; }
            "-c" | "--stdout" => { stdout = true; i += 1; }

            "-p" | "--password" => {
                if password.is_some() {
                    return Err("one password option only".to_string());
                }
                password = Some(take_value(args, i, "-p/--password")?.clone());
                i += 2;
            }

            "-o" | "--output" => {
                if output_path.is_some() {
                    return Err("one output option only".to_string());
                }
                output_path = Some(take_value(args, i, "-o/--output")?.clone());
                i += 2;
            }

            _ => {
                return Err("unknown option".to_string());
            }
        }
    }

    if stdout && output_path.is_some() {
        return Err("cannot use --stdout together with --output".to_string());
    }

    // 当未指定 输出文件路径 时
    if output_path.is_none() {
        if stdout || input_path == "-" {
            // `-` 输入天然是流式场景：未给 `-o` 时默认写 stdout
            // （旧行为会推出 `-.decx` / `-.out` 这种假文件名，随后又被
            //  `*_with_mode` 的 stdin 分支忽略，属于静默不一致）。
            output_path = Some("-".to_string());
        } else {
            match op {
                Op::Enc => output_path = Some(format!("{}.decx", input_path)),
                Op::Dec => {
                    if input_path.ends_with(".decx") {
                        output_path = Some(input_path[..input_path.len() - 5].to_string());
                    } else {
                        output_path = Some(format!("{}.out", input_path));
                    }
                }
            }
        }
    }

    let output = output_path.unwrap();

    // `-c/--stdout` 不单独留存：它和 `-o -`、`-` 输入一样，最终都体现为
    // `output_path == "-"`，路由只需要看输出路径。
    Ok(Args { op, input_path, output_path: output, password, quiet })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_encrypt_basic() {
        // 创建一个测试文件
        let test_file = create_test_file("test_input.txt");

        let args = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string()
        ];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.op, Op::Enc);
        assert_eq!(parsed_args.output_path, format!("{}.decx", test_file.path().to_str().unwrap()));
        assert_eq!(parsed_args.quiet, false);
    }

    #[test]
    fn test_parse_args_decrypt_with_options() {
        // 创建一个测试文件
        let test_file = create_test_file("test_input.decx");

        let args = vec![
            "-d".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "-o".to_string(),
            "custom_output.txt".to_string(),
            "-p".to_string(),
            "testpassword".to_string(),
            "-q".to_string()
        ];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.op, Op::Dec);
        assert_eq!(parsed_args.output_path, "custom_output.txt");
        assert_eq!(parsed_args.password, Some("testpassword".to_string()));
        assert_eq!(parsed_args.quiet, true);
    }

    #[test]
    fn test_parse_args_stdout_mode() {
        let test_file = create_test_file("test_input.txt");

        let args = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "--stdout".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.output_path, "-");
    }

    #[test]
    fn test_parse_args_stdin_mode() {
        let args = vec![
            "-e".to_string(),
            "-".to_string(),
            "--stdout".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.input_path, "-");
        assert_eq!(parsed_args.output_path, "-");
    }

    /// `-` 输入且未给 `-o` 时，默认输出去向是 stdout（不是 `-.decx` / `-.out`）。
    #[test]
    fn test_parse_args_stdin_default_output_is_stdout() {
        for op in ["-e", "-d"] {
            let args = vec![op.to_string(), "-".to_string()];
            let parsed = parse_args(&args).expect("stdin mode should parse");
            assert_eq!(parsed.input_path, "-");
            assert_eq!(parsed.output_path, "-", "stdin input must default to stdout");
        }

        // 显式 `-o` 仍然优先，不受 `-` 输入影响
        let args = vec![
            "-d".to_string(),
            "-".to_string(),
            "-o".to_string(),
            "out.bin".to_string(),
        ];
        assert_eq!(parse_args(&args).unwrap().output_path, "out.bin");
    }

    #[test]
    fn test_parse_args_stdout_conflicts_with_output() {
        let test_file = create_test_file("test_input.txt");

        let args = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "--stdout".to_string(),
            "-o".to_string(),
            "custom_output.txt".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "cannot use --stdout together with --output");
    }

    #[test]
    fn test_parse_args_stdout_short_flag() {
        let test_file = create_test_file("test_input.txt");

        let args = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "-c".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.output_path, "-");
    }

    #[test]
    fn test_parse_args_decrypt_default_output_strips_decx() {
        let test_file = create_test_file_with_suffix(".decx");
        let input_path = test_file.path().to_str().unwrap().to_string();

        let args = vec!["-d".to_string(), input_path.clone()];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.output_path, input_path.trim_end_matches(".decx"));
    }

    #[test]
    fn test_parse_args_decrypt_default_output_appends_out() {
        let test_file = create_test_file("ciphertext.bin");
        let input_path = test_file.path().to_str().unwrap().to_string();

        let args = vec!["-d".to_string(), input_path.clone()];

        let result = parse_args(&args);
        assert!(result.is_ok());
        let parsed_args = result.unwrap();
        assert_eq!(parsed_args.output_path, format!("{}.out", input_path));
    }

    #[test]
    fn test_parse_args_invalid_operation() {
        let args = vec!["-x".to_string(), "input.txt".to_string()];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "unknown operation");
    }

    #[test]
    fn test_parse_args_missing_arguments() {
        let args = vec!["-e".to_string()];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "arg too short");
    }

    #[test]
    fn test_parse_args_file_not_found() {
        let args = vec!["-e".to_string(), "nonexistent.txt".to_string()];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "no such file");
    }

    /// 回归测试：`-p` 落在参数末尾且没有跟值时，曾经直接 `args[i]` 越界 panic。
    #[test]
    fn test_parse_args_password_missing_value_is_error() {
        let test_file = create_test_file("test_input.txt");
        let args = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "-p".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "missing value for -p/--password");
    }

    /// 回归测试：`-o` 落在参数末尾且没有跟值时，曾经直接 `args[i]` 越界 panic。
    #[test]
    fn test_parse_args_output_missing_value_is_error() {
        let test_file = create_test_file("test_input.txt");
        let args = vec![
            "-d".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "-o".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "missing value for -o/--output");
    }

    /// 长形式的 `--password` / `--output` 同样要安全报错。
    #[test]
    fn test_parse_args_long_form_missing_value_is_error() {
        let test_file = create_test_file("test_input.txt");
        let path = test_file.path().to_str().unwrap().to_string();

        let missing_password = vec!["-e".to_string(), path.clone(), "--password".to_string()];
        assert_eq!(
            parse_args(&missing_password).unwrap_err(),
            "missing value for -p/--password"
        );

        let missing_output = vec!["-e".to_string(), path, "--output".to_string()];
        assert_eq!(
            parse_args(&missing_output).unwrap_err(),
            "missing value for -o/--output"
        );
    }

    /// 缺值后再跟其它选项，仍要稳定报错而不是 panic（游标推进不能错位）。
    #[test]
    fn test_parse_args_missing_value_before_other_options_is_error() {
        let test_file = create_test_file("test_input.txt");
        let mut with_trailing_flag = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "-o".to_string(),
        ];
        // `-q` 不会被误当成 `-o` 的值
        with_trailing_flag.push("-q".to_string());

        let result = parse_args(&with_trailing_flag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "missing value for -o/--output");
    }

    /// 密码本身可以合法地以连字符开头，不应该被当成"缺值"。
    #[test]
    fn test_parse_args_password_may_start_with_dash() {
        let test_file = create_test_file("test_input.txt");
        let args = vec![
            "-e".to_string(),
            test_file.path().to_str().unwrap().to_string(),
            "-p".to_string(),
            "-leading-dash".to_string(),
        ];

        let result = parse_args(&args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().password, Some("-leading-dash".to_string()));
    }

    /// 重复选项的报错行为保持不变。
    #[test]
    fn test_parse_args_duplicate_options_still_rejected() {
        let test_file = create_test_file("test_input.txt");
        let path = test_file.path().to_str().unwrap().to_string();

        let dup_password = vec![
            "-e".to_string(), path.clone(), "-p".to_string(), "a".to_string(),
            "-p".to_string(), "b".to_string(),
        ];
        assert_eq!(parse_args(&dup_password).unwrap_err(), "one password option only");

        let dup_output = vec![
            "-e".to_string(), path, "-o".to_string(), "a".to_string(),
            "-o".to_string(), "b".to_string(),
        ];
        assert_eq!(parse_args(&dup_output).unwrap_err(), "one output option only");
    }

    // 辅助函数：创建临时测试文件
    fn create_test_file(_name: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "test content").unwrap();
        file
    }

    fn create_test_file_with_suffix(suffix: &str) -> tempfile::NamedTempFile {
        let file = tempfile::Builder::new()
            .suffix(suffix)
            .tempfile()
            .unwrap();
        std::fs::write(file.path(), "test content").unwrap();
        file
    }
}
