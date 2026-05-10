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
    pub stdout: bool,
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

    if args.len() > 2 {
        let mut skip = false;
        let mut i: usize = 2;
        for v in &args[2..] {
            i += 1;
            if skip { skip = false; continue; }
            match v.as_str() {
                "-q" | "--quiet" => { quiet = true; }
                "-c" | "--stdout" => { stdout = true; }

                "-p" | "--password" => {
                    if password.is_none() {
                        password = Some(args[i].clone());
                        skip = true;
                    } else {
                        return Err("one password option only".to_string());
                    }
                }

                "-o" | "--output" => {
                    if output_path.is_none() {
                        output_path = Some(args[i].clone());
                        skip = true;
                    } else {
                        return Err("one output option only".to_string());
                    }
                }

                _ => {
                    return Err("unknown option".to_string());
                }
            }
        }
    }

    if stdout && output_path.is_some() {
        return Err("cannot use --stdout together with --output".to_string());
    }

    // 当未指定 输出文件路径 时
    if output_path.is_none() {
        if stdout {
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

    Ok(Args { op, input_path, output_path: output, password, quiet, stdout })
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
        assert_eq!(parsed_args.stdout, false);
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
        assert_eq!(parsed_args.stdout, false);
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
        assert_eq!(parsed_args.stdout, true);
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
        assert_eq!(parsed_args.stdout, true);
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
        assert!(parsed_args.stdout);
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
