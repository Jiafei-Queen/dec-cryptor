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
pub fn parse_args(args: &Vec<String>) -> Result<Args, String> {
    // 标准：~ -e file （两个往上）
    if args.len() < 2 {
        return Err("arg too short".to_string());
    }

    // 参数分类
    let op = {
        match args[0].as_str() {
            "-e" | "--encrypt" => { Op::Enc }
            "-d" | "--decrypt" => { Op::Dec }
            _ => {
                return Err("unknown operation".to_string())
            }
        }
    };

    // 获取 输出文件路径
    let input_path = args[1].clone();

    // 检查 输入文件 是否存在
    if !Path::new(&input_path).exists() {
        return Err("no such file".to_string())
    }

    let mut quiet = false;
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

                "-p" | "--password" => {
                    if password == None {
                        password = Some(args[i].clone());
                        skip = true;
                    } else {
                        return Err("one password option only".to_string());
                    }
                }

                "-o" | "--output" => {
                    if output_path == None {
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

    // 当未指定 输出文件路径 时
    if output_path == None {
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

    let output = match output_path {
        Some(s) => s,
        _ => unreachable!()
    };

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
}