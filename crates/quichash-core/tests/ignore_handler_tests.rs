use quichash_core::ignore_handler::IgnoreHandler;
use std::fs;
use std::path::Path;

#[test]
fn test_ignore_handler_no_hashignore() {
    // Create a temporary directory without .hashignore
    let test_dir = "test_ignore_no_file";
    fs::create_dir_all(test_dir).unwrap();

    // Create handler
    let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

    // No files should be ignored
    assert!(!handler.should_ignore(Path::new("test.txt"), false));
    assert!(!handler.should_ignore(Path::new("subdir/file.txt"), false));

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_ignore_handler_basic_patterns() {
    // Create a temporary directory with .hashignore
    let test_dir = "test_ignore_basic";
    fs::create_dir_all(test_dir).unwrap();

    // Create .hashignore with basic patterns
    let hashignore_content = "*.log\n*.tmp\ntemp/\n";
    fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

    // Create handler
    let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

    // Test patterns
    assert!(handler.should_ignore(Path::new("test.log"), false));
    assert!(handler.should_ignore(Path::new("file.tmp"), false));
    assert!(handler.should_ignore(Path::new("temp"), true));
    assert!(!handler.should_ignore(Path::new("test.txt"), false));
    assert!(!handler.should_ignore(Path::new("data.csv"), false));

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_ignore_handler_negation() {
    // Create a temporary directory with .hashignore
    let test_dir = "test_ignore_negation";
    fs::create_dir_all(test_dir).unwrap();

    // Create .hashignore with negation pattern
    let hashignore_content = "*.log\n!important.log\n";
    fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

    // Create handler
    let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

    // Test patterns
    assert!(handler.should_ignore(Path::new("test.log"), false));
    assert!(handler.should_ignore(Path::new("debug.log"), false));
    assert!(!handler.should_ignore(Path::new("important.log"), false));

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_ignore_handler_comments() {
    // Create a temporary directory with .hashignore
    let test_dir = "test_ignore_comments";
    fs::create_dir_all(test_dir).unwrap();

    // Create .hashignore with comments
    let hashignore_content = "# This is a comment\n*.log\n# Another comment\n*.tmp\n";
    fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

    // Create handler
    let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

    // Test patterns (comments should be ignored)
    assert!(handler.should_ignore(Path::new("test.log"), false));
    assert!(handler.should_ignore(Path::new("file.tmp"), false));
    assert!(!handler.should_ignore(Path::new("test.txt"), false));

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_ignore_handler_subdirectories() {
    // Create a temporary directory with .hashignore
    let test_dir = "test_ignore_subdir";
    fs::create_dir_all(test_dir).unwrap();

    // Create .hashignore with directory patterns
    let hashignore_content = "build/\nnode_modules/\n*.o\n";
    fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

    // Create handler
    let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

    // Test directory patterns
    assert!(handler.should_ignore(Path::new("build"), true));
    assert!(handler.should_ignore(Path::new("node_modules"), true));
    assert!(handler.should_ignore(Path::new("src/main.o"), false));
    assert!(!handler.should_ignore(Path::new("src"), true));
    assert!(!handler.should_ignore(Path::new("src/main.c"), false));

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}
