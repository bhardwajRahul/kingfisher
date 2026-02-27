use clap::Parser;
use tempfile::tempdir;

use kingfisher::cli::{
    commands::scan::ScanOperation,
    global::{Command, CommandLineArgs},
};

#[test]
fn parse_git_clone_dir_and_keep_clones() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "https://github.com/octocat/Hello-World.git",
        "--git-clone-dir",
        dir.path().to_str().unwrap(),
        "--keep-clones",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert_eq!(scan_args.input_specifier_args.git_clone_dir.as_deref(), Some(dir.path()));
    assert!(scan_args.input_specifier_args.keep_clones);

    Ok(())
}

#[test]
fn keep_clones_defaults_to_false() -> anyhow::Result<()> {
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "github.com/octocat/Hello-World",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert!(scan_args.input_specifier_args.git_clone_dir.is_none());
    assert!(!scan_args.input_specifier_args.keep_clones);

    Ok(())
}

#[test]
fn deprecated_git_url_flag_still_parses() -> anyhow::Result<()> {
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "--git-url",
        "https://github.com/octocat/Hello-World.git",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert_eq!(scan_args.input_specifier_args.git_url.len(), 1);
    assert_eq!(
        scan_args.input_specifier_args.git_url[0].as_str(),
        "https://github.com/octocat/Hello-World.git"
    );
    assert!(scan_args.input_specifier_args.path_inputs.is_empty());

    Ok(())
}

#[test]
fn positional_git_url_examples_parse() -> anyhow::Result<()> {
    let examples = [
        ("github.com/kubernetes/kubernetes", "https://github.com/kubernetes/kubernetes"),
        ("https://github.com/org/repo", "https://github.com/org/repo"),
        ("gitlab.com/gitlab-org/gitlab", "https://gitlab.com/gitlab-org/gitlab"),
        (
            "https://gitlab.com/namespace/project.git",
            "https://gitlab.com/namespace/project.git",
        ),
    ];

    for (input, expected) in examples {
        let args =
            CommandLineArgs::try_parse_from(["kingfisher", "scan", input, "--no-update-check"])?;

        let command = match args.command {
            Command::Scan(scan_args) => scan_args,
            other => panic!("unexpected command parsed: {:?}", other),
        };

        let scan_args = match command.into_operation()? {
            ScanOperation::Scan(scan_args) => scan_args,
            op => panic!("expected scan operation, got {:?}", op),
        };

        assert_eq!(scan_args.input_specifier_args.git_url.len(), 1);
        assert_eq!(scan_args.input_specifier_args.git_url[0].as_str(), expected);
        assert!(scan_args.input_specifier_args.path_inputs.is_empty());
    }

    Ok(())
}

#[test]
fn turbo_mode_applies_speed_first_defaults() -> anyhow::Result<()> {
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        ".",
        "--turbo",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert!(scan_args.turbo);
    assert!(scan_args.no_base64);
    assert!(!scan_args.input_specifier_args.commit_metadata);

    Ok(())
}

#[test]
fn fast_alias_still_enables_turbo_mode() -> anyhow::Result<()> {
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        ".",
        "--turbo",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert!(scan_args.turbo);

    Ok(())
}
