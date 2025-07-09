// imports
use anyhow::anyhow;
use anyhow::Context;
use clap::{Arg, ArgGroup, Command};
use std::io::BufRead;

/// Config struct
///
/// Stores all global variables
pub struct Config {
	/// Path to input file
	pub path_input: std::path::PathBuf,
	/// Path to output directory. If not given is automatically determined from input path.
	pub path_output: std::path::PathBuf,
	/// Password to open backup file
	pub password: Vec<u8>,
	/// Should HMAC be verified?
	pub verify_mac: bool,
	/// Log / verbosity level
	pub log_level: log::LevelFilter,
	/// Overwrite existing output files?
	pub force_overwrite: bool,
	/// Output type
	pub output_type: crate::output::SignalOutputType,
	/// Use in memory sqlite database
	pub output_raw_db_in_memory: bool,
}

impl Config {
	/// Create new config object
	pub fn new() -> Result<Self, anyhow::Error> {
		let matches = Command::new(env!("CARGO_PKG_NAME"))
			.version(env!("CARGO_PKG_VERSION"))
			.about(env!("CARGO_PKG_DESCRIPTION"))
			.author(env!("CARGO_PKG_AUTHORS"))
			.arg(
				Arg::new("input-file")
					.help("Sets the input file to use")
					.value_name("INPUT")
					.required(true)
					.index(1),
			)
			.arg(
				Arg::new("output-path")
					.help("Directory to save output to. If not given, input file directory is used")
					.long("output-path")
					.short('o')
					.value_name("FOLDER"),
			)
			.arg(
				Arg::new("output-type")
					.help("Output type, either RAW, CSV or NONE")
					.long("output-type")
					.short('t')
					.value_name("TYPE"),
			)
			.arg(
				Arg::new("log-level")
					.help("Verbosity level, either DEBUG, INFO, WARN, or ERROR")
					.long("verbosity")
					.short('v')
					.value_name("LEVEL"),
			)
			.arg(
				Arg::new("force-overwrite")
					.help("Overwrite existing output files")
					.long("force")
					.short('f')
					.action(clap::ArgAction::SetTrue),
			)
			.arg(
				Arg::new("no-verify-mac")
					.help("Do not verify the HMAC of each frame in the backup")
					.long("no-verify-mac")
					.action(clap::ArgAction::SetTrue),
			)
			.arg(
				Arg::new("no-in-memory-db")
					.help("Do not use in memory sqlite database. Database is immediately created on disk (only considered with output type RAW).")
					.long("no-in-memory-db")
					.action(clap::ArgAction::SetTrue),
			)
			.arg(
				Arg::new("password-string")
					.help("Backup password (30 digits, with or without spaces)")
					.long("password")
					.value_name("PASSWORD")
					.short('p'),
			)
			.arg(
				Arg::new("password-file")
					.help("File to read the backup password from")
					.long("password-file")
					.value_name("FILE"),
			)
			.arg(
				Arg::new("password-command")
					.help("Read backup password from stdout from COMMAND")
					.long("password-command")
					.value_name("COMMAND"),
			)
			.group(
				ArgGroup::new("password")
					.args(["password-string", "password-file", "password-command"])
					.required(true)
					.multiple(false),
			)
			.get_matches();

		// input file handling
		let input_file = std::path::PathBuf::from(matches.get_one::<String>("input-file").unwrap());

		// output path handling
		let output_path = std::path::PathBuf::from(
			matches
				.get_one::<String>("output-path")
				.map(|s| s.as_str())
				.unwrap_or({
					input_file.file_stem().unwrap().to_str().context(
						"output-path is not given and path to input file could not be read.",
					)?
				}),
		);

		// password handling
		let mut password = {
			if matches.contains_id("password-string") {
				String::from(matches.get_one::<String>("password-string").unwrap())
			} else if matches.contains_id("password-file") {
				let password_file = std::io::BufReader::new(
					std::fs::File::open(matches.get_one::<String>("password-file").unwrap())
						.context("Unable to open password file")?,
				);
				password_file
					.lines()
					.next()
					.context("Password file is empty")?
					.context("Unable to read from password file")?
			} else if matches.contains_id("password-command") {
				let shell = std::env::var("SHELL").context("Could not determine current shell")?;
				let output = std::process::Command::new(shell)
					.arg("-c")
					.arg(matches.get_one::<String>("password-command").unwrap())
					.output()
					.context("Failed to execute password command")?;

				// check whether command returned an error code
				if output.status.success() {
					String::from_utf8(output.stdout)
						.context("Password command returned invalid characters")?
						.lines()
						.next()
						.context("Password command returned empty line")?
						.into()
				} else {
					return Err(anyhow!("Password command returned error code"));
				}
			} else {
				unreachable!()
			}
		};
		password.retain(|c| c >= '0' && c <= '9');
		let password = password.as_bytes().to_vec();
		if password.len() != 30 {
			return Err(anyhow!(
				"Wrong password length (30 numeric characters are expected)"
			));
		}

		// verbosity handling
		let log_level = if let Some(x) = matches.get_one::<String>("log-level") {
			match x.to_lowercase().as_str() {
				"debug" => log::LevelFilter::Debug,
				"info" => log::LevelFilter::Info,
				"warn" => log::LevelFilter::Warn,
				"error" => log::LevelFilter::Error,
				_ => return Err(anyhow!("Unknown log level given")),
			}
		} else {
			log::LevelFilter::Info
		};

		// determine output type
		let output_type = if let Some(x) = matches.get_one::<String>("output-type") {
			match x.to_lowercase().as_str() {
				"none" => crate::output::SignalOutputType::None,
				"raw" => crate::output::SignalOutputType::Raw,
				"csv" => crate::output::SignalOutputType::Csv,
				_ => return Err(anyhow!("Unknown output type given")),
			}
		} else {
			crate::output::SignalOutputType::Raw
		};

		Ok(Self {
			path_input: input_file,
			path_output: output_path,
			password,
			verify_mac: !matches.get_flag("no-verify-mac"),
			log_level,
			force_overwrite: matches.get_flag("force-overwrite"),
			output_type,
			output_raw_db_in_memory: !matches.get_flag("no-in-memory-db"),
		})
	}
}
