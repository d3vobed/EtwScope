use clap::Parser;

mod etw;
mod parser;
mod stream;

#[derive(Parser)]
#[command(author, version, about = "ETWScope Backend - High-performance ETW JSON streaming engine")]
struct Cli {
    /// List of ETW providers to subscribe to
    #[arg(short, long, value_delimiter = ',')]
    providers: Option<Vec<String>>,

    /// Mock mode: Read from a JSON file and stream it as if it were live
    #[arg(long)]
    mock: Option<String>,

    /// Events per second to stream in mock mode (0 for unlimited)
    #[arg(long, default_value_t = 100)]
    eps: u64,
}

fn main() {
    let cli = Cli::parse();

    if let Some(filepath) = cli.mock {
        etw::start_mock_stream(&filepath, cli.eps);
    } else {
        #[cfg(windows)]
        {
            let providers = cli.providers.unwrap_or_else(|| vec![
                "Microsoft-Windows-Kernel-Process".to_string(),
                "Microsoft-Windows-Kernel-Audit-API-Calls".to_string(),
            ]);
            etw::start_real_etw_session(providers);
        }

        #[cfg(not(windows))]
        {
            eprintln!("Error: Real ETW subscription is only available on Windows.");
            eprintln!("Please use --mock <file.json> to stream test data on Linux.");
            std::process::exit(1);
        }
    }
}
