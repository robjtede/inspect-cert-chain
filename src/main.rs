#![deny(rust_2018_idioms, future_incompatible)]

use std::{
    fs,
    io::{self, Read},
};

use clap::Parser;
use der::Decode as _;
use eyre::WrapErr as _;

mod ext;
mod fetch;
mod info;
mod util;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(long, conflicts_with = "file")]
    host: Option<String>,

    #[clap(long, conflicts_with = "host")]
    file: Option<String>,
}

// let anchor = &TLS_SERVER_ROOTS.0[3]; // seems to have wrong modulus ?!?

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    pretty_env_logger::try_init_timed()?;

    let args = Args::parse();

    let certs = if let Some(host) = &args.host {
        tracing::info!("fetching certificate chain from remote host: {host}");
        fetch::cert_chain(host)?
    } else if let Some(file) = &args.file {
        let mut input = if file == "-" {
            tracing::info!("reading certificate chain from stdin: {file}");

            let mut buf = String::new();
            let n_bytes = io::stdin().read_to_string(&mut buf).unwrap();
            tracing::trace!("read {n_bytes} from stdin");
            Box::new(io::Cursor::new(buf)) as Box<dyn io::BufRead>
        } else {
            tracing::info!("reading certificate chain from file: {file}");

            let file =
                fs::File::open(file).wrap_err_with(|| format!("could not open file: {file}"))?;
            Box::new(io::BufReader::new(file)) as Box<dyn io::BufRead>
        };

        tracing::debug!("reading certificate chain PEM files");
        let certs = rustls_pemfile::certs(&mut input)?;

        tracing::debug!("parsing certificate chain");
        certs
            .into_iter()
            .map(|der| x509_cert::Certificate::from_der(&der))
            .collect::<Result<_, _>>()?
    } else {
        return Err(eyre::eyre!("use --host or --file"));
    };

    let n_certs = certs.len();
    tracing::info!("chain contains {n_certs} certificates");

    if n_certs == 0 {
        return Err(eyre::eyre!("chain contained 0 certificates"));
    }

    for cert in certs.into_iter() {
        info::print_cert_info(&cert);

        println!();
        println!();
    }

    Ok(())
}
