use std::{
    fs::File,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use crypto::prime;
use structopt::StructOpt;

#[derive(Debug, structopt::StructOpt)]
struct Opt {
    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, structopt::StructOpt)]
enum Cmd {
    Prime {
        #[structopt(subcommand)]
        subcmd: PrimeCmd,
    },
    Rsa {
        #[structopt(subcommand)]
        subcmd: RsaCmd,
    },
}

#[derive(Debug, structopt::StructOpt)]
enum PrimeCmd {
    Gen {
        #[structopt(long, short)]
        size: NonZeroUsize,
    },
}

#[derive(Debug, structopt::StructOpt)]
enum RsaCmd {
    Gen {
        #[structopt(long, short)]
        size: NonZeroUsize,

        #[structopt(long, short)]
        output: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();

    match opt.cmd {
        Cmd::Prime { subcmd } => match subcmd {
            PrimeCmd::Gen { size } => {
                let prime = prime::gen(size.get());
                println!("{}", prime);
            }
        },
        Cmd::Rsa { subcmd } => match subcmd {
            RsaCmd::Gen { size, output } => {
                let (public, private) = crypto::rsa::gen_pair(size.get())?;

                let public_path = append_suffix(&output, ".public.json")?;
                let private_path = append_suffix(&output, ".private.json")?;

                let public_file = File::create(&public_path)?;
                let private_file = File::create(&private_path)?;

                serde_json::to_writer(public_file, &public)?;
                serde_json::to_writer(private_file, &private)?;
                eprintln!("Public key is saved to {:?}", &public_path);
                eprintln!("Private key is saved to {:?}", &private_path);
            }
        },
    }

    Ok(())
}

fn append_suffix(path: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow!("invalid filename"))?
        .to_owned();

    name.push(suffix);

    Ok(path.with_file_name(name))
}
