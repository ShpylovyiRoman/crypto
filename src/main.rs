use std::{
    fs::File,
    io::{Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use crypto::{
    prime,
    rsa::{RsaPrivate, RsaPublic},
};
use serde::{de::DeserializeOwned, Serialize};
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

    Encrypt {
        #[structopt(long, short)]
        public: PathBuf,
    },

    Decrypt {
        #[structopt(long, short)]
        private: PathBuf,
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

                let public_path = append_suffix(&output, ".public")?;
                let private_path = append_suffix(&output, ".private")?;

                File::create(&public_path)?.write_as_base64(&public)?;
                File::create(&private_path)?.write_as_base64(&private)?;

                eprintln!("Public key is saved to {:?}", &public_path);
                eprintln!("Private key is saved to {:?}", &private_path);
            }
            RsaCmd::Encrypt { public } => {
                let key: RsaPublic = File::open(public)?.read_as_base64()?;

                let mut msg = Vec::new();
                std::io::stdin().read_to_end(&mut msg)?;

                let encrypted = key.encrypt(&msg)?;
                std::io::stdout().write_all(&encrypted)?;
            }

            RsaCmd::Decrypt { private } => {
                let key: RsaPrivate = File::open(private)?.read_as_base64()?;

                let mut msg = Vec::new();
                std::io::stdin().read_to_end(&mut msg)?;

                let decrypted = key.decrypt(&msg)?;
                std::io::stdout().write_all(&decrypted)?;
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

trait WriteAsBase64 {
    fn write_as_base64<S: Serialize>(&mut self, s: &S) -> anyhow::Result<()>;
}
trait ReadAsBase64 {
    fn read_as_base64<D: DeserializeOwned>(&mut self) -> anyhow::Result<D>;
}

impl<T> WriteAsBase64 for T
where
    T: Write,
{
    fn write_as_base64<S: Serialize>(&mut self, s: &S) -> anyhow::Result<()> {
        let serialized = bincode::serialize(s)?;
        let encoded = base64::encode(serialized);
        self.write_all(encoded.as_bytes())?;
        Ok(())
    }
}

impl<T> ReadAsBase64 for T
where
    T: Read,
{
    fn read_as_base64<D>(&mut self) -> anyhow::Result<D>
    where
        D: DeserializeOwned,
    {
        let mut encoded = String::new();
        self.read_to_string(&mut encoded)
            .context("reading from the source")?;
        let serialized = base64::decode(encoded).context("decoding base64")?;
        bincode::deserialize(&serialized).context("deserializing")
    }
}
