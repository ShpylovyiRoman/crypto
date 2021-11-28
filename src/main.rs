use std::{
    fs::File,
    io::{stdin, stdout, Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use crypto::{
    prime,
    rsa::{RsaPrivate, RsaPublic, RsaSignature},
    sym::{Cipher, Key},
};
use serde::{de::DeserializeOwned, Serialize};
use structopt::StructOpt;

#[derive(Debug, structopt::StructOpt)]
/// Crypto tool for symmetric and asymmetric crypto operations, like key
/// generation, encryption, signing, etc.
///
/// DO NOT USE IT: it's an educational project.
struct Opt {
    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, structopt::StructOpt)]
enum Cmd {
    /// Subcommand dedicated to operations with prime numbers.
    Prime {
        #[structopt(subcommand)]
        subcmd: PrimeCmd,
    },
    /// Rsa key generation, encryption and signing.
    Rsa {
        #[structopt(subcommand)]
        subcmd: RsaCmd,
    },
    /// Symmetric encryption
    Sym {
        #[structopt(subcommand)]
        subcmd: SymCmd,
    },
}

#[derive(Debug, structopt::StructOpt)]
enum PrimeCmd {
    /// Generates prime number with a specified bit length
    Gen {
        /// Bit length of the prime. Too big values can took a lot of time.
        #[structopt(long, short)]
        size: NonZeroUsize,
    },
}

#[derive(Debug, structopt::StructOpt)]
enum RsaCmd {
    /// Generates new rsa keys with a specified length.
    Gen {
        /// Bit length of the rsa keys.
        #[structopt(long, short)]
        size: NonZeroUsize,

        /// Path for saving the keys.
        #[structopt(long, short)]
        output: PathBuf,
    },

    /// Paddingless encryption with RSA. You should specify the public key.
    /// The message comes into the stdin and encrypted ciphertext will come into
    /// the stdout. The message should not be bigger than modulus.
    Encrypt {
        /// Path to the public key
        #[structopt(long, short)]
        public: PathBuf,
    },

    /// Paddingless decryption with RSA. You should specify the private key.
    /// The ciphertext comes into the stdin and plain message will come into
    /// the stdout. The message should not be bigger than modulus.
    Decrypt {
        /// Path to the private key
        #[structopt(long, short)]
        private: PathBuf,
    },

    /// Paddingless signing. You should specify the private key. The message
    /// comes into the stdin and signature will come into stdout.
    Sign {
        /// Path to the private key
        #[structopt(long, short)]
        private: PathBuf,
    },

    /// Paddingless verification. You should specify the public key and path to
    /// signature. The message comes into stdin. If signature is ok, prints nothing
    /// and exits with 0.
    Verify {
        /// The path to the public key
        #[structopt(long, short)]
        public: PathBuf,

        /// Path to the signature
        #[structopt(long, short)]
        sig: PathBuf,
    },
}

#[derive(Debug, structopt::StructOpt)]
enum SymCmd {
    /// Encrypt message with the password. Message comes into the stdin and
    /// the ciphertext will come into stdout.
    Enc {
        #[structopt(long)]
        pass: String,
    },

    /// Decrypt message with the password. Ciphertext comes into the stdin and
    /// the message will come into stdout.
    Dec {
        #[structopt(long)]
        pass: String,
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

                let msg = read_raw_stdin()?;

                let encrypted = key.encrypt(&msg)?;
                stdout().write_all(&encrypted)?;
            }

            RsaCmd::Decrypt { private } => {
                let key: RsaPrivate = File::open(private)?.read_as_base64()?;

                let msg = read_raw_stdin()?;

                let decrypted = key.decrypt(&msg)?;
                stdout().write_all(&decrypted)?;
            }
            RsaCmd::Sign { private } => {
                let key: RsaPrivate = File::open(private)?.read_as_base64()?;

                let msg = read_raw_stdin()?;

                let sign = key.sign(&msg)?;
                stdout().write_as_base64(&sign)?;
            }
            RsaCmd::Verify { public, sig } => {
                let key: RsaPublic = File::open(public)?.read_as_base64()?;
                let sig: RsaSignature = File::open(sig)?.read_as_base64()?;

                let msg = read_raw_stdin()?;

                key.verify(&msg, &sig)?;
            }
        },
        Cmd::Sym { subcmd } => match subcmd {
            SymCmd::Enc { pass } => {
                let key = Key::from_pass(&pass)?;
                let cipher = Cipher::new(&key);

                let msg = read_raw_stdin()?;

                let encrypted = cipher.encrypt(&msg)?;
                stdout().write_all(&encrypted)?;
            }
            SymCmd::Dec { pass } => {
                let key = Key::from_pass(&pass)?;
                let cipher = Cipher::new(&key);

                let msg = read_raw_stdin()?;

                let decrypted = cipher.decrypt(&msg)?;
                stdout().write_all(&decrypted)?;
            }
        },
    }

    Ok(())
}

fn read_raw_stdin() -> anyhow::Result<Vec<u8>> {
    let mut raw = Vec::new();
    stdin().read_to_end(&mut raw)?;
    Ok(raw)
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
