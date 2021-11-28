# crypto
Crypto tool for symmetric and asymmetric crypto operations, like key generation, encryption, signing, etc.

DO NOT USE IT: it's an educational project.

```
USAGE:
    $ crypto <SUBCOMMAND>

FLAGS:
    -h, --help
            Prints help information

    -V, --version
            Prints version information


SUBCOMMANDS:
    help     Prints this message or the help of the given subcommand(s)
    prime    Subcommand dedicated to operations with prime numbers
    rsa      Rsa key generation, encryption and signing
    sym      Symmetric encryption
```

## Prime

Subcommand dedicated to operations with prime numbers

```
USAGE:
    crypto prime <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    gen     Generates prime number with a specified bit length
    help    Prints this message or the help of the given subcommand(s)

EXAMPLE:
    $ crypto prime gen --size 256
```

## Rsa

Rsa key generation, encryption and signing

```
USAGE:
    crypto rsa <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt    Paddingless decryption with RSA. You should specify the private key. The ciphertext comes into the
               stdin and plain message will come into the stdout. The message should not be bigger than modulus
    encrypt    Paddingless encryption with RSA. You should specify the public key. The message comes into the stdin
               and encrypted ciphertext will come into the stdout. The message should not be bigger than modulus
    gen        Generates new rsa keys with a specified length
    help       Prints this message or the help of the given subcommand(s)
    sign       Paddingless signing. You should specify the private key. The message comes into the stdin and
               signature will come into stdout
    verify     Paddingless verification. You should specify the public key and path to signature. The message comes
               into stdin. If signature is ok, prints nothing and exits with 0
```

### Examples

- Generate new keys
  ```bash
  $ cargo run -- rsa gen --size 512 -o key
  Public key is saved to "key.public"
  Private key is saved to "key.private"
  $ cat key.public
  AQEAAAAAAAAAAQABAAEQAAAAAAAAANNLfw4qQtYk1aaE2tVitPIB6Z2S3ZTgVwKTD0xMGE7+GpoIbm685009BmxgCNrD3rWkvCZbhgp5V30U9f4FDHo=
  ```

- Encrypt with rsa
  ```bash
  $ echo "some data" > data
  $ cargo run -- rsa encrypt --public key.public < data > data.enc
  $ xxd data.enc
  00000000: 0867 e343 217c 8c6f 459b bdeb 2a72 aed5  .g.C!|.oE...*r..
  00000010: 5ebf b158 dc0c 2c89 f6db 7b57 7470 0a1f  ^..X..,...{Wtp..
  00000020: 88c3 8b24 7233 0d2e 9bad 2757 f24d 7de9  ...$r3....'W.M}.
  00000030: 0471 bc45 022d fc0a facd 90ae 1007 5b33  .q.E.-........[3
  ```

- Decrypt with rsa
  ```bash
  $ cargo run -- rsa decrypt --private key.private < data.enc
  some data
  ```

- Signing
  ```bash
  $ cargo run -- rsa sign --private key.private < data > data.sig
  $ cat data.sig
  ARAAAAAAAAAAO6ygxIFogFQCkZz5Arvh6CrzEPh7eH4wZSevqUJ4TMLuMOeU3m4pdXCKffkairv/FRJVnJZV2J8bgTkNLKqOZQ==
  ```

- Verification
  ```bash
  $ cargo run -- rsa verify --public key.public --sig data.sig < data
  # no messages so everything is ok
  ```

## Symmetric

Symmetric encryption

```
USAGE:
    crypto sym <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    dec     Decrypt message with the password. Ciphertext comes into the stdin and the message will come into stdout
    enc     Encrypt message with the password. Message comes into the stdin and the ciphertext will come into stdout
    help    Prints this message or the help of the given subcommand(s)
```

### Examples

- Encryption
  ```bash
  $ cargo run -- sym enc --pass "super-duper-secret-password" < data > data.enc
  $ xxd data.enc
  00000000: 0fff 19db c957 65ee 59be fdc1 b62c 3a5d  .....We.Y....,:]
  00000010: 0580 2422 126a 4a7d b448 4b3a 4a15 44a5  ..$".jJ}.HK:J.D.
  00000020: 95a0 1525 79c7                           ...%y.
  ```

- Decryption
  ```bash
  $ cargo run -- sym dec --pass "super-duper-secret-password" < data.enc
  some data
  ```
