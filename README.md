# Substrate SM2

substrate-sm2 is a simple SM2 integration for Substrate. With this, you can sign message with SM2 algorithm and submit it into substrate for verifying.

**DO NOT** use it as-is in real applications.

## 

## Build

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Build Wasm and native code:

```bash
cargo build --release
```

## Run

### Single node development chain

Purge any existing developer chain state:

```bash
./target/release/node-template purge-chain --dev
```

Start a development chain with:

```bash
./target/release/node-template --dev
```

Detailed logs may be shown by running the node with the following environment variables set: `RUST_LOG=debug RUST_BACKTRACE=1 cargo run -- --dev`.

## Test
Go to `utils`, run:

```bash
cargo run --release
```

for testing. For this showcase, you will see:

```bash
    Finished release [optimized] target(s) in 8.95s
     Running `/Users/hammer/Documents/paritytech/code/hammeWang/substrate-sm2/target/release/utils`
Balance transfer success: value: 10000
```

## Thanks
Many thanks to [CITA](https://github.com/citahub/libsm)