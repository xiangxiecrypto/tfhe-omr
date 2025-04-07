# InstantOMR

## Install Rust

To work with this project, you'll need to install Rust and the nightly toolchain. Follow these steps:

1. Install Rust using rustup (the recommended Rust installer):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
   On Windows, you can download and run the [rustup-init.exe](https://win.rustup.rs/) installer.

2. After installation, verify Rust is installed correctly:
   ```bash
   rustc --version
   cargo --version
   ```

3. Install the nightly toolchain:
   ```bash
   rustup toolchain install nightly
   ```

4. Verify the nightly toolchain is available:
   ```bash
   rustc +nightly --version
   ```

For more information, see the [Rust installation guide](https://www.rust-lang.org/tools/install).

## Run InstantOMR example (omr_core\examples\omr.rs)

Run the InstantOMR example with custom parameters:

```bash
cargo run --package omr_core --example omr --release -- --thread-count 4 --payload-count 10
# or
cargo run --package omr_core --example omr --release -- -t 4 -p 10
```

Parameters:
- `thread-count`: Number of threads to use for parallel processing (default: number of logical cores)
- `payload-count`: Number of payloads to process (default: 8*thread-count)

For AVX512 support (requires nightly toolchain):
```bash
cargo +nightly run --package omr_core --example omr --features="nightly" --release -- --thread-count 4 --payload-count 10
# or
cargo +nightly run --package omr_core --example omr --features="nightly" --release -- -t 4 -p 10
```

Note: AVX512 support requires:
1. Nightly Rust toolchain
2. CPU with AVX512 support
3. `--features="nightly"` flag when running

## Notes

Our benchmark data was obtained through testing on a platform equipped with AVX-512 instructions.