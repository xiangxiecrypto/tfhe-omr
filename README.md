# InstantOMR

## Abstract

Oblivious message retrieval (OMR) enables resource-limited recipients to outsource the expensive message retrieval process in anonymous messaging systems while preserving privacy.

This work introduces **InstantOMR**, a novel OMR scheme that combines TFHE functional bootstrapping with standard RLWE operations in a hybrid design. **InstantOMR** is specifically optimized for low latency and high parallelizability. Our implementation using the **Primus-fhe** library (and estimates based on **TFHE-rs**) demonstrates that **InstantOMR** has the following key advantages:
- **Low latency:** **InstantOMR** achieves $> 480\times$ lower latency than **SophOMR** (the existing highest throughput OMR) and $> 280\times$ lower than **PerfOMR** (the existing lowest latency OMR) for a single message using a single CPU core with **TFHE-rs**. This translates directly into reduced recipient waiting time (by the same factor) in *streaming* setting, where the detector processes incoming messages on-the-fly and returns a digest immediately upon the recipient becomes online.
- **Optimal parallelizability:** **InstantOMR** scales near-optimally with available CPU cores. This is enabled by a design where each message is processed independently. With 180 physical cores, it achieves nearly $180\times$ speedup over single-core execution, approximately $4.5\times$ faster than **SophOMR**, which gains limited benefit from multi-threading due to its reliance on BFV.

## Install Rust

This project relies on Rust and the nightly toolchain. Installation can be done by following these steps:

1. Install Rust using rustup (the recommended Rust installer):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

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

### Recover our latency (per message), table 1 column 2 row 5

```bash
cargo run --package omr_core --example omr --release -- --thread-count 1 --payload-count 1
# or enable avx512
cargo +nightly run --package omr_core --example omr --features="nightly" --release -- --thread-count 1 --payload-count 1
```

Expected output:
```text
num threads: 1
all payloads count: 1
2025-04-14T14:08:22.064673Z DEBUG ThreadId(01) omr: Generating secret key pack...
2025-04-14T14:08:22.065688Z DEBUG ThreadId(01) omr: Generating sender and detector...
2025-04-14T14:08:22.719183Z DEBUG ThreadId(01) omr: Generating clues...
2025-04-14T14:08:22.720238Z  INFO ThreadId(01) omr: gen clues time: 945.4µs
2025-04-14T14:08:22.720301Z DEBUG ThreadId(01) omr: Generating payloads...
2025-04-14T14:08:22.720346Z  INFO ThreadId(01) omr: gen payloads time: 7.9µs
2025-04-14T14:08:22.720628Z DEBUG ThreadId(01) omr: Detecting...
[elapsed: 00:00:00] [####################################################################################]      1/1      [eta: 00:00:00] [0s]
2025-04-14T14:08:22.964331Z DEBUG ThreadId(01) omr: Detect done
2025-04-14T14:08:22.964418Z  INFO ThreadId(01) omr: detect time: 243.6431ms
2025-04-14T14:08:22.964466Z  INFO ThreadId(01) omr: detect time per message: 243.6431ms
2025-04-14T14:08:22.964819Z  INFO ThreadId(01) omr: encode indices times: 146.3µs
2025-04-14T14:08:22.964878Z  INFO ThreadId(01) omr: encode indices times per ciphertext: 48.766µs
2025-04-14T14:08:22.965031Z  INFO ThreadId(01) omr: encode pertinent payloads time: 79.5µs
2025-04-14T14:08:23.011517Z  INFO ThreadId(01) omr: decode time: 46.4251ms
2025-04-14T14:08:23.011637Z  INFO ThreadId(01) omr: All done
```

### Recover our runtime for D = 65536, single-core, table 1 column 3 row 5.
*This is expected to run at least around 4 hours.*

```bash
cargo run --package omr_core --example omr --release -- --thread-count 1 --payload-count 65536
# or enable avx512
cargo +nightly run --package omr_core --example omr --features="nightly" --release -- --thread-count 1 --payload-count 65536
```

Expected output:
```text
num threads: 1
all payloads count: 65536
2025-04-14T14:10:57.838257Z DEBUG ThreadId(01) omr: Generating secret key pack...
2025-04-14T14:10:57.838995Z DEBUG ThreadId(01) omr: Generating sender and detector...
2025-04-14T14:10:58.444275Z DEBUG ThreadId(01) omr: Generating clues...
2025-04-14T14:11:57.382862Z  INFO ThreadId(01) omr: gen clues time: 58.9381541s
2025-04-14T14:11:57.383002Z DEBUG ThreadId(01) omr: Generating payloads...
2025-04-14T14:11:57.403619Z  INFO ThreadId(01) omr: gen payloads time: 20.5511ms
2025-04-14T14:11:57.403832Z DEBUG ThreadId(01) omr: Detecting...
[elapsed: 04:15:40] [###########################################################################################] 65,536/65,536 [eta: 00:00:00] [0s]
2025-04-14T18:27:37.612223Z DEBUG ThreadId(01) omr: Detect done
2025-04-14T18:27:37.612318Z  INFO ThreadId(01) omr: detect time: 15340.2083335s
2025-04-14T18:27:37.612369Z  INFO ThreadId(01) omr: detect time per message: 234.073003ms
2025-04-14T18:27:41.094382Z  INFO ThreadId(01) omr: encode indices times: 3.4819539s
2025-04-14T18:27:41.094491Z  INFO ThreadId(01) omr: encode indices times per ciphertext: 696.39078ms
2025-04-14T18:28:05.354507Z  INFO ThreadId(01) omr: encode pertinent payloads time: 24.2598764s
2025-04-14T18:28:05.660156Z  INFO ThreadId(01) omr: decode time: 305.5313ms
2025-04-14T18:28:05.660291Z  INFO ThreadId(01) omr: All done
```


### Run the InstantOMR example with arbitrary D and multi-threading:

```bash
cargo run --package omr_core --example omr --release -- --thread-count 4 --payload-count 16
# or
cargo run --package omr_core --example omr --release -- -t 4 -p 16
```

Parameters:
- `thread-count`: the number of threads to use for parallel processing (default: number of logical cores)
- `payload-count`: D, the number of messages to process (default: 8*thread-count)

### For AVX512 support (requires nightly toolchain):
```bash
cargo +nightly run --package omr_core --example omr --features="nightly" --release -- --thread-count 4 --payload-count 16
# or
cargo +nightly run --package omr_core --example omr --features="nightly" --release -- -t 4 -p 16
```

Note: AVX512 support requires:
1. Nightly Rust toolchain
2. CPU with AVX512 support
3. `--features="nightly"` flag when running

## Notes

Our benchmark data was obtained through testing on a platform equipped with AVX-512 instructions.