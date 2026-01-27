# InstantOMR

## Abstract

Oblivious message retrieval (OMR) addresses the expensive message retrieval process in anonymous messaging systems and private blockchains. It enables resource-limited recipients to outsource detection and retrieval of their messages, while preserving privacy.

This work introduces **InstantOMR**, a novel OMR scheme that combines TFHE functional bootstrapping with standard RLWE operations in a hybrid design. **InstantOMR** is specifically optimized for low latency and high parallelizability. Our implementation, using the **Primus-fhe** library (and estimates based on **TFHE-rs**), demonstrates that **InstantOMR** offers the following key advantages:

- **Low latency:** **InstantOMR** achieves ${\sim} 860\times$ lower latency than **SophOMR**, the state-of-the-art single-server OMR construction. This translates directly into reduced recipient waiting time (by the same factor) in the *streaming* setting, where the detector processes incoming messages on-the-fly and returns a digest immediately upon the recipient becomes online.
- **Optimal parallelizability:** **InstantOMR** scales near-optimally with available CPU cores (by processing messages independently), so for high core counts it is faster than SophOMR (whose parallelism is constrained by reliance on BFV).

## Project file structure
- `omr_core`: The implementation of **InstantOMR**,
  - `src`: The main codes of **InstantOMR**.
  - `examples`:
    - `omr.rs`: An example of **InstantOMR** for the specific number of threads and message counts.
    - `omd.rs`: Check that the oblivious message detection is running correctly.
    - `omr_time_analyze.rs`: Measure the time cost of each stage when **InstantOMR** runs with different numbers of threads and varying message counts.
    - `omr_time_analyze2.rs`: Measure the time cost of each stage without detecting when **InstantOMR** runs with different numbers of threads and varying message counts. In this way, `omr_time_analyze2.rs` runs much faster than `omr_time_analyze.rs`
- `omr_core2`: Benchmark of the bootstrapping of the `tfhe-rs`.

## Install Rust

This project relies on Rust and the nightly toolchain. Installation can be done by following these steps:

1. Install build tools.
On Windows, please install [Visual Studio C++ Build tools](https://rust-lang.github.io/rustup/installation/windows-msvc.html).
On Ubuntu and Debian, please install build-essential according to the instructions below:
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential
   ```

1. Install Rust using rustup (the recommended Rust installer):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
   On Windows, one can download and run the installer ``rustup-init.exe'' from [https://rust-lang.org/tools/install/](https://rust-lang.org/tools/install/).

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

### [Latency]: Recover our latency (per message), table 1 column 2 row 6

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

### [Throughput]: Recover our runtime for D = 65536, single-core, table 1 column 3 row 6.
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


### [Parallelizability]: Run the InstantOMR example with arbitrary D and multi-threading:

```bash
cargo run --package omr_core --example omr --release -- --thread-count 8 --payload-count 8
# or
cargo run --package omr_core --example omr --release -- -t 8 -p 8
```

Parameters:
- `thread-count`: the number of threads to use for parallel processing (default: number of logical cores)
- `payload-count`: D, the number of messages to process (default: 8*thread-count)

It should be noted that the maximum payload-count supported by **InstantOMR** example is 65536, and the maximum thread-count is recommended to be the number of cores of the machine.
For example, a CPU with 8 cores and 16 threads can run 16 threads at the same time, but the optimal operating efficiency is achieved at 8 threads.

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