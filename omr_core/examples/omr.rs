// cargo +nightly run --package omr_core --example omr --features="nightly" --release
// cargo run --package omr_core --example omr --release

use std::{collections::HashSet, time::Instant};

use clap::Parser;
use fhe_core::CmLweCiphertext;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::NttRlwe;
use omr_core::{Detector, KeyGen, OmrParameters, Payload, SecondLevelField, SecretKeyPack, Sender};
use rand::{
    rngs::{StdRng, ThreadRng},
    seq::SliceRandom,
    Rng, SeedableRng,
};
use rayon::prelude::*;
use tracing::{debug, info, Level};
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser)]
struct Args {
    /// thread count
    #[arg(short = 't', long)]
    thread_count: Option<usize>,
    /// payload count
    #[arg(short = 'p', long)]
    payload_count: Option<usize>,
}

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true)
        .with_max_level(Level::DEBUG)
        .init();

    let args = Args::parse();

    let thread_count = args.thread_count;

    let payload_count = args.payload_count;

    let max_cpu_cores = num_cpus::get();
    let num_threads = if let Some(thread_count) = thread_count {
        if thread_count > max_cpu_cores {
            max_cpu_cores
        } else {
            thread_count
        }
    } else {
        max_cpu_cores
    };
    println!("num threads: {}", num_threads);

    let all_payloads_count = if let Some(payload_count) = payload_count {
        if payload_count > 0 {
            payload_count
        } else {
            1
        }
    } else {
        num_threads * 8
    };
    println!("all payloads count: {}", all_payloads_count);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    debug!("Generating secret key pack...");
    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    debug!("Generating sender and detector...");
    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);

    let detector = secret_key_pack.generate_detector(&mut rng);

    omr(
        all_payloads_count,
        &secret_key_pack,
        &sender,
        &sender2,
        &detector,
        &mut rng,
    );
}

fn omr(
    all_payloads_count: usize,
    secret_key_pack: &SecretKeyPack,
    sender: &Sender,
    sender2: &Sender,
    detector: &Detector,
    rng: &mut ThreadRng,
) {
    let pertinent_count = if all_payloads_count <= 50 {
        all_payloads_count
    } else {
        50
    };

    let mut pertinent = vec![false; all_payloads_count];
    pertinent[0..pertinent_count]
        .iter_mut()
        .for_each(|v| *v = true);
    pertinent.shuffle(rng);

    let mut pertinent_set = HashSet::new();
    pertinent
        .iter()
        .enumerate()
        .filter(|(_i, f)| **f)
        .for_each(|(i, _)| {
            pertinent_set.insert(i as usize);
        });

    debug!("Generating clues...");
    let start = Instant::now();
    let clues_list: Vec<CmLweCiphertext<u16>> = pertinent
        .par_iter()
        .map_init(
            || rand::thread_rng(),
            |rng, &f| {
                if f {
                    sender.gen_clues(rng)
                } else {
                    sender2.gen_clues(rng)
                }
            },
        )
        .collect();
    let end = Instant::now();
    info!("gen clues time: {:?}", end - start);

    debug!("Generating payloads...");
    let start = Instant::now();
    let payloads: Vec<Payload> = (0..all_payloads_count)
        .into_par_iter()
        .map_init(|| rand::thread_rng(), |rng, _| Payload::random(rng))
        .collect();
    let end = Instant::now();
    info!("gen payloads time: {:?}", end - start);

    let pb = ProgressBar::new(all_payloads_count as u64);

    let sty = ProgressStyle::with_template(
        "[elapsed: {elapsed_precise}] [{wide_bar:.cyan/blue}] {human_pos:>6}/{human_len:6} [eta: {eta_precise}] [{duration}]",
    )
    .unwrap()
    .progress_chars("##-");

    pb.set_style(sty);

    debug!("Detecting...");
    let start = Instant::now();
    let pertinency_vector: Vec<NttRlwe<SecondLevelField>> = clues_list
        .par_iter()
        .progress_with(pb.clone())
        .map(|clues| detector.detect(clues))
        .collect();
    pb.finish();
    let end = Instant::now();
    debug!("Detect done");
    info!("detect time: {:?}", end - start);
    info!(
        "detect time per message: {:?}",
        (end - start) / all_payloads_count as u32
    );

    let mut retriever = secret_key_pack.generate_retriever(all_payloads_count, pertinent_count);
    let retrieval_params = retriever.params();

    let max_encode_indices_cipher_count = retrieval_params.max_encode_indices_cipher_count();

    let encode_indices_start = Instant::now();
    let encode_pertinent_indices: Vec<_> = (0..max_encode_indices_cipher_count)
        .into_par_iter()
        .map(|_| detector.encode_pertinent_indices(retrieval_params, &pertinency_vector))
        .collect();
    let encode_indices_end = Instant::now();
    info!(
        "encode indices times: {:?}",
        encode_indices_end - encode_indices_start
    );
    info!(
        "encode indices times per ciphertext: {:?}",
        (encode_indices_end - encode_indices_start) / max_encode_indices_cipher_count as u32
    );

    let seed = rng.gen();

    let combine_start = Instant::now();
    let encode_pertinent_payloads = detector.encode_pertinent_payloads(
        &pertinency_vector,
        &payloads,
        retrieval_params.combination_count(),
        retrieval_params.cmb_count_per_cipher(),
        &mut StdRng::from_seed(seed),
    );
    let combine_end = Instant::now();
    info!(
        "encode pertinent payloads time: {:?}",
        combine_end - combine_start
    );

    let mut indices = pertinent_set.iter().copied().collect::<Vec<usize>>();
    indices.sort_unstable();

    // retriever.test_combine(&indices, &combinations, &payloads, seed);

    let retrieve_start = Instant::now();
    let (indices, solved_payloads) = retriever
        .decode_digest(&encode_pertinent_indices, &encode_pertinent_payloads, seed)
        .unwrap();
    let retrieve_end = Instant::now();
    info!("decode time: {:?}", retrieve_end - retrieve_start);

    for (&i, p) in indices.iter().zip(solved_payloads.iter()) {
        if payloads[i] != *p {
            println!("Fail {}", i);
            let count = payloads[i]
                .iter()
                .zip(p.iter())
                .filter(|(a, b)| a != b)
                .count();
            println!("Different count: {}", count);
        }
    }

    info!("All done");
}
