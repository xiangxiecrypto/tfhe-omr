use std::{collections::HashSet, time::Instant};

use fhe_core::CmLweCiphertext;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::Rlwe;
use omr_core::{Detector, KeyGen, OmrParameters, SecondLevelField, SecretKeyPack, Sender};
use rand::{rngs::ThreadRng, seq::SliceRandom};
use rayon::prelude::*;
use tracing::{debug, info, Level};
use tracing_subscriber::fmt::format::FmtSpan;

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true)
        .with_max_level(Level::DEBUG)
        .init();

    let num_threads = 16;
    println!("num_threads: {}", num_threads);

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

    for i in (0..=15).rev() {
        println!("\nall_payloads_count: {}", 1 << i);
        println!("all_payloads_count: 2^{}", i);
        let all_payloads_count = 1 << i;
        omr(
            all_payloads_count,
            &secret_key_pack,
            &sender,
            &sender2,
            &detector,
            &mut rng,
        );
    }
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
    pertinent.iter().enumerate().for_each(|(i, &f)| {
        if f {
            pertinent_set.insert(i as usize);
        }
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

    let pb = ProgressBar::new(all_payloads_count as u64);

    let sty = ProgressStyle::with_template(
        "[elapsed: {elapsed_precise}] [{wide_bar:.cyan/blue}] {human_pos:>6}/{human_len:6} [eta: {eta_precise}] [{duration}]",
    )
    .unwrap()
    .progress_chars("##-");

    pb.set_style(sty);

    debug!("Detecting...");
    let start = Instant::now();
    let detect_list: Vec<Rlwe<SecondLevelField>> = clues_list
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

    let max_retrieve_cipher_count = retrieval_params.max_retrieve_cipher_count();

    let compress_start = Instant::now();
    let ciphertexts: Vec<_> = (0..max_retrieve_cipher_count)
        .map(|_| detector.generate_retrieval_ciphertext(retrieval_params, &detect_list))
        .collect();
    let compress_end = Instant::now();
    info!("compress times: {:?}", compress_end - compress_start);
    info!(
        "compress times per ciphertext: {:?}",
        (compress_end - compress_start) / max_retrieve_cipher_count as u32
    );

    for ciphertext in ciphertexts.iter() {
        if let Ok(_) = retriever.retrieve(ciphertext) {
            return;
        }
    }

    assert!(
        retriever.retrieval_set().difference(&pertinent_set).count() == 0,
        "retrieval failed"
    );
}
