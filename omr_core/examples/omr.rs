use std::{collections::HashSet, time::Instant};

use fhe_core::CmLweCiphertext;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::Rlwe;
use omr_core::{KeyGen, OmrParameters, RetrievalParams, Retriever, SecondLevelField};
use rand::seq::SliceRandom;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tracing::{debug, info, Level};
use tracing_subscriber::fmt::format::FmtSpan;

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true)
        .with_max_level(Level::DEBUG)
        .init();

    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    debug!("Generating secret key pack...");
    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let ntt_table = secret_key_pack.second_level_ntt_table();
    let key = secret_key_pack.second_level_ntt_rlwe_secret_key();

    debug!("Generating sender and detector...");
    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);

    let detector = secret_key_pack.generate_detector(&mut rng);

    // let all_payloads_count: usize = 1 << 15;
    let all_payloads_count: usize = 1 << 9;
    let pertinent_count = 50;

    let mut pertinent = vec![false; all_payloads_count];
    pertinent[0..pertinent_count]
        .iter_mut()
        .for_each(|v| *v = true);
    pertinent.shuffle(&mut rng);

    let mut pertinent_set = HashSet::new();
    pertinent.iter().enumerate().for_each(|(i, &f)| {
        if f {
            pertinent_set.insert(i as usize);
        }
    });

    let start = Instant::now();
    debug!("Generating clues...");
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

    let start = Instant::now();
    debug!("Detecting...");
    let detect_list: Vec<Rlwe<SecondLevelField>> = clues_list
        .par_iter()
        .progress_with(pb.clone())
        .map(|clues| detector.detect(clues))
        .collect();
    pb.finish();
    debug!("Detect done");
    let end = Instant::now();
    info!("detect times: {:?}", end - start);

    let retrieval_params: RetrievalParams<SecondLevelField> = RetrievalParams::new(
        params.output_plain_modulus_value(),
        params.second_level_ring_dimension(),
        all_payloads_count,
        pertinent_count,
        130,
        25,
    );

    let mut retriever = Retriever::new(retrieval_params, ntt_table.clone(), key.clone());

    let retrieval_start = Instant::now();
    debug!("Start retrieval...");

    let retrieval_set;
    let mut times = 0;

    loop {
        let ciphertext = detector.generate_retrieval_ciphertext(retrieval_params, &detect_list);

        match retriever.retrieve(&ciphertext) {
            Ok(set) => {
                retrieval_set = set;
                break;
            }
            Err(_) => {}
        }

        times += 1;
        if times == retrieval_params.max_retrieve_cipher_count() {
            panic!("retrieval failed");
        }
    }

    debug!("Retrieval done");
    let retrieval_end = Instant::now();
    info!("retrieval times: {:?}", retrieval_end - retrieval_start);

    assert_eq!(pertinent_set, retrieval_set);
}
