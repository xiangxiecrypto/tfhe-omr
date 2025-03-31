// cargo +nightly run --package omr_core --example omr_time_analyze --features="nightly" --release
// cargo run --package omr_core --example omr_time_analyze --release

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use chrono::prelude::*;
use rand::prelude::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use fhe_core::CmLweCiphertext;
use lattice::NttRlwe;
use omr_core::{Detector, KeyGen, OmrParameters, Payload, Retriever, SecondLevelField, Sender};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    #[serde(rename = "threads count")]
    num_threads: usize,
    #[serde(rename = "all payloads count")]
    all_payloads_count: usize,
    #[serde(rename = "pertinent count")]
    pertinent_count: usize,
    #[serde(rename = "detect time")]
    #[serde(with = "humantime_serde")]
    detect_time: Duration,
    #[serde(rename = "compress time")]
    #[serde(with = "humantime_serde")]
    compress_time: Duration,
    #[serde(rename = "combine time")]
    #[serde(with = "humantime_serde")]
    combine_time: Duration,
    #[serde(rename = "retrieve time")]
    #[serde(with = "humantime_serde")]
    retrieve_time: Duration,
}

pub struct Time {
    detect_time: Duration,
    compress_time: Duration,
    combine_time: Duration,
    retrieve_time: Duration,
}

const OFFSET: FixedOffset = FixedOffset::east_opt(8 * 60 * 60).unwrap();

fn main() {
    let mut wtr = csv::Writer::from_path("benchmark.csv").unwrap();

    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);

    let detector = secret_key_pack.generate_detector(&mut rng);

    // let num_threads_vec = vec![16];
    // let num_threads_vec = vec![1, 2, 4, 8, 16];
    let num_threads_vec = vec![1, 2, 4, 8, 16, 32, 64, 90, 96, 128, 160, 180];
    let pools = num_threads_vec
        .iter()
        .map(|&num_threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap()
        })
        .collect::<Vec<_>>();

    for all_payloads_count in (0..=16).rev().map(|i| 1 << i) {
        let pertinent_count = get_pertinent_count(all_payloads_count);
        let pertinent_tag = generate_pertinent_tag(all_payloads_count, pertinent_count);
        let pertinent_set = generate_pertinent_set(pertinent_tag.as_slice());
        let clues_list = generate_clues(&sender, &sender2, &pertinent_tag);
        let payloads_list = generate_payloads(all_payloads_count);

        let seed = rng.gen();

        for pool in pools.iter().rev() {
            let mut retriever =
                secret_key_pack.generate_retriever(all_payloads_count, pertinent_count);

            println!("Each Start time: {}", Utc::now().with_timezone(&OFFSET));
            let time = pool.install(|| {
                omr(
                    &detector,
                    &clues_list,
                    &payloads_list,
                    &pertinent_set,
                    &mut retriever,
                    seed,
                )
            });

            let record = Record {
                num_threads: pool.current_num_threads(),
                all_payloads_count,
                pertinent_count,
                detect_time: time.detect_time,
                compress_time: time.compress_time,
                combine_time: time.combine_time,
                retrieve_time: time.retrieve_time,
            };
            println!("{:#?}\n\n", record);
            wtr.serialize(record).unwrap();
            wtr.flush().unwrap();
        }
    }
}

fn get_pertinent_count(all_payloads_count: usize) -> usize {
    if all_payloads_count <= 50 {
        all_payloads_count
    } else {
        50
    }
}

fn generate_pertinent_tag(all_payloads_count: usize, pertinent_count: usize) -> Vec<bool> {
    let mut pertinent_tag = vec![false; all_payloads_count];
    pertinent_tag[0..pertinent_count]
        .iter_mut()
        .for_each(|v| *v = true);
    pertinent_tag.shuffle(&mut rand::thread_rng());
    pertinent_tag
}

fn generate_pertinent_set(pertinent_tag: &[bool]) -> HashSet<usize> {
    let mut pertinent_set = HashSet::new();
    pertinent_tag
        .iter()
        .enumerate()
        .filter(|(_i, f)| **f)
        .for_each(|(i, _)| {
            pertinent_set.insert(i as usize);
        });
    pertinent_set
}

fn generate_clues(
    sender: &Sender,
    sender2: &Sender,
    pertinent: &[bool],
) -> Vec<CmLweCiphertext<u16>> {
    pertinent
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
        .collect()
}

fn generate_payloads(all_payloads_count: usize) -> Vec<Payload> {
    (0..all_payloads_count)
        .into_par_iter()
        .map_init(|| rand::thread_rng(), |rng, _| Payload::random(rng))
        .collect()
}

fn omr(
    detector: &Detector,
    clues_list: &[CmLweCiphertext<u16>],
    payloads_list: &[Payload],
    pertinent_set: &HashSet<usize>,
    retriever: &mut Retriever<SecondLevelField>,
    seed: [u8; 32],
) -> Time {
    let retrieval_params = retriever.params();
    let max_retrieve_cipher_count = retrieval_params.max_retrieve_cipher_count();

    let time_0 = Instant::now();

    let pertinency_vector: Vec<NttRlwe<SecondLevelField>> = clues_list
        .par_iter()
        .map(|clues| detector.detect(clues))
        .collect();

    let time_1 = Instant::now();

    let compress_indices: Vec<_> = (0..max_retrieve_cipher_count)
        .into_par_iter()
        .map(|_| detector.compress_pertinency_vector(retrieval_params, &pertinency_vector))
        .collect();

    let time_2 = Instant::now();

    let combinations = detector.generate_random_combinations(
        &pertinency_vector,
        payloads_list,
        retrieval_params.combination_count(),
        retrieval_params.cmb_count_per_cipher(),
        &mut StdRng::from_seed(seed),
    );

    let time_3 = Instant::now();

    let (indices, solved_payloads) = retriever
        .retrieve(&compress_indices, &combinations, seed)
        .unwrap();

    let time_4 = Instant::now();

    assert!(
        retriever.retrieval_set().difference(&pertinent_set).count() == 0,
        "retrieval failed"
    );

    for (&i, p) in indices.iter().zip(solved_payloads.iter()) {
        if payloads_list[i] != *p {
            println!("Fail {}", i);
            let count = payloads_list[i]
                .iter()
                .zip(p.iter())
                .filter(|(a, b)| a != b)
                .count();
            println!("Different count: {}", count);
            panic!()
        }
    }

    Time {
        detect_time: time_1 - time_0,
        compress_time: time_2 - time_1,
        combine_time: time_3 - time_2,
        retrieve_time: time_4 - time_3,
    }
}
