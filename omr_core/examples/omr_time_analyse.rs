use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use rand::prelude::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use fhe_core::CmLweCiphertext;
use lattice::Rlwe;
use omr_core::{
    DetectTimeInfoPerMessage, Detector, KeyGen, OmrParameters, Retriever, SecondLevelField, Sender,
};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    #[serde(rename = "threads count")]
    num_threads: usize,
    #[serde(rename = "all payloads count")]
    all_payloads_count: usize,
    #[serde(rename = "pertinent count")]
    pertinent_count: usize,
    #[serde(rename = "total detect outer time")]
    #[serde(with = "humantime_serde")]
    total_detect_outer_time: Duration,
    #[serde(rename = "total detect inner time")]
    #[serde(with = "humantime_serde")]
    total_detect_inner_time: Duration,
    #[serde(rename = "total first level blind rotation outer time")]
    #[serde(with = "humantime_serde")]
    total_first_level_blind_rotation_outer_time: Duration,
    #[serde(rename = "total first level blind rotation inner time")]
    #[serde(with = "humantime_serde")]
    total_first_level_blind_rotation_inner_time: Duration,
    #[serde(rename = "total second level blind rotation time")]
    #[serde(with = "humantime_serde")]
    total_second_level_blind_rotation_time: Duration,
    #[serde(rename = "total trace time")]
    #[serde(with = "humantime_serde")]
    total_trace_time: Duration,
    #[serde(rename = "compress time")]
    #[serde(with = "humantime_serde")]
    compress_time: Duration,
}

fn main() {
    let mut wtr = csv::Writer::from_path("benchmark.csv").unwrap();

    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);

    let detector = secret_key_pack.generate_detector(&mut rng);

    // let num_threads_vec = vec![8, 16];
    let num_threads_vec = vec![1, 2, 4, 8, 16];
    // let num_threads_vec = vec![1, 2, 4, 8, 16, 32, 64, 96, 128, 160, 192];
    let pools = num_threads_vec
        .iter()
        .map(|&num_threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap()
        })
        .collect::<Vec<_>>();

    for all_payloads_count in (0..=15).rev().map(|i| 1 << i) {
        let pertinent_count = get_pertinent_count(all_payloads_count);
        let pertinent_tag = generate_pertinent_tag(all_payloads_count, pertinent_count);
        let pertinent_set = generate_pertinent_set(pertinent_tag.as_slice());
        let clues_list = generate_clues(&sender, &sender2, &pertinent_tag);

        for pool in pools.iter().rev() {
            let mut retriever =
                secret_key_pack.generate_retriever(all_payloads_count, pertinent_count);

            let (
                total_detect_outer_time,
                total_detect_inner_time,
                total_first_level_blind_rotation_outer_time,
                total_first_level_blind_rotation_inner_time,
                total_second_level_blind_rotation_time,
                total_trace_time,
                compress_time,
            ) = pool.install(|| omr(&detector, &clues_list, &pertinent_set, &mut retriever));

            let record = Record {
                num_threads: pool.current_num_threads(),
                all_payloads_count,
                pertinent_count,
                total_detect_outer_time,
                total_detect_inner_time,
                total_first_level_blind_rotation_outer_time,
                total_first_level_blind_rotation_inner_time,
                total_second_level_blind_rotation_time,
                total_trace_time,
                compress_time,
            };
            println!("{:#?}\n\n", record);
            wtr.serialize(record).unwrap();
        }
    }
    wtr.flush().unwrap();
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
    pertinent_tag.iter().enumerate().for_each(|(i, &f)| {
        if f {
            pertinent_set.insert(i);
        }
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

fn omr(
    detector: &Detector,
    clues_list: &[CmLweCiphertext<u16>],
    pertinent_set: &HashSet<usize>,
    retriever: &mut Retriever<SecondLevelField>,
) -> (
    Duration,
    Duration,
    Duration,
    Duration,
    Duration,
    Duration,
    Duration,
) {
    let total_detect_outer_start = Instant::now();
    let (detect_list, detect_inner_time_list): (
        Vec<Rlwe<SecondLevelField>>,
        Vec<DetectTimeInfoPerMessage>,
    ) = clues_list
        .par_iter()
        .map(|clues| detector.detect_with_time_info(clues))
        .collect();
    let total_detect_outer_time = total_detect_outer_start.elapsed();

    let retrieval_params = retriever.params();

    let max_retrieve_cipher_count = retrieval_params.max_retrieve_cipher_count();

    let compress_start = Instant::now();
    let ciphertexts: Vec<_> = (0..max_retrieve_cipher_count)
        .map(|_| detector.generate_retrieval_ciphertext(retrieval_params, &detect_list))
        .collect();
    let compress_time = compress_start.elapsed();

    for ciphertext in ciphertexts.iter() {
        if let Ok(_) = retriever.retrieve(ciphertext) {
            break;
        }
    }

    assert!(
        retriever.retrieval_set().difference(&pertinent_set).count() == 0,
        "retrieval failed"
    );

    let (
        total_detect_inner_time,
        total_first_level_blind_rotation_outer_time,
        total_first_level_blind_rotation_inner_time,
        total_second_level_blind_rotation_time,
        total_trace_time,
    ) = detect_inner_time_list.iter().fold(
        (
            Duration::default(),
            Duration::default(),
            Duration::default(),
            Duration::default(),
            Duration::default(),
        ),
        |acc, b| {
            let (
                total_detect_inner_time,
                total_first_level_blind_rotation_outer_time,
                total_first_level_blind_rotation_inner_time,
                total_second_level_blind_rotation_time,
                total_trace_time,
            ) = acc;
            (
                total_detect_inner_time + b.total_time,
                total_first_level_blind_rotation_outer_time
                    + b.total_first_level_blind_rotation_outer_time,
                total_first_level_blind_rotation_inner_time
                    + b.total_first_level_blind_rotation_inner_time,
                total_second_level_blind_rotation_time + b.second_level_blind_rotation_time,
                total_trace_time + b.trace_time,
            )
        },
    );
    (
        total_detect_outer_time,
        total_detect_inner_time,
        total_first_level_blind_rotation_outer_time,
        total_first_level_blind_rotation_inner_time,
        total_second_level_blind_rotation_time,
        total_trace_time,
        compress_time,
    )
}
