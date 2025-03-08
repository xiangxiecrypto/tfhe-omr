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
    DetectTimeInfo, DetectTimeInfoPerMessage, Detector, KeyGen, OmrParameters, Retriever,
    SecondLevelField, Sender,
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
    #[serde(rename = "total first level bootstrapping time")]
    #[serde(with = "humantime_serde")]
    total_first_level_bootstrapping_time: Duration,
    #[serde(rename = "total second level bootstrapping time")]
    #[serde(with = "humantime_serde")]
    total_second_level_bootstrapping_time: Duration,
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

    let num_threads_vec = vec![8, 16];
    // let num_threads_vec = vec![1, 2, 4, 8, 16];
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

    for all_payloads_count in (0..=8).rev().map(|i| 1 << i) {
        let pertinent_count = get_pertinent_count(all_payloads_count);
        let pertinent_tag = generate_pertinent_tag(all_payloads_count, pertinent_count);
        let pertinent_set = generate_pertinent_set(pertinent_tag.as_slice());
        let clues_list = generate_clues(&sender, &sender2, &pertinent_tag);

        for pool in pools.iter().rev() {
            let mut retriever =
                secret_key_pack.generate_retriever(all_payloads_count, pertinent_count);

            let (total_detect_outer_time, time_info, compress_time) =
                pool.install(|| omr(&detector, &clues_list, &pertinent_set, &mut retriever));

            let record = Record {
                num_threads: pool.current_num_threads(),
                all_payloads_count,
                pertinent_count,
                total_detect_outer_time,
                total_detect_inner_time: time_info.total_detect_time,
                total_first_level_bootstrapping_time: time_info
                    .total_first_level_bootstrapping_time,
                total_second_level_bootstrapping_time: time_info
                    .total_second_level_bootstrapping_time,
                total_trace_time: time_info.total_trace_time,
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
) -> (Duration, DetectTimeInfo, Duration) {
    let time_0 = Instant::now();

    let (pertivency_vector, detect_inner_time_list): (
        Vec<Rlwe<SecondLevelField>>,
        Vec<DetectTimeInfoPerMessage>,
    ) = clues_list
        .par_iter()
        .map(|clues| detector.detect_with_time_info(clues))
        .collect();

    let time_1 = Instant::now();

    let retrieval_params = retriever.params();
    let max_retrieve_cipher_count = retrieval_params.max_retrieve_cipher_count();
    let ciphertexts: Vec<_> = (0..max_retrieve_cipher_count)
        .map(|_| detector.compress_pertivency_vector(retrieval_params, &pertivency_vector))
        .collect();

    let time_2 = Instant::now();

    for ciphertext in ciphertexts.iter() {
        if let Ok(_) = retriever.retrieve_indices(ciphertext) {
            break;
        }
    }

    assert!(
        retriever.retrieval_set().difference(&pertinent_set).count() == 0,
        "retrieval failed"
    );

    let time_info = detect_inner_time_list
        .into_iter()
        .fold(DetectTimeInfo::default(), |acc, b| acc + b);

    (time_1 - time_0, time_info, time_2 - time_1)
}
