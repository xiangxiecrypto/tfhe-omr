use std::{collections::HashSet, time::Instant};

use algebra::{
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
};
use fhe_core::CmLweCiphertext;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::Rlwe;
use omr_core::{Detector, KeyGen, OmrParameters, Payload, SecondLevelField, SecretKeyPack, Sender};
use rand::{
    rngs::{StdRng, ThreadRng},
    seq::SliceRandom,
    Rng, RngCore, SeedableRng,
};
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

    let all_payloads_count = 1 << 9;
    println!("all_payloads_count: {}", all_payloads_count);

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

    debug!("Generating payloads...");
    let start = Instant::now();
    let payloads: Vec<Payload> = (0..all_payloads_count)
        .into_par_iter()
        .map_init(
            || rand::thread_rng(),
            |rng, _| {
                let mut data = [0u8; 612];
                rng.fill_bytes(&mut data);
                Payload(data)
            },
        )
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
    let pertivency_vector: Vec<Rlwe<SecondLevelField>> = clues_list
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
        .map(|_| detector.compress_pertivency_vector(retrieval_params, &pertivency_vector))
        .collect();
    let compress_end = Instant::now();
    info!("compress times: {:?}", compress_end - compress_start);
    info!(
        "compress times per ciphertext: {:?}",
        (compress_end - compress_start) / max_retrieve_cipher_count as u32
    );

    let seed = rng.gen();
    let mut seed_rng = StdRng::from_seed(seed);

    let combinations =
        detector.generate_random_combinations(&pertivency_vector, &payloads, &mut seed_rng);

    // receiver
    for ciphertext in ciphertexts.iter() {
        if let Ok(_) = retriever.retrieve(ciphertext) {
            break;
        }
    }

    let mut indices = retriever
        .retrieval_set()
        .iter()
        .copied()
        .collect::<Vec<_>>();
    indices.sort_unstable();

    let mut seed_rng = StdRng::from_seed(seed);

    let mut matrix = vec![vec![0u8; 60]; pertinent_count];
    let mut weights = vec![0u8; 60];
    let j = 0;
    for (k, &i) in indices.iter().enumerate() {
        while j != i {
            seed_rng.fill_bytes(&mut weights);
        }
        seed_rng.fill_bytes(&mut weights);

        matrix[k].copy_from_slice(&mut weights);
    }

    let ntt_table = secret_key_pack.second_level_ntt_table();
    let second_level_ring_dimesion = ntt_table.dimension();
    let sk = secret_key_pack.second_level_ntt_rlwe_secret_key();
    let mut combined_payload = vec![Payload([0u8; 612]); 60];
    let mut a: FieldPolynomial<SecondLevelField> =
        FieldPolynomial::zero(second_level_ring_dimesion);
    let mut temp: FieldNttPolynomial<SecondLevelField> =
        FieldNttPolynomial::zero(second_level_ring_dimesion);
    let mut b: FieldPolynomial<SecondLevelField> =
        FieldPolynomial::zero(second_level_ring_dimesion);
    let q = secret_key_pack
        .parameters()
        .second_level_blind_rotation_params()
        .modulus as f64;
    let r = q / 8.0;
    for (cipher, payload) in combinations.iter().zip(combined_payload.iter_mut()) {
        b.copy_from(cipher.b());
        ntt_table.inverse_transform_slice(b.as_mut_slice());

        cipher.a().mul_inplace(sk, &mut temp);
        a.copy_from(&temp);
        ntt_table.inverse_transform_slice(a.as_mut_slice());
        b -= &a;
        payload.0.iter_mut().zip(b.as_slice()).for_each(|(p, &b)| {
            let t = (b as f64 / r).round();
            *p = t as u8;
        });
    }
}
