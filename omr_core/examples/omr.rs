use std::{collections::HashSet, time::Instant};

use algebra::{
    arith::Xgcd,
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
};
use bigdecimal::{BigDecimal, RoundingMode};
use fhe_core::{CmLweCiphertext, NttRlweCiphertext};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::Rlwe;
use num_traits::{FromPrimitive, ToPrimitive};
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

    let all_payloads_count = 1 << 15;
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
    let combination_count = 60;

    let combinations = detector.generate_random_combinations(
        &pertivency_vector,
        &payloads,
        combination_count,
        &mut seed_rng,
    );

    // receiver
    for ciphertext in ciphertexts.iter() {
        if let Ok(_) = retriever.retrieve(ciphertext) {
            break;
        }
    }

    let retrieval_set = retriever.retrieval_set();
    assert!(retrieval_set.difference(&pertinent_set).count() == 0);
    let mut indices = retrieval_set.iter().copied().collect::<Vec<_>>();
    indices.sort_unstable();

    let retrieval_count = indices.len();

    let mut seed_rng = StdRng::from_seed(seed);
    let mut all_weights = vec![0u8; combination_count * all_payloads_count];
    seed_rng.fill_bytes(&mut all_weights);

    let mut matrix = vec![vec![0u8; combination_count]; retrieval_count];
    let mut matrix_iter = matrix.iter_mut();
    for (i, weights) in all_weights.chunks_exact(combination_count).enumerate() {
        if retrieval_set.contains(&i) {
            let row = matrix_iter.next().unwrap();
            row.copy_from_slice(weights);
        }
    }

    let mut test_combined_payload = vec![Payload::new(); combination_count];

    for (&index, row) in indices.iter().zip(matrix.iter()) {
        let payload = payloads[index];
        test_combined_payload
            .iter_mut()
            .zip(row.iter())
            .for_each(|(p, &w)| {
                *p = *p + (payload * w);
            });
    }

    let mut combined_payload =
        decode_combined_payload(secret_key_pack, &combinations, combination_count);

    for (i, (a, b)) in test_combined_payload
        .iter()
        .zip(combined_payload.iter())
        .enumerate()
    {
        a.0.iter()
            .zip(b.0.iter())
            .enumerate()
            .for_each(|(j, (x, y))| {
                if *x != *y {
                    println!("i: {}, j: {}, left: {}, right: {}", i, j, x, y);
                }
            });
    }

    let solved_payloads =
        solve_matrix_mod_2_8_ver_2(&mut matrix, &mut indices, &mut combined_payload);

    for (&i, p) in indices.iter().zip(solved_payloads.iter()) {
        if payloads[i] == *p {
            println!("Pass {}", i);
        } else {
            println!("Fail {}", i);
            let count = payloads[i]
                .0
                .iter()
                .zip(p.0.iter())
                .filter(|(a, b)| a != b)
                .count();
            println!("Different count: {}", count);
        }
    }

    info!("All done");
}

fn decode_combined_payload(
    skp: &SecretKeyPack,
    combinations: &[NttRlweCiphertext<SecondLevelField>],
    combination_count: usize,
) -> Vec<Payload> {
    let ntt_table = skp.second_level_ntt_table();
    let ring_dimesion = ntt_table.dimension();
    let sk = skp.second_level_ntt_rlwe_secret_key();

    let q = BigDecimal::from(
        skp.parameters()
            .second_level_blind_rotation_params()
            .modulus,
    );
    let plain = BigDecimal::from_u16(256).unwrap();

    let mut a: FieldPolynomial<SecondLevelField> = FieldPolynomial::zero(ring_dimesion);
    let mut b: FieldPolynomial<SecondLevelField> = FieldPolynomial::zero(ring_dimesion);
    let mut temp: FieldNttPolynomial<SecondLevelField> = FieldNttPolynomial::zero(ring_dimesion);

    let mut combined_payload = vec![Payload::new(); combination_count];

    for (cipher, payload) in combinations.iter().zip(combined_payload.iter_mut()) {
        b.copy_from(cipher.b());
        ntt_table.inverse_transform_slice(b.as_mut_slice());

        cipher.a().mul_inplace(sk, &mut temp);
        a.copy_from(&temp);
        ntt_table.inverse_transform_slice(a.as_mut_slice());
        b -= &a;
        payload.0.iter_mut().zip(b.as_slice()).for_each(|(p, &b)| {
            let mut t = (BigDecimal::from_u64(b).unwrap() * &plain / &q)
                .with_scale_round(0, RoundingMode::HalfUp);
            if t >= q {
                t -= &q;
            }
            let t = t.to_u64().unwrap() as u8;
            *p = t;
        });
    }
    combined_payload
}

fn solve_matrix_mod_2_8(
    matrix: &mut [Vec<u8>],
    indices: &mut [usize],
    combined_payload: &mut [Payload],
) -> Vec<Payload> {
    let cmb_len = combined_payload.len();
    let indices_len = indices.len();

    let mut coeff = vec![0u8; cmb_len];

    for i in 0..indices_len {
        let mut odd_index = i;
        for &v in matrix[i][i..].iter() {
            if v % 2 == 1 {
                break;
            }
            odd_index += 1;
        }

        if odd_index == combined_payload.len() {
            panic!("Matrix is not invertible");
        }

        if i != odd_index {
            combined_payload.swap(i, odd_index);
            matrix.iter_mut().for_each(|w| w.swap(i, odd_index));
        }

        let value = matrix[i][i];
        if value != 1 {
            let (inv, gcd) = Xgcd::gcdinv(value as u16, 1 << 8);
            assert_eq!(gcd, 1);
            let inv = inv as u8;

            matrix[i..].iter_mut().for_each(|w| {
                w[i] = w[i].wrapping_mul(inv);
            });
            combined_payload[i] *= inv;
        }

        if i == indices_len - 1 {
            break;
        }

        matrix[i][i + 1..]
            .iter()
            .zip(coeff.iter_mut())
            .for_each(|(&v, c)| {
                *c = v;
            });

        matrix[i..].iter_mut().for_each(|w| {
            let base = w[i];
            w[i + 1..].iter_mut().zip(coeff.iter()).for_each(|(v, &c)| {
                *v = v.wrapping_sub(base.wrapping_mul(c));
            })
        });

        let payload_base = combined_payload[i];
        combined_payload[i + 1..]
            .iter_mut()
            .zip(coeff.iter())
            .for_each(|(p, &c)| {
                *p -= payload_base * c;
            });

        coeff.fill(0);
    }

    let mut solved_payloads = vec![Payload::new(); indices_len];
    for i in (0..indices_len).rev() {
        solved_payloads[i] = combined_payload[i];
        if i > 0 {
            for j in 0..i {
                let c = matrix[i][j];
                if c != 0 {
                    combined_payload[j] -= solved_payloads[i] * c;
                }
            }
        }
    }

    solved_payloads
}

fn solve_matrix_mod_2_8_ver_2(
    matrix: &mut [Vec<u8>],
    indices: &mut [usize],
    combined_payload: &mut [Payload],
) -> Vec<Payload> {
    let cmb_len = combined_payload.len();
    let indices_len = indices.len();

    let mut new_matrix = vec![vec![0u8; indices_len]; cmb_len];
    for i in 0..indices_len {
        for j in 0..cmb_len {
            new_matrix[j][i] = matrix[i][j];
        }
    }

    for i in 0..indices_len {
        let mut odd_index = None;
        for j in i..cmb_len {
            if new_matrix[j][i] % 2 == 1 {
                odd_index = Some(j);
                break;
            }
        }

        if odd_index.is_none() {
            panic!("Matrix is not invertible");
        }

        let odd_index = odd_index.unwrap();
        if i != odd_index {
            new_matrix.swap(i, odd_index);
            combined_payload.swap(i, odd_index);
        }

        let value = new_matrix[i][i];
        if value != 1 {
            let (inv, gcd) = Xgcd::gcdinv(value as u16, 1 << 8);
            assert_eq!(gcd, 1, "value: {}", value);
            let inv = inv as u8;

            new_matrix[i][i..].iter_mut().for_each(|w| {
                *w = w.wrapping_mul(inv);
            });
            combined_payload[i] *= inv;
        }

        if i == indices_len - 1 {
            break;
        }

        for j in i + 1..cmb_len {
            let c = new_matrix[j][i];
            if c != 0 {
                for k in i..indices_len {
                    new_matrix[j][k] =
                        new_matrix[j][k].wrapping_sub(new_matrix[i][k].wrapping_mul(c));
                }
                combined_payload[j] -= combined_payload[i] * c;
            }
        }
    }

    for i in (0..indices_len).rev() {
        if i > 0 {
            for j in 0..i {
                let c = new_matrix[j][i];
                if c != 0 {
                    combined_payload[j] -= combined_payload[i] * c;
                    new_matrix[j][i] = 0;
                }
            }
        }
    }

    combined_payload.iter().copied().take(indices_len).collect()
}
