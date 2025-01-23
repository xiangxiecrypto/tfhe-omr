use std::{collections::HashSet, time::Instant};

use algebra::{
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    Field,
};
use fhe_core::CmLweCiphertext;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::{NttRlwe, Rlwe};
use omr_core::{KeyGen, OmrParameters, SecondLevelField};
use rand::{distributions::Uniform, prelude::Distribution, seq::SliceRandom};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tracing::{debug, Level};
use tracing_subscriber::fmt::format::FmtSpan;

type Inner = <SecondLevelField as Field>::ValueT; // inner type

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true)
        .with_max_level(Level::DEBUG)
        .init();

    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    let fp = <SecondLevelField as Field>::MODULUS_VALUE;
    let ft = params.output_plain_modulus_value();

    let decode = |c: Inner| (c as f64 * ft as f64 / fp as f64).round() as Inner % ft;

    debug!("Generating secret key pack...");
    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let ntt_table = secret_key_pack.second_level_ntt_table();
    let key = secret_key_pack.second_level_ntt_rlwe_secret_key();

    debug!("Generating sender and detector...");
    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);

    let detector = secret_key_pack.generate_detector(&mut rng);

    let all_payloads_count: usize = 1 << 15;
    let pertinent_count = 50;

    let index_slots_per_budget = all_payloads_count
        .next_power_of_two()
        .trailing_zeros()
        .div_ceil(ft.trailing_zeros()) as usize;

    let mut pertinent = vec![false; all_payloads_count];
    pertinent[0..pertinent_count]
        .iter_mut()
        .for_each(|v| *v = true);
    pertinent.shuffle(&mut rng);

    let mut pertinent_set = HashSet::new();
    pertinent.iter().enumerate().for_each(|(i, &f)| {
        if f {
            pertinent_set.insert(i as u64);
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
    println!("gen clues time: {:?}", end - start);

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
    println!("detect time: {:?}", end - start);

    let mut retrieval_set = HashSet::new();

    let retrieval_start = Instant::now();
    debug!("Start retrieval...");
    let budget_count = 130;
    let retrieval_count = 25;
    let slots_per_budget = index_slots_per_budget + 1;
    let slots = params.second_level_ring_dimension();
    let times_per_cipher = slots / (budget_count * slots_per_budget);
    let cipher_count = retrieval_count / times_per_cipher;

    let budget_distr = Uniform::new(0, budget_count);

    let mut poly: FieldPolynomial<SecondLevelField> = FieldPolynomial::zero(slots);
    let mut ntt_poly: FieldNttPolynomial<SecondLevelField> = FieldNttPolynomial::zero(slots);

    let mut ciphertext: NttRlwe<SecondLevelField> = NttRlwe::zero(slots);
    let mut temp: NttRlwe<SecondLevelField> = NttRlwe::zero(slots);

    let mask = ft - 1;
    let shift_bits = ft.trailing_zeros();

    for c in 0..cipher_count {
        println!("retrieval round: {}", c + 1);
        let per_retrieval_start = Instant::now();
        ciphertext.set_zero();

        detect_list.iter().enumerate().for_each(|(i, detect)| {
            poly.set_zero();
            budget_distr
                .sample_iter(&mut rng)
                .enumerate()
                .take(times_per_cipher)
                .for_each(|(j, budget_index)| {
                    let mut i = i as u64;
                    let address = (j * budget_count + budget_index) * slots_per_budget;

                    let mut k = 0;
                    while i != 0 {
                        poly[address + k] = i & mask;
                        i >>= shift_bits;
                        k += 1;
                    }

                    poly[address + index_slots_per_budget] = 1;
                });
            ntt_poly.copy_from(&poly);
            ntt_table.transform_slice(ntt_poly.as_mut_slice());

            detect.mul_ntt_polynomial_inplace(&ntt_poly, ntt_table, &mut temp);
            ciphertext.add_assign_element_wise(&temp);
        });

        let decrypted_ntt = ciphertext.b() - ciphertext.a().clone() * &**key;
        let decrypted = ntt_table.inverse_transform_inplace(decrypted_ntt);
        let decoded = decrypted.into_iter().map(decode).collect::<Vec<Inner>>();

        decoded
            .chunks_exact(budget_count * slots_per_budget)
            .take(times_per_cipher)
            .for_each(|chunk| {
                chunk.chunks_exact(slots_per_budget).for_each(|budget| {
                    if *budget.last().unwrap() == 1 {
                        let index = budget[0..index_slots_per_budget]
                            .iter()
                            .rev()
                            .fold(0, |acc, &v| (acc << shift_bits) | v);
                        retrieval_set.insert(index);
                    }
                });
            });

        let diff = pertinent_set.difference(&retrieval_set);

        let per_retrieval_end = Instant::now();
        println!(
            "per retrieval time: {:?}",
            per_retrieval_end - per_retrieval_start
        );

        let diff_count = diff.count();
        if diff_count == 0 {
            break;
        }
    }
    debug!("Retrieval done");
    let retrieval_end = Instant::now();
    println!("retrieval time: {:?}", retrieval_end - retrieval_start);

    println!("pertinent:{:?}", pertinent_set);
    println!("retrieval_set:{:?}", retrieval_set);
}
