// cargo +nightly run --package omr_core --example omr --features="nightly" --release
// cargo run --package omr_core --example omr --release

use std::{collections::HashSet, time::Instant};

use algebra::{reduce::ModulusValue, Field};
use clap::Parser;
use fhe_core::CmLweCiphertext;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use lattice::NttRlwe;
use omr_core::{
    DetectNoiseInfo, DetectNoiseStats, Detector, InterLweValue, KeyGen, OmrParameters, Payload,
    SecondLevelField, SecretKeyPack, Sender,
};
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
            pertinent_set.insert(i);
        });

    debug!("Generating clues...");
    let start = Instant::now();
    let clues_list: Vec<CmLweCiphertext<u16>> = pertinent
        .par_iter()
        .map_init(rand::thread_rng, |rng, &f| {
            if f {
                sender.gen_clues(rng)
            } else {
                sender2.gen_clues(rng)
            }
        })
        .collect();
    let end = Instant::now();
    info!("gen clues time: {:?}", end - start);

    debug!("Generating payloads...");
    let start = Instant::now();
    let payloads: Vec<Payload> = (0..all_payloads_count)
        .into_par_iter()
        .map_init(rand::thread_rng, |rng, _| Payload::random(rng))
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
    let detected: Vec<(NttRlwe<SecondLevelField>, DetectNoiseInfo)> = clues_list
        .par_iter()
        .progress_with(pb.clone())
        .map(|clues| detector.detect_with_noise_info(clues, secret_key_pack))
        .collect();
    pb.finish();
    let end = Instant::now();
    debug!("Detect done");

    let mut noise_info = DetectNoiseInfo::default();
    let mut pertinency_vector = Vec::with_capacity(detected.len());
    detected.into_iter().for_each(|(ciphertext, info)| {
        pertinency_vector.push(ciphertext);
        noise_info.merge(info);
    });

    let intermediate_lwe_params = detector.detection_key().params().intermediate_lwe_params();
    log_single_stage_noise(
        "first_level_bootstrapping intermediate",
        &noise_info.after_first_level_bootstrapping,
        modulus_value_as_f64(intermediate_lwe_params.cipher_modulus_value),
        intermediate_lwe_params.plain_modulus_value as f64,
    );
    log_noise_growth(
        "constant coefficient",
        &noise_info.after_second_level_bootstrapping.constant,
        &noise_info.after_hom_trace.constant,
    );
    log_noise_growth(
        "other coefficients",
        &noise_info.after_second_level_bootstrapping.other,
        &noise_info.after_hom_trace.other,
    );

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

    let mut pertinent_indices = pertinent_set.iter().copied().collect::<Vec<usize>>();
    pertinent_indices.sort_unstable();

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

    let payload_noise = detector.analyze_encode_pertinent_payloads_noise(
        &encode_pertinent_payloads,
        &payloads,
        &pertinent_indices,
        seed,
        retrieval_params.combination_count(),
        retrieval_params.cmb_count_per_cipher(),
        secret_key_pack,
    );
    log_payload_noise(
        "encode_pertinent_payloads",
        &payload_noise,
        retrieval_params.index_modulus(),
    );

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

fn log_noise_growth(label: &str, before: &DetectNoiseStats, after: &DetectNoiseStats) {
    // Printed metrics:
    // - mean: empirical bias of signed noise. It should be close to zero for centered noise.
    // - sigma: fitted Gaussian standard deviation sqrt(E[e^2] - E[e]^2).
    // - sigma bits: log2(sigma), the typical noise scale in coefficient-space bits.
    // - sigma growth: log2(after_sigma / before_sigma), the bit increase caused by hom_trace.
    // - max_abs: largest observed |e|, useful for checking the actual decoding margin.
    // - max_centered: largest |e - mean|, expressed both as a value and as sigma multiples.
    info!(
        "hom_trace noise {label}: count={}, mean {:.3e} -> {:.3e}, sigma {:.3e} ({:.3} bits) -> {:.3e} ({:.3} bits), sigma growth {:.3} bits, max_abs {:.3e} ({:.3} bits) -> {:.3e} ({:.3} bits), max_abs growth {:.3} bits, max_centered {:.3e} ({:.3} sigma) -> {:.3e} ({:.3} sigma)",
        after.count,
        before.mean(),
        after.mean(),
        before.sigma(),
        before.sigma_bits(),
        after.sigma(),
        after.sigma_bits(),
        growth_bits(before.sigma(), after.sigma()),
        before.max_abs,
        before.max_abs_bits(),
        after.max_abs,
        after.max_abs_bits(),
        growth_bits(before.max_abs, after.max_abs),
        before.max_centered_abs(),
        before.max_centered_sigma(),
        after.max_centered_abs(),
        after.max_centered_sigma(),
    );
    log_gaussian_tail(label, "before hom_trace", before);
    log_gaussian_tail(label, "after hom_trace", after);
}

fn log_payload_noise(label: &str, stats: &DetectNoiseStats, plain_modulus: u64) {
    // Payload noise is measured only after encode_pertinent_payloads.
    // The reference value is the true weighted payload sum, not the nearest decoded message.
    //
    // decode_bound = q / (2p) is half the spacing between two adjacent plaintext encodings.
    // If every |e| is below this bound, rounding to the plaintext modulus should decode correctly.
    //
    // - sigma margin: log2(decode_bound / sigma), the distance from the fitted sigma to failure.
    // - max_abs margin: log2(decode_bound / max_abs), the distance from the worst observed sample
    //   to the decoding boundary.
    let decode_bound =
        <SecondLevelField as Field>::MODULUS_VALUE as f64 / (2.0 * plain_modulus as f64);
    info!(
        "{label} noise: count={}, mean {:.3e}, sigma {:.3e} ({:.3} bits), max_abs {:.3e} ({:.3} bits), max_centered {:.3e} ({:.3} sigma), sigma margin {:.3} bits, max_abs margin {:.3} bits",
        stats.count,
        stats.mean(),
        stats.sigma(),
        stats.sigma_bits(),
        stats.max_abs,
        stats.max_abs_bits(),
        stats.max_centered_abs(),
        stats.max_centered_sigma(),
        growth_bits(stats.sigma(), decode_bound),
        growth_bits(stats.max_abs, decode_bound),
    );
    log_gaussian_tail(label, "after encode", stats);
}

fn log_single_stage_noise(
    label: &str,
    stats: &DetectNoiseStats,
    cipher_modulus: f64,
    plain_modulus: f64,
) {
    let decode_bound = cipher_modulus / (2.0 * plain_modulus);
    info!(
        "{label} noise: count={}, mean {:.3e}, sigma {:.3e} ({:.3} bits), max_abs {:.3e} ({:.3} bits), max_centered {:.3e} ({:.3} sigma), sigma margin {:.3} bits, max_abs margin {:.3} bits",
        stats.count,
        stats.mean(),
        stats.sigma(),
        stats.sigma_bits(),
        stats.max_abs,
        stats.max_abs_bits(),
        stats.max_centered_abs(),
        stats.max_centered_sigma(),
        growth_bits(stats.sigma(), decode_bound),
        growth_bits(stats.max_abs, decode_bound),
    );
    log_gaussian_tail(label, "after stage", stats);
}

fn growth_bits(before: f64, after: f64) -> f64 {
    // Positive means `after` is larger; negative means `after` is smaller.
    // For margins we call this as growth_bits(noise_or_sigma, decode_bound), so the
    // result means "how many bits of room remain before the decoding boundary".
    match (before > 0.0, after > 0.0) {
        (true, true) => after.log2() - before.log2(),
        (false, true) => f64::INFINITY,
        (true, false) => f64::NEG_INFINITY,
        (false, false) => 0.0,
    }
}

fn log_gaussian_tail(label: &str, stage: &str, stats: &DetectNoiseStats) {
    // Compare observed centered residual tails against an ideal two-sided Gaussian.
    // Example: >4sigma reports count(|e - mean| > 4*sigma), its empirical ratio,
    // and the expected count under N(mean, sigma^2) for the same sample count.
    let sigma_multipliers = [3.0, 4.0, 5.0, 6.0];
    let tail_counts = stats.tail_counts(sigma_multipliers);
    let tail = |index: usize| {
        let count = tail_counts[index];
        let ratio = if stats.count == 0 {
            0.0
        } else {
            count as f64 / stats.count as f64
        };
        let expected =
            stats.count as f64 * gaussian_two_sided_tail_probability(sigma_multipliers[index]);
        (count, ratio, expected)
    };

    let (tail_3_count, tail_3_ratio, tail_3_expected) = tail(0);
    let (tail_4_count, tail_4_ratio, tail_4_expected) = tail(1);
    let (tail_5_count, tail_5_ratio, tail_5_expected) = tail(2);
    let (tail_6_count, tail_6_ratio, tail_6_expected) = tail(3);

    info!(
        "gaussian tail {label} {stage}: >3sigma {} ({:.3e}, exp {:.3e}), >4sigma {} ({:.3e}, exp {:.3e}), >5sigma {} ({:.3e}, exp {:.3e}), >6sigma {} ({:.3e}, exp {:.3e})",
        tail_3_count,
        tail_3_ratio,
        tail_3_expected,
        tail_4_count,
        tail_4_ratio,
        tail_4_expected,
        tail_5_count,
        tail_5_ratio,
        tail_5_expected,
        tail_6_count,
        tail_6_ratio,
        tail_6_expected,
    );
}

/// Returns the ideal two-sided standard-normal tail probability `P(|Z| > k)`.
///
/// The caller multiplies this probability by the sample count to estimate how many
/// samples an ideal Gaussian `N(mean, sigma^2)` would put outside `k*sigma`.
fn gaussian_two_sided_tail_probability(sigma_multiplier: f64) -> f64 {
    match sigma_multiplier {
        x if (x - 3.0).abs() < f64::EPSILON => 2.699_796_063_260_186_6e-3,
        x if (x - 4.0).abs() < f64::EPSILON => 6.334_248_366_623_996e-5,
        x if (x - 5.0).abs() < f64::EPSILON => 5.733_031_437_583_866e-7,
        x if (x - 6.0).abs() < f64::EPSILON => 1.973_175_290_075_402_4e-9,
        _ => f64::NAN,
    }
}

fn modulus_value_as_f64(modulus: ModulusValue<InterLweValue>) -> f64 {
    match modulus {
        ModulusValue::Native => (1u128 << InterLweValue::BITS) as f64,
        ModulusValue::PowerOf2(q) | ModulusValue::Prime(q) | ModulusValue::Others(q) => q as f64,
    }
}
