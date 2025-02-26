use algebra::{
    integer::AsInto,
    reduce::{ModulusValue, Reduce, ReduceAddAssign},
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use fhe_core::{lwe_modulus_switch, lwe_modulus_switch_assign, LweCiphertext, RlweCiphertext};
use omr_core::{
    first_level_lut, second_level_lut, ClueValue, FirstLevelField, InterLweValue, KeyGen,
    OmrParameters,
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let sender = secret_key_pack.generate_sender(&mut rng);
    let detector = secret_key_pack.generate_detector(&mut rng);

    let clue_params = params.clue_params();
    let first_level_ring_dimension = params.first_level_ring_dimension();
    let detection_key = detector.detection_key();
    let clue_modulus = detection_key.clue_modulus();

    let first_level_blind_rotation_key = detection_key.first_level_blind_rotation_key();
    let intermediate_lwe_params = params.intermediate_lwe_params();
    let intermediate_plain_modulus = intermediate_lwe_params.plain_modulus_value;
    let second_level_blind_rotation_key = detection_key.second_level_blind_rotation_key();

    let clues = sender.gen_clues(&mut rng);

    let msg_count = clues.msg_count();

    // Extract clues
    let mut clues: Vec<LweCiphertext<ClueValue>> = clues.extract_all(clue_modulus);

    // Modulus switching
    if clue_params.cipher_modulus_value
        != ModulusValue::PowerOf2(first_level_ring_dimension as ClueValue * 2)
    {
        clues.iter_mut().for_each(|clue| {
            lwe_modulus_switch_assign(
                clue,
                clue_params.cipher_modulus_value,
                first_level_ring_dimension as ClueValue * 2,
            );
        });
    }

    // Generate first level LUT
    let lut1 = first_level_lut(
        first_level_ring_dimension,
        clue_params.plain_modulus_value.as_into(),
        intermediate_plain_modulus as usize,
    );

    let clue = &clues[0];

    c.bench_function("first level bootstrapping", |b| {
        b.iter_batched(
            || lut1.clone(),
            |lut| first_level_blind_rotation_key.blind_rotate(lut, black_box(clue)),
            BatchSize::SmallInput,
        );
    });

    // First level blind rotation and sum
    let intermedia = clues
        .par_iter()
        .map(|c| first_level_blind_rotation_key.blind_rotate(lut1.clone(), c))
        .reduce(
            || <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension),
            |acc, c| acc.add_element_wise(&c),
        );

    // Key switching
    let intermedia = detection_key
        .first_level_key_switching_key()
        .key_switch_for_rlwe(intermedia);

    // Modulus switching
    let mut intermedia = lwe_modulus_switch(
        &intermedia,
        params.first_level_blind_rotation_params().modulus,
        intermediate_lwe_params.cipher_modulus_value,
    );

    let log_plain_modulus = intermediate_lwe_params.plain_modulus_value.trailing_zeros();

    let cipher_modulus = intermediate_lwe_params.cipher_modulus;

    // Add `msg_count`
    let scale = (msg_count as InterLweValue) * {
        match intermediate_lwe_params.cipher_modulus_value {
            ModulusValue::Native => 1 << (InterLweValue::BITS - log_plain_modulus),
            ModulusValue::PowerOf2(q) => q >> log_plain_modulus,
            ModulusValue::Prime(q) | ModulusValue::Others(q) => {
                let temp = q >> (log_plain_modulus - 1);
                (temp + 1) >> 1
            }
        }
    };
    cipher_modulus.reduce_add_assign(intermedia.b_mut(), cipher_modulus.reduce(scale));

    // Modulus switching
    if intermediate_lwe_params.cipher_modulus_value
        != ModulusValue::PowerOf2(params.second_level_ring_dimension() as InterLweValue * 2)
    {
        lwe_modulus_switch_assign(
            &mut intermedia,
            intermediate_lwe_params.cipher_modulus_value,
            params.second_level_ring_dimension() as InterLweValue * 2,
        );
    }

    let output_plain_modulus = params.output_plain_modulus_value();
    // Generate second level LUT
    let lut2 = second_level_lut(
        params.second_level_ring_dimension(),
        msg_count,
        intermediate_lwe_params.plain_modulus_value as usize,
        output_plain_modulus as usize,
    );

    c.bench_function("second level bootstrapping", |b| {
        b.iter(|| {
            second_level_blind_rotation_key.blind_rotate(lut2.clone(), black_box(&intermedia))
        });
        b.iter_batched(
            || lut2.clone(),
            |lut| second_level_blind_rotation_key.blind_rotate(lut, black_box(&intermedia)),
            BatchSize::SmallInput,
        );
    });
    // Second level blind rotation
    let mut second_level_result = second_level_blind_rotation_key.blind_rotate(lut2, &intermedia);

    // Multiply by `n_inv`
    let n_inv = detection_key.second_level_ring_dimension_inv();
    second_level_result.a_mut().mul_shoup_scalar_assign(n_inv);
    second_level_result.b_mut().mul_shoup_scalar_assign(n_inv);

    // Homomorphic Trace
    c.bench_function("Trace", |b| {
        b.iter(|| {
            detection_key
                .trace_key()
                .trace(black_box(&second_level_result))
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
