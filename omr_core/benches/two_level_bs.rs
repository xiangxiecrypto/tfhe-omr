// cargo +nightly bench --package omr_core --bench two_level_bs --features="nightly"
// cargo bench --package omr_core --bench two_level_bs

use algebra::{
    reduce::{ModulusValue, Reduce, ReduceAddAssign},
    Field,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use fhe_core::{lwe_modulus_switch, lwe_modulus_switch_assign, LweCiphertext, RlweCiphertext};
use omr_core::{ClueValue, FirstLevelField, InterLweValue, KeyGen, OmrParameters};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let params = OmrParameters::new();
    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let sender = secret_key_pack.generate_sender(&mut rng);
    let detector = secret_key_pack.generate_detector(&mut rng);
    let detection_key = detector.detection_key();

    let clues = sender.gen_clues(&mut rng);
    let msg_count = clues.msg_count();

    // Extract clues
    let mut clues: Vec<LweCiphertext<ClueValue>> = clues.extract_all(detection_key.clue_modulus());

    let clue_cipher_modulus_value = params.clue_params().cipher_modulus_value;
    let first_level_ring_dimension = params.first_level_ring_dimension();

    // Modulus switching to `2 * N_1`
    let twice_first_level_ring_dimension = first_level_ring_dimension as ClueValue * 2;
    if clue_cipher_modulus_value != ModulusValue::PowerOf2(twice_first_level_ring_dimension) {
        clues.iter_mut().for_each(|clue| {
            lwe_modulus_switch_assign(
                clue,
                clue_cipher_modulus_value,
                twice_first_level_ring_dimension,
            );
        });
    }

    let first_level_blind_rotation_key = detection_key.first_level_blind_rotation_key();

    let clue = &clues[0];

    c.bench_function("blind rotation of first level bootstrapping", |b| {
        b.iter_batched(
            || detector.first_level_lut().clone(),
            |lut| first_level_blind_rotation_key.blind_rotate(lut, black_box(clue)),
            BatchSize::SmallInput,
        );
    });

    // First level blind rotation and sum
    let intermediate = clues
        .iter()
        .map(|c| first_level_blind_rotation_key.blind_rotate(detector.first_level_lut().clone(), c))
        .reduce(|acc, ele| acc.add_element_wise(&ele))
        .unwrap_or_else(|| <RlweCiphertext<FirstLevelField>>::zero(first_level_ring_dimension));

    c.bench_function("key switch", |b| {
        b.iter_batched(
            || intermediate.clone(),
            |intermediate| {
                detection_key.first_level_key_switching_key().key_switch(
                    &intermediate.extract_lwe_locally(),
                    FirstLevelField::MODULUS,
                )
            },
            BatchSize::SmallInput,
        );
    });

    // Key switching
    let intermediate = detection_key.first_level_key_switching_key().key_switch(
        &intermediate.extract_lwe_locally(),
        FirstLevelField::MODULUS,
    );

    let intermediate_lwe_params = params.intermediate_lwe_params();
    let intermediate_cipher_modulus_value = intermediate_lwe_params.cipher_modulus_value;
    let intermediate_cipher_modulus = intermediate_lwe_params.cipher_modulus;
    let intermediate_plain_modulus_value = intermediate_lwe_params.plain_modulus_value;

    // Modulus switching
    let mut intermediate = lwe_modulus_switch(
        &intermediate,
        params.first_level_blind_rotation_params().modulus,
        intermediate_cipher_modulus_value,
    );

    let log_plain_modulus = intermediate_plain_modulus_value.trailing_zeros();

    // Add `msg_count`
    let scale = (msg_count as InterLweValue) * {
        match intermediate_cipher_modulus_value {
            ModulusValue::Native => 1 << (InterLweValue::BITS - log_plain_modulus),
            ModulusValue::PowerOf2(q) => q >> log_plain_modulus,
            ModulusValue::Prime(q) | ModulusValue::Others(q) => {
                let temp = q >> (log_plain_modulus - 1);
                (temp + 1) >> 1
            }
        }
    };
    intermediate_cipher_modulus.reduce_add_assign(
        intermediate.b_mut(),
        intermediate_cipher_modulus.reduce(scale),
    );

    // Modulus switching
    if intermediate_cipher_modulus_value
        != ModulusValue::PowerOf2(params.second_level_ring_dimension() as InterLweValue * 2)
    {
        lwe_modulus_switch_assign(
            &mut intermediate,
            intermediate_cipher_modulus_value,
            params.second_level_ring_dimension() as InterLweValue * 2,
        );
    }

    let second_level_blind_rotation_key = detection_key.second_level_blind_rotation_key();

    c.bench_function("blind rotation of second level bootstrapping", |b| {
        b.iter_batched(
            || detector.second_level_lut().clone(),
            |lut| second_level_blind_rotation_key.blind_rotate(lut, black_box(&intermediate)),
            BatchSize::SmallInput,
        );
    });

    // Second level blind rotation
    let mut second_level_result = second_level_blind_rotation_key
        .blind_rotate(detector.second_level_lut().clone(), &intermediate);

    // Multiply by `n_inv`
    let n_inv = detection_key.second_level_ring_dimension_inv();
    second_level_result.a_mut().mul_shoup_scalar_assign(n_inv);
    second_level_result.b_mut().mul_shoup_scalar_assign(n_inv);

    let trace_key = detection_key.trace_key();
    // Homomorphic Trace
    c.bench_function("Trace", |b| {
        b.iter(|| trace_key.trace(black_box(&second_level_result)));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
