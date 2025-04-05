// cargo +nightly bench --package omr_core2 --bench two_level_bs --features="nightly"

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::{
    keyswitch_lwe_ciphertext, CiphertextModulus, LweCiphertextMutView,
};

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        use tfhe::boolean::prelude::*;

        // generate the client key
        let cks = ClientKey::new(&TFHE_LIB_PARAMETERS);

        // generate the server key
        let sks = ServerKey::new(&cks);

        // Extract clues
        let ct1: Ciphertext = cks.encrypt(false);
        let ct2: Ciphertext = cks.encrypt(false);

        c.bench_function("first level bootstrapping", |b| {
            b.iter(|| sks.nand(black_box(&ct1), black_box(&ct2)));
        });

        let (_bootstrapping_key, key_switching_key, _pbs_order) = sks.into_raw_parts();
        let ct = match ct1 {
            Ciphertext::Encrypted(ct) => ct,
            Ciphertext::Trivial(_) => panic!("ct1 is not a ciphertext"),
        };

        let mut buffer = vec![0u32; key_switching_key.output_key_lwe_dimension().to_lwe_size().0];

        let mut buffer_lwe_after_ks =
            LweCiphertextMutView::from_container(&mut buffer, CiphertextModulus::new_native());

        c.bench_function("key switch", |b| {
            b.iter(|| {
                keyswitch_lwe_ciphertext(
                    black_box(&key_switching_key),
                    black_box(&ct),
                    black_box(&mut buffer_lwe_after_ks),
                )
            });
        });
    }
    {
        use tfhe::shortint::parameters::v1_0::V1_0_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M128;
        use tfhe::shortint::prelude::*;
        use tfhe::shortint::server_key::LookupTable;

        let (client_key, detect_l1_key) =
            gen_keys(V1_0_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M128);

        let f1 = |x: u64| if x == 10 { 1 } else { 0 };
        let lut1: LookupTable<Vec<u64>> = detect_l1_key.generate_lookup_table(f1);

        let ct = client_key.encrypt(10);

        c.bench_function("second level bootstrapping", |b| {
            b.iter(|| detect_l1_key.apply_lookup_table(black_box(&ct), black_box(&lut1)));
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
