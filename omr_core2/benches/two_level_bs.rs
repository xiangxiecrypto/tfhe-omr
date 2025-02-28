use criterion::{black_box, criterion_group, criterion_main, Criterion};

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
