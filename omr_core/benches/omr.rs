use criterion::{black_box, criterion_group, criterion_main, Criterion};
use omr_core::{KeyGen, OmrParameters};

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let sender = secret_key_pack.generate_sender(&mut rng);
    let detector = secret_key_pack.generate_detector(&mut rng);

    let clues = sender.gen_clues(&mut rng);

    c.bench_function("omr detect", |b| {
        b.iter(|| detector.detect(black_box(&clues)));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
