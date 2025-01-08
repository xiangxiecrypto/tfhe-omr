use criterion::{black_box, criterion_group, criterion_main, Criterion};
use omr_core::{Detector, KeyGen, OmrParameters, Sender};

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    println!("Generating secret key pack...");
    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);

    println!("Generating sender and detector...");
    let sender = Sender::new(
        secret_key_pack.generate_clue_key(&mut rng),
        params.clue_count(),
    );
    let detector = Detector::new(secret_key_pack.generate_detection_key(&mut rng));

    println!("Generating clues...");
    let clues = sender.gen_clues(&mut rng);

    c.bench_function("omr detect", |b| {
        b.iter(|| detector.detect(black_box(&clues)));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
