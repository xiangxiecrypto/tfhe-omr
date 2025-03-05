use std::collections::HashSet;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use fhe_core::CmLweCiphertext;
use lattice::Rlwe;
use omr_core::{KeyGen, OmrParameters, SecondLevelField};
use rand::seq::SliceRandom;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = OmrParameters::new();
    let mut rng = rand::thread_rng();

    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);
    let detector = secret_key_pack.generate_detector(&mut rng);

    c.bench_function("generate clues for a message", |b| {
        b.iter(|| sender.gen_clues(&mut rng));
    });

    let clues = sender.gen_clues(&mut rng);

    c.bench_function("detect single message", |b| {
        b.iter(|| detector.detect(black_box(&clues)));
    });

    let all_payloads_count: usize = 1;
    let pertinent_count = if all_payloads_count <= 50 {
        all_payloads_count
    } else {
        50
    };

    let mut pertinent = vec![false; all_payloads_count];
    pertinent[0..pertinent_count]
        .iter_mut()
        .for_each(|v| *v = true);
    pertinent.shuffle(&mut rng);

    let mut pertinent_set = HashSet::new();
    pertinent.iter().enumerate().for_each(|(i, &f)| {
        if f {
            pertinent_set.insert(i as usize);
        }
    });

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

    let detect_list: Vec<Rlwe<SecondLevelField>> = clues_list
        .par_iter()
        .map(|clues| detector.detect(clues))
        .collect();

    let retriever = secret_key_pack.generate_retriever(all_payloads_count, pertinent_count);
    let retrieval_params = retriever.params();

    c.bench_function(
        &format!(
            "compress index of pertinent messages with all payloads count: {all_payloads_count}"
        ),
        |b| {
            b.iter(|| {
                detector.compress_pertivency_vector(retrieval_params, black_box(&detect_list))
            });
        },
    );

    let ct = detector.compress_pertivency_vector(retrieval_params, &detect_list);

    c.bench_function("retrieve single ciphertext", |b| {
        b.iter_batched_ref(
            || retriever.clone(),
            |retriever| retriever.retrieve(black_box(&ct)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
