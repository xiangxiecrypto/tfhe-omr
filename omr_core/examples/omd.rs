use algebra::{ntt::NumberTheoryTransform, Field};
use omr_core::{KeyGen, OmrParameters, SecondLevelField};
use rand::SeedableRng;
use tracing::{debug, Level};
use tracing_subscriber::fmt::format::FmtSpan;

type Inner = <SecondLevelField as Field>::ValueT; // inner type

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true)
        .with_max_level(Level::TRACE)
        .init();

    let params = OmrParameters::new();
    let mut rng = rand::rngs::StdRng::from_entropy();

    let fp = <SecondLevelField as Field>::MODULUS_VALUE;
    let ft = params.output_plain_modulus_value();

    let decode = |c: Inner| (c as f64 * ft as f64 / fp as f64).round() as Inner % ft;

    debug!("Generating secret key pack...");
    let secret_key_pack = KeyGen::generate_secret_key(params.clone(), &mut rng);
    let secret_key_pack2 = KeyGen::generate_secret_key(params.clone(), &mut rng);

    let key = secret_key_pack.second_level_ntt_rlwe_secret_key();
    let ntt_table = secret_key_pack.second_level_ntt_table();

    debug!("Generating sender and detector...");
    let sender = secret_key_pack.generate_sender(&mut rng);
    let sender2 = secret_key_pack2.generate_sender(&mut rng);

    let detector = secret_key_pack.generate_detector(&mut rng);

    debug!("Generating clues...");
    let clues = sender.gen_clues(&mut rng);
    let clues2 = sender2.gen_clues(&mut rng);

    debug!("Detecting...");
    let (result, result2) = rayon::join(|| detector.detect(&clues), || detector.detect(&clues2));
    debug!("Detect done");

    let poly =
        result.b() - ntt_table.inverse_transform_inplace(ntt_table.transform(result.a()) * &**key);

    let decrypted = poly.into_iter().map(decode).collect::<Vec<Inner>>();

    assert_eq!(decrypted[0], 1);
    assert!(decrypted[1..].iter().all(|&x| x == 0));

    let poly2 = result2.b()
        - ntt_table.inverse_transform_inplace(ntt_table.transform(result2.a()) * &**key);
    let decrypted2 = poly2.into_iter().map(decode).collect::<Vec<Inner>>();

    assert!(decrypted2.iter().all(|&x| x == 0));
}
