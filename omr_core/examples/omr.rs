use algebra::{ntt::NumberTheoryTransform, Field};
use omr_core::{Detector, KeyGen, OmrParameters, SecondLevelField, Sender};

type Inner = <SecondLevelField as Field>::ValueT; // inner type

const FP: Inner = <SecondLevelField as Field>::MODULUS_VALUE; // ciphertext space
const FT: Inner = 1 << 15; // message space

#[inline]
fn decode(c: Inner) -> Inner {
    (c as f64 * FT as f64 / FP as f64).round() as Inner % FT
}

fn main() {
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

    println!("Detecting...");
    let start = std::time::Instant::now();
    let result = detector.detect(&clues);
    let end = std::time::Instant::now();
    println!("Detection done");
    println!("Detection time: {:?}", end - start);

    let key = secret_key_pack.second_level_ntt_rlwe_secret_key();

    let ntt_table = secret_key_pack.second_level_ntt_table();
    let poly =
        result.b() - ntt_table.inverse_transform_inplace(ntt_table.transform(result.a()) * &**key);

    let decrypted = poly.into_iter().map(decode).collect::<Vec<Inner>>();

    println!("{:?}", decrypted);
}
