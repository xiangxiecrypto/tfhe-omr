use algebra::{ntt::NumberTheoryTransform, Field};
use omr_core::{OmrParameters, SecondLevelField};
use rand::Rng;

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
    let secret_key_pack = omr_core::KeyGen::generate_secret_key(params.clone(), &mut rng);

    println!("Generating sender and detector...");
    let sender = omr_core::Sender::new(
        secret_key_pack.generate_clue_key(&mut rng),
        params.clue_count(),
    );
    let detector = omr_core::Detector::new(secret_key_pack.generate_detection_key(&mut rng));

    println!("Generating clues...");
    let clues = sender.gen_clues(&mut rng);

    println!("Decrypting test clue...");
    let clue = clues.extract_rlwe_mode(
        rng.gen_range(0..params.clue_count()),
        params.clue_params().cipher_modulus,
    );
    let m = secret_key_pack.decrypt_clue(&clue);
    assert_eq!(m, 0);

    println!("Detecting...");
    let result = detector.detect(&clues);

    let key = secret_key_pack.second_level_ntt_rlwe_secret_key();

    let ntt_table = secret_key_pack.second_level_ntt_table();
    let poly =
        result.b() - ntt_table.inverse_transform_inplace(ntt_table.transform(result.a()) * &**key);

    let decrypted = poly.into_iter().map(decode).collect::<Vec<Inner>>();

    println!("{:?}", decrypted);
}
