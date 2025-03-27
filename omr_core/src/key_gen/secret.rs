use std::sync::Arc;

use algebra::{modulus::ShoupFactor, ntt::NttTable, utils::Size, Field, NttField};
use fhe_core::{
    BlindRotationKey, LweCiphertext, LwePublicKeyRlweMode, LweSecretKey,
    NonPowOf2LweKeySwitchingKey, NttRlweSecretKey, RlweSecretKey, TraceKey,
};
use rand::{CryptoRng, Rng};

use crate::{
    ClueValue, Detector, FirstLevelField, InterLweValue, OmrParameters, RetrievalParams, Retriever,
    SecondLevelField, Sender,
};

use super::{ClueKey, DetectionKey};

/// tfhe omr's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and parameters.
#[derive(Clone)]
pub struct SecretKeyPack {
    /// clue secret key
    clue_secret_key: LweSecretKey<ClueValue>,
    /// first level rlwe secret key
    first_level_rlwe_secret_key: RlweSecretKey<FirstLevelField>,
    /// first level ntt version rlwe secret key
    first_level_ntt_rlwe_secret_key: NttRlweSecretKey<FirstLevelField>,
    /// first level ntt table
    first_level_ntt_table: Arc<<FirstLevelField as NttField>::Table>,
    /// intermediate lwe secret key
    intermediate_lwe_secret_key: LweSecretKey<InterLweValue>,
    /// second level rlwe secret key
    second_level_rlwe_secret_key: RlweSecretKey<SecondLevelField>,
    /// second level ntt version rlwe secret key
    second_level_ntt_rlwe_secret_key: NttRlweSecretKey<SecondLevelField>,
    /// second level ntt table
    second_level_ntt_table: Arc<<SecondLevelField as NttField>::Table>,
    /// omr parameters
    parameters: OmrParameters,
}

impl SecretKeyPack {
    /// Creates a new [`SecretKeyPack`].
    pub fn new<R>(parameters: OmrParameters, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let clue_secret_key = LweSecretKey::generate(parameters.clue_params(), rng);
        let intermediate_lwe_secret_key =
            LweSecretKey::generate(parameters.intermediate_lwe_params(), rng);

        let first_level_ring_dimension = parameters.first_level_ring_dimension();
        let first_level_rlwe_secret_key: RlweSecretKey<FirstLevelField> = {
            RlweSecretKey::generate(
                parameters.first_level_ring_secret_key_type(),
                first_level_ring_dimension,
                Some(parameters.first_level_noise_distribution()),
                rng,
            )
        };
        let first_level_ntt_table = parameters.generate_first_level_ntt_table();
        let first_level_ntt_rlwe_secret_key = NttRlweSecretKey::from_coeff_secret_key(
            &first_level_rlwe_secret_key,
            &first_level_ntt_table,
        );

        let second_level_ring_dimension = parameters.second_level_ring_dimension();
        let second_level_rlwe_secret_key: RlweSecretKey<SecondLevelField> = {
            RlweSecretKey::generate(
                parameters.second_level_ring_secret_key_type(),
                second_level_ring_dimension,
                Some(parameters.second_level_ring_noise_distribution()),
                rng,
            )
        };
        let second_level_ntt_table = parameters.generate_second_level_ntt_table();
        let second_level_ntt_rlwe_secret_key = NttRlweSecretKey::from_coeff_secret_key(
            &second_level_rlwe_secret_key,
            &second_level_ntt_table,
        );

        Self {
            clue_secret_key,
            first_level_rlwe_secret_key,
            first_level_ntt_rlwe_secret_key,
            first_level_ntt_table: Arc::new(first_level_ntt_table),
            intermediate_lwe_secret_key,
            second_level_rlwe_secret_key,
            second_level_ntt_rlwe_secret_key,
            second_level_ntt_table: Arc::new(second_level_ntt_table),
            parameters,
        }
    }

    /// Generates a [`ClueKey`].
    #[inline]
    pub fn generate_clue_key<R>(&self, rng: &mut R) -> ClueKey
    where
        R: Rng + CryptoRng,
    {
        let params = self.parameters.clue_params();
        let key = LwePublicKeyRlweMode::new(&self.clue_secret_key, params, rng);
        ClueKey::new(key, *params)
    }

    /// Generates a [`Sender`].
    #[inline]
    pub fn generate_sender<R>(&self, rng: &mut R) -> Sender
    where
        R: Rng + CryptoRng,
    {
        Sender::new(self.generate_clue_key(rng), self.parameters.clue_count())
    }

    /// Generates a [`DetectionKey`].
    pub fn generate_detection_key<R>(&self, rng: &mut R) -> DetectionKey
    where
        R: Rng + CryptoRng,
    {
        let parameters = self.parameters();

        let first_level_blind_rotation_key = BlindRotationKey::generate(
            self.clue_secret_key(),
            self.first_level_ntt_rlwe_secret_key(),
            parameters.first_level_blind_rotation_basis(),
            parameters.first_level_noise_distribution(),
            Arc::clone(self.first_level_ntt_table()),
            rng,
        );

        let key_switching_key = {
            let s_in = self.first_level_rlwe_secret_key();
            let s_in = LweSecretKey::<<FirstLevelField as Field>::ValueT>::from_rlwe_secret_key(
                s_in,
                <FirstLevelField as Field>::MODULUS_VALUE - 1,
            );
            let s_out = self.intermediate_lwe_secret_key();
            NonPowOf2LweKeySwitchingKey::<<FirstLevelField as Field>::ValueT>::generate(
                &s_in,
                s_out,
                parameters.first_level_key_switching_params(),
                <FirstLevelField as Field>::MODULUS,
                rng,
            )
        };

        let second_level_blind_rotation_key = BlindRotationKey::generate(
            self.intermediate_lwe_secret_key(),
            self.second_level_ntt_rlwe_secret_key(),
            parameters.second_level_blind_rotation_basis(),
            parameters.second_level_ring_noise_distribution(),
            Arc::clone(self.second_level_ntt_table()),
            rng,
        );

        let trace_key = TraceKey::new(
            self.second_level_rlwe_secret_key(),
            self.second_level_ntt_rlwe_secret_key(),
            parameters.hom_trace_params().basis(),
            parameters.hom_trace_params().noise_distribution(),
            Arc::clone(self.second_level_ntt_table()),
            rng,
        );

        let n = self.second_level_ntt_table().dimension();
        let inv_n = SecondLevelField::inv(n as <SecondLevelField as Field>::ValueT);

        DetectionKey::new(
            first_level_blind_rotation_key,
            key_switching_key,
            second_level_blind_rotation_key,
            ShoupFactor::new(inv_n, SecondLevelField::MODULUS_VALUE),
            trace_key,
            self.parameters.clone(),
        )
    }

    /// Generates a [`Detector`].
    #[inline]
    pub fn generate_detector<R>(&self, rng: &mut R) -> Detector
    where
        R: Rng + CryptoRng,
    {
        Detector::new(self.generate_detection_key(rng))
    }

    pub fn generate_retriever(
        &self,
        all_payloads_count: usize,
        pertinent_count: usize,
    ) -> Retriever<SecondLevelField> {
        let params = self.parameters();
        let retrieval_params: RetrievalParams<SecondLevelField> = RetrievalParams::new(
            params.output_plain_modulus_value(),
            params.second_level_ring_dimension(),
            all_payloads_count,
            pertinent_count,
            130,
            25,
        );
        Retriever::new(
            retrieval_params,
            Arc::clone(self.second_level_ntt_table()),
            self.second_level_ntt_rlwe_secret_key().clone(),
        )
    }

    /// Returns a reference to the parameters.
    #[inline]
    pub fn parameters(&self) -> &OmrParameters {
        &self.parameters
    }

    /// Returns a reference to the clue secret key of this [`SecretKeyPack`].
    #[inline]
    pub fn clue_secret_key(&self) -> &LweSecretKey<ClueValue> {
        &self.clue_secret_key
    }

    /// Returns a reference to the first level rlwe secret key of this [`SecretKeyPack`].
    #[inline]
    pub fn first_level_rlwe_secret_key(&self) -> &RlweSecretKey<FirstLevelField> {
        &self.first_level_rlwe_secret_key
    }

    /// Returns a reference to the first level ntt rlwe secret key of this [`SecretKeyPack`].
    #[inline]
    pub fn first_level_ntt_rlwe_secret_key(&self) -> &NttRlweSecretKey<FirstLevelField> {
        &self.first_level_ntt_rlwe_secret_key
    }

    /// Returns a reference to the first level ntt table of this [`SecretKeyPack`].
    #[inline]
    pub fn first_level_ntt_table(&self) -> &Arc<<FirstLevelField as NttField>::Table> {
        &self.first_level_ntt_table
    }

    /// Returns a reference to the intermediate lwe secret key of this [`SecretKeyPack`].
    #[inline]
    pub fn intermediate_lwe_secret_key(&self) -> &LweSecretKey<InterLweValue> {
        &self.intermediate_lwe_secret_key
    }

    /// Returns a reference to the second level rlwe secret key of this [`SecretKeyPack`].
    #[inline]
    pub fn second_level_rlwe_secret_key(&self) -> &RlweSecretKey<SecondLevelField> {
        &self.second_level_rlwe_secret_key
    }

    /// Returns a reference to the second level ntt rlwe secret key of this [`SecretKeyPack`].
    #[inline]
    pub fn second_level_ntt_rlwe_secret_key(&self) -> &NttRlweSecretKey<SecondLevelField> {
        &self.second_level_ntt_rlwe_secret_key
    }

    /// Returns a reference to the second level ntt table of this [`SecretKeyPack`].
    #[inline]
    pub fn second_level_ntt_table(&self) -> &Arc<<SecondLevelField as NttField>::Table> {
        &self.second_level_ntt_table
    }

    /// Decrypts a clue.
    #[inline]
    pub fn decrypt_clue(&self, clue: &LweCiphertext<ClueValue>) -> ClueValue {
        self.clue_secret_key
            .decrypt::<ClueValue, _>(clue, self.parameters.clue_params())
    }

    /// z2 key size
    #[inline]
    pub fn z2_size(&self) -> usize {
        self.second_level_rlwe_secret_key.size()
    }
}

impl Size for SecretKeyPack {
    #[inline]
    fn size(&self) -> usize {
        self.clue_secret_key.size()
            + self.first_level_rlwe_secret_key.size()
            // + self.first_level_ntt_rlwe_secret_key.size()
            + self.intermediate_lwe_secret_key.size()
            + self.second_level_rlwe_secret_key.size()
        // + self.second_level_ntt_rlwe_secret_key.size()
    }
}
