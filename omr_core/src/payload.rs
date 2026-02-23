//! Payload representation and arithmetic helpers.

use algebra::reduce::RingReduce;
use itertools::izip;
use rand::RngCore;

/// Number of bytes per payload (as used in the paper's experiments).
pub const PAYLOAD_LENGTH: usize = 612;
/// Element type used in payload arithmetic.
pub type PayloadByteType = u16;

/// Fixed-length payload used by InstantOMR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload(pub [PayloadByteType; PAYLOAD_LENGTH]);

impl Payload {
    /// Creates a new [`Payload`].
    #[inline]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Payload([0; PAYLOAD_LENGTH])
    }

    /// Generates a random [`Payload`].
    #[inline]
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore,
    {
        let mut payload = Self::new();
        let mut temp = [0u8; PAYLOAD_LENGTH];
        rng.fill_bytes(&mut temp);
        payload
            .iter_mut()
            .zip(temp.iter())
            .for_each(|(p, &b)| *p = PayloadByteType::from(b));
        payload
    }

    /// Returns an iterator over the payload.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &PayloadByteType> {
        self.0.iter()
    }

    /// Returns a mutable iterator over the payload.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PayloadByteType> {
        self.0.iter_mut()
    }

    #[inline]
    pub fn add<M: RingReduce<PayloadByteType>>(mut self, rhs: &Self, modulus: M) -> Self {
        for (r, &b) in izip!(self.0.iter_mut(), rhs.0.iter()) {
            modulus.reduce_add_assign(r, b);
        }
        self
    }

    #[inline]
    pub fn add_assign<M: RingReduce<PayloadByteType>>(&mut self, rhs: &Self, modulus: M) {
        for (r, &b) in izip!(self.0.iter_mut(), rhs.0.iter()) {
            modulus.reduce_add_assign(r, b);
        }
    }

    #[inline]
    pub fn sub<M: RingReduce<PayloadByteType>>(mut self, rhs: &Self, modulus: M) -> Self {
        for (r, &b) in izip!(self.0.iter_mut(), rhs.0.iter()) {
            modulus.reduce_sub_assign(r, b);
        }
        self
    }

    #[inline]
    pub fn sub_assign<M: RingReduce<PayloadByteType>>(&mut self, rhs: &Self, modulus: M) {
        for (r, &b) in izip!(self.0.iter_mut(), rhs.0.iter()) {
            modulus.reduce_sub_assign(r, b);
        }
    }

    #[inline]
    pub fn mul_scalar<M: RingReduce<PayloadByteType>>(
        mut self,
        scaler: PayloadByteType,
        modulus: M,
    ) -> Self {
        for r in self.0.iter_mut() {
            modulus.reduce_mul_assign(r, scaler);
        }
        self
    }

    #[inline]
    pub fn mul_scalar_assign<M: RingReduce<PayloadByteType>>(
        &mut self,
        scaler: PayloadByteType,
        modulus: M,
    ) {
        for r in self.0.iter_mut() {
            modulus.reduce_mul_assign(r, scaler);
        }
    }
}
