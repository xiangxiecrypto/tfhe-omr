use std::ops::{Add, Mul, MulAssign, Sub, SubAssign};

use itertools::izip;
use rand::RngCore;

pub const PAYLOAD_LENGTH: usize = 612;
// pub const PAYLOAD_LENGTH: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload(pub [u8; PAYLOAD_LENGTH]);

impl Payload {
    pub fn new() -> Self {
        Payload([0; PAYLOAD_LENGTH])
    }

    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore,
    {
        let mut payload = Self::new();
        rng.fill_bytes(&mut payload.0);
        payload
    }
}

impl Add<Self> for Payload {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let mut result = Self::new();
        for (r, a, b) in izip!(result.0.iter_mut(), self.0.iter(), rhs.0.iter()) {
            *r = a.wrapping_add(*b);
        }
        result
    }
}

impl Add<&Self> for Payload {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut result = Self::new();
        for (r, a, b) in izip!(result.0.iter_mut(), self.0.iter(), rhs.0.iter()) {
            *r = a.wrapping_add(*b);
        }
        result
    }
}

impl SubAssign<Self> for Payload {
    fn sub_assign(&mut self, rhs: Self) {
        for (r, b) in izip!(self.0.iter_mut(), rhs.0.iter()) {
            *r = r.wrapping_sub(*b);
        }
    }
}

impl Sub<Self> for Payload {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = Self::new();
        for (r, a, b) in izip!(result.0.iter_mut(), self.0.iter(), rhs.0.iter()) {
            *r = a.wrapping_sub(*b);
        }
        result
    }
}

impl Sub<&Self> for Payload {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut result = Self::new();
        for (r, a, b) in izip!(result.0.iter_mut(), self.0.iter(), rhs.0.iter()) {
            *r = a.wrapping_sub(*b);
        }
        result
    }
}

impl Mul<u8> for Payload {
    type Output = Self;

    fn mul(self, rhs: u8) -> Self::Output {
        let mut result = Self::new();
        for (r, a) in izip!(result.0.iter_mut(), self.0.iter()) {
            *r = a.wrapping_mul(rhs);
        }
        result
    }
}

impl MulAssign<u8> for Payload {
    fn mul_assign(&mut self, rhs: u8) {
        for r in self.0.iter_mut() {
            *r = r.wrapping_mul(rhs);
        }
    }
}
