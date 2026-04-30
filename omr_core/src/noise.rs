//! Noise statistics used by detector diagnostics and examples.

/// Aggregates signed noise samples measured after decrypting ciphertext coefficients.
///
/// Each recorded sample is a centered modular error:
/// `decrypted_phase - expected_encoded_value`, mapped into the interval around zero.
/// Positive and negative signs are preserved so [`Self::mean`] can reveal bias. The
/// absolute values are used for "largest observed error" and Gaussian-tail checks.
///
/// This is a diagnostic accumulator, not a formal cryptographic bound. Samples are
/// stored and accumulated as `f64`; integers are represented exactly only up to about
/// `2^53`, and very large sample counts can still accumulate rounding error. Variance
/// is tracked with Welford's online algorithm to avoid the cancellation in
/// `E[x^2] - E[x]^2`.
///
/// The raw samples are retained for centered tail checks such as
/// `|e - mean| > k * sigma`. This costs roughly `8 * count` bytes, before `Vec`
/// capacity overhead. For very large benchmark runs, prefer adding a separate
/// lightweight summary type instead of weakening this diagnostic type.
#[derive(Debug, Clone)]
pub struct NoiseStats {
    /// Number of recorded coefficient samples.
    pub count: usize,
    /// Smallest signed noise sample.
    pub min: f64,
    /// Largest signed noise sample.
    pub max: f64,
    /// Online empirical mean `E[e]`.
    pub mean: f64,
    /// Welford second moment accumulator `sum((e - mean)^2)`.
    pub m2: f64,
    /// Largest observed absolute noise `max(|e|)`.
    ///
    /// This is useful for checking the actual decoding margin.
    pub max_abs: f64,
    /// Raw signed samples retained for centered tail checks `|e - mean| > k*sigma`.
    samples: Vec<f64>,
}

/// Noise statistics split by the constant coefficient and all other coefficients.
#[derive(Debug, Clone, Default)]
pub struct NoiseByCoefficient {
    pub constant: NoiseStats,
    pub other: NoiseStats,
}

/// Noise observed around the trace boundary during detection.
#[derive(Debug, Clone, Default)]
pub struct DetectNoiseInfo {
    pub after_first_level_bootstrapping: NoiseStats,
    pub after_second_level_bootstrapping: NoiseByCoefficient,
    pub after_hom_trace: NoiseByCoefficient,
}

impl NoiseStats {
    /// Adds one signed centered noise sample.
    #[inline]
    pub fn record(&mut self, noise: f64) {
        if self.count == 0 {
            self.min = noise;
            self.max = noise;
        } else {
            self.min = self.min.min(noise);
            self.max = self.max.max(noise);
        }

        self.count += 1;
        self.max_abs = self.max_abs.max(noise.abs());

        let delta = noise - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = noise - self.mean;
        self.m2 += delta * delta2;

        self.samples.push(noise);
    }

    /// Merges another statistics accumulator into this one.
    #[inline]
    pub fn merge(&mut self, mut rhs: Self) {
        if rhs.count == 0 {
            return;
        }

        if self.count == 0 {
            *self = rhs;
            return;
        }

        let lhs_count = self.count;
        let rhs_count = rhs.count;
        let total_count = lhs_count + rhs_count;
        let delta = rhs.mean - self.mean;

        self.min = self.min.min(rhs.min);
        self.max = self.max.max(rhs.max);
        self.max_abs = self.max_abs.max(rhs.max_abs);
        self.mean += delta * rhs_count as f64 / total_count as f64;
        self.m2 +=
            rhs.m2 + delta * delta * lhs_count as f64 * rhs_count as f64 / total_count as f64;
        self.count = total_count;
        self.samples.append(&mut rhs.samples);
    }

    /// Empirical mean `E[e]`.
    ///
    /// For well-centered noise this should be close to zero. A large nonzero value
    /// means the noise distribution has a bias, so RMS alone is not a good sigma estimate.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Root mean square `sqrt(E[e^2])`.
    ///
    /// When the mean is close to zero, RMS is almost the same as sigma. When the mean
    /// is not close to zero, use [`Self::sigma`] for Gaussian fitting.
    #[inline]
    pub fn rms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            (self.variance() + self.mean * self.mean).sqrt()
        }
    }

    /// Population variance `E[(e - mean)^2]`.
    #[inline]
    pub fn variance(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            (self.m2 / self.count as f64).max(0.0)
        }
    }

    /// Empirical standard deviation used as the fitted Gaussian `sigma`.
    #[inline]
    pub fn sigma(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Bit size of the absolute mean, i.e. `log2(|mean|)`.
    #[inline]
    pub fn mean_bits(&self) -> f64 {
        noise_bits(self.mean.abs())
    }

    /// Bit size of RMS, i.e. `log2(rms)`.
    #[inline]
    pub fn rms_bits(&self) -> f64 {
        noise_bits(self.rms())
    }

    /// Bit size of sigma, i.e. `log2(sigma)`.
    ///
    /// This is the "typical noise scale" in bits, not the remaining decoding margin.
    #[inline]
    pub fn sigma_bits(&self) -> f64 {
        noise_bits(self.sigma())
    }

    /// Bit size of the larger positive signed sample.
    #[inline]
    pub fn max_bits(&self) -> f64 {
        noise_bits(self.max.abs())
    }

    /// Bit size of the largest observed absolute noise, i.e. `log2(max(|e|))`.
    #[inline]
    pub fn max_abs_bits(&self) -> f64 {
        noise_bits(self.max_abs)
    }

    /// Largest absolute noise expressed in fitted sigmas: `max(|e|) / sigma`.
    #[inline]
    pub fn max_abs_sigma(&self) -> f64 {
        let sigma = self.sigma();
        if sigma > 0.0 {
            self.max_abs / sigma
        } else if self.max_abs > 0.0 {
            f64::INFINITY
        } else {
            0.0
        }
    }

    /// Largest centered residual `max(|e - mean|)`.
    ///
    /// This is the value to compare to Gaussian tail predictions.
    #[inline]
    pub fn max_centered_abs(&self) -> f64 {
        let mean = self.mean();
        self.samples
            .iter()
            .map(|&noise| (noise - mean).abs())
            .fold(0.0, f64::max)
    }

    /// Largest centered residual expressed in fitted sigmas.
    #[inline]
    pub fn max_centered_sigma(&self) -> f64 {
        let sigma = self.sigma();
        if sigma > 0.0 {
            self.max_centered_abs() / sigma
        } else if self.max_centered_abs() > 0.0 {
            f64::INFINITY
        } else {
            0.0
        }
    }

    /// Count of samples outside the two-sided Gaussian-style threshold:
    /// `|e - mean| > sigma_multiplier * sigma`.
    #[inline]
    pub fn tail_count(&self, sigma_multiplier: f64) -> usize {
        let threshold = self.sigma() * sigma_multiplier;
        let mean = self.mean();
        self.samples
            .iter()
            .filter(|&&noise| (noise - mean).abs() > threshold)
            .count()
    }

    /// Counts several two-sided Gaussian-style tails in one pass over the samples.
    ///
    /// For example, passing `[3.0, 4.0, 5.0, 6.0]` returns the counts for
    /// `|e - mean| > 3*sigma`, `|e - mean| > 4*sigma`, and so on. This avoids
    /// rescanning the sample vector once per threshold.
    pub fn tail_counts<const N: usize>(&self, sigma_multipliers: [f64; N]) -> [usize; N] {
        let mut counts = [0; N];
        let sigma = self.sigma();
        let mean = self.mean();

        self.samples.iter().for_each(|&noise| {
            let centered_abs = (noise - mean).abs();
            sigma_multipliers.iter().zip(counts.iter_mut()).for_each(
                |(&sigma_multiplier, count)| {
                    if centered_abs > sigma_multiplier * sigma {
                        *count += 1;
                    }
                },
            );
        });

        counts
    }

    /// Ratio of samples outside `sigma_multiplier * sigma`.
    #[inline]
    pub fn tail_ratio(&self, sigma_multiplier: f64) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.tail_count(sigma_multiplier) as f64 / self.count as f64
        }
    }
}

impl Default for NoiseStats {
    #[inline]
    fn default() -> Self {
        Self {
            count: 0,
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            m2: 0.0,
            max_abs: 0.0,
            samples: Vec::new(),
        }
    }
}

impl NoiseByCoefficient {
    #[inline]
    pub fn merge(&mut self, rhs: Self) {
        self.constant.merge(rhs.constant);
        self.other.merge(rhs.other);
    }
}

impl DetectNoiseInfo {
    #[inline]
    pub fn merge(&mut self, rhs: Self) {
        self.after_first_level_bootstrapping
            .merge(rhs.after_first_level_bootstrapping);
        self.after_second_level_bootstrapping
            .merge(rhs.after_second_level_bootstrapping);
        self.after_hom_trace.merge(rhs.after_hom_trace);
    }
}

/// Formats a single-stage noise diagnostic report.
///
/// `decode_bound`, when present, is the distance from an encoding center to the
/// nearest decoding boundary. It is used to print sigma and worst-sample margins.
pub fn format_noise_snapshot(label: &str, stats: &NoiseStats, decode_bound: Option<f64>) -> String {
    format!(
        "[noise] {label}\n  samples      : {}\n  center       : mean={}, sigma={}\n  extremes     : max_abs={}, max_centered={}\n  decode margin: {}\n  tails:\n{}",
        stats.count,
        format_sci(stats.mean()),
        format_value_bits(stats.sigma(), stats.sigma_bits()),
        format_value_bits(stats.max_abs, stats.max_abs_bits()),
        format_value_sigma(stats.max_centered_abs(), stats.max_centered_sigma()),
        format_decode_margin(stats, decode_bound),
        format_tail_summary(stats),
    )
}

/// Formats a before/after noise diagnostic report.
pub fn format_noise_growth(
    label: &str,
    before_stage: &str,
    after_stage: &str,
    before: &NoiseStats,
    after: &NoiseStats,
) -> String {
    format!(
        "[noise growth] {label}\n  samples: {before_stage}={}, {after_stage}={}\n  metric        {:<24} {:<24} delta\n  mean          {:<24} {:<24} {}\n  sigma         {:<24} {:<24} {}\n  max_abs       {:<24} {:<24} {}\n  max_centered  {:<24} {:<24} {}\n  tails {before_stage}:\n{}\n  tails {after_stage}:\n{}",
        before.count,
        after.count,
        before_stage,
        after_stage,
        format_sci(before.mean()),
        format_sci(after.mean()),
        "-",
        format_value_bits(before.sigma(), before.sigma_bits()),
        format_value_bits(after.sigma(), after.sigma_bits()),
        format_delta_bits(growth_bits(before.sigma(), after.sigma())),
        format_value_bits(before.max_abs, before.max_abs_bits()),
        format_value_bits(after.max_abs, after.max_abs_bits()),
        format_delta_bits(growth_bits(before.max_abs, after.max_abs)),
        format_value_sigma(before.max_centered_abs(), before.max_centered_sigma()),
        format_value_sigma(after.max_centered_abs(), after.max_centered_sigma()),
        "-",
        format_tail_summary(before),
        format_tail_summary(after),
    )
}

fn format_decode_margin(stats: &NoiseStats, decode_bound: Option<f64>) -> String {
    if let Some(decode_bound) = decode_bound {
        format!(
            "sigma={}, max_abs={}",
            format_delta_bits(growth_bits(stats.sigma(), decode_bound)),
            format_delta_bits(growth_bits(stats.max_abs, decode_bound)),
        )
    } else {
        "n/a".to_owned()
    }
}

fn format_tail_summary(stats: &NoiseStats) -> String {
    let sigma_multipliers = [3.0, 4.0, 5.0, 6.0];
    let tail_counts = stats.tail_counts(sigma_multipliers);

    sigma_multipliers
        .iter()
        .zip(tail_counts)
        .map(|(&sigma_multiplier, count)| {
            let ratio = if stats.count == 0 {
                0.0
            } else {
                count as f64 / stats.count as f64
            };
            let expected =
                stats.count as f64 * gaussian_two_sided_tail_probability(sigma_multiplier);

            format!(
                "    >{sigma_multiplier:.0}s: count={count}, ratio={ratio:.3e}, expected={expected:.3e}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_sci(value: f64) -> String {
    format!("{value:.3e}")
}

fn format_value_bits(value: f64, bits: f64) -> String {
    format!("{} ({:.3} bits)", format_sci(value), bits)
}

fn format_value_sigma(value: f64, sigma: f64) -> String {
    format!("{} ({:.3} sigma)", format_sci(value), sigma)
}

fn format_delta_bits(bits: f64) -> String {
    if bits == 0.0 {
        "0.000 bits".to_owned()
    } else if bits.is_sign_positive() && bits.is_finite() {
        format!("+{bits:.3} bits")
    } else {
        format!("{bits:.3} bits")
    }
}

fn growth_bits(before: f64, after: f64) -> f64 {
    match (before > 0.0, after > 0.0) {
        (true, true) => after.log2() - before.log2(),
        (false, true) => f64::INFINITY,
        (true, false) => f64::NEG_INFINITY,
        (false, false) => 0.0,
    }
}

/// Returns the ideal two-sided standard-normal tail probability `P(|Z| > k)`.
fn gaussian_two_sided_tail_probability(sigma_multiplier: f64) -> f64 {
    match sigma_multiplier {
        x if (x - 3.0).abs() < f64::EPSILON => 2.699_796_063_260_186_6e-3,
        x if (x - 4.0).abs() < f64::EPSILON => 6.334_248_366_623_996e-5,
        x if (x - 5.0).abs() < f64::EPSILON => 5.733_031_437_583_866e-7,
        x if (x - 6.0).abs() < f64::EPSILON => 1.973_175_290_075_402_4e-9,
        _ => f64::NAN,
    }
}

#[inline]
fn noise_bits(noise: f64) -> f64 {
    if noise > 0.0 {
        noise.log2()
    } else {
        f64::NEG_INFINITY
    }
}

#[cfg(test)]
mod tests {
    use super::NoiseStats;

    #[test]
    fn records_population_variance_with_welford() {
        let mut stats = NoiseStats::default();
        [1.0, 2.0, 3.0, 4.0]
            .into_iter()
            .for_each(|sample| stats.record(sample));

        assert_eq!(stats.count, 4);
        assert_close(stats.mean(), 2.5);
        assert_close(stats.variance(), 1.25);
        assert_close(stats.sigma(), 1.25f64.sqrt());
        assert_close(stats.max_abs, 4.0);
    }

    #[test]
    fn merging_matches_recording_all_samples() {
        let mut left = NoiseStats::default();
        [1.0, 2.0]
            .into_iter()
            .for_each(|sample| left.record(sample));

        let mut right = NoiseStats::default();
        [3.0, 4.0]
            .into_iter()
            .for_each(|sample| right.record(sample));

        let mut merged = left.clone();
        merged.merge(right);

        let mut all = NoiseStats::default();
        [1.0, 2.0, 3.0, 4.0]
            .into_iter()
            .for_each(|sample| all.record(sample));

        assert_eq!(merged.count, all.count);
        assert_close(merged.mean(), all.mean());
        assert_close(merged.variance(), all.variance());
        assert_close(merged.sigma(), all.sigma());
        assert_eq!(merged.tail_counts([1.0, 2.0]), all.tail_counts([1.0, 2.0]));
    }

    fn assert_close(lhs: f64, rhs: f64) {
        assert!(
            (lhs - rhs).abs() <= 1e-12,
            "expected {lhs} to be close to {rhs}"
        );
    }
}
