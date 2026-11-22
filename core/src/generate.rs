use crate::{Error, ErrorKind, Result, SecretValue};
use zeroize::Zeroizing;

/// Rules for generating a secret; `chars` replaces all character classes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationOptions {
    /// Number of Unicode characters, from 1 through 4096.
    pub size: usize,
    /// Include uppercase ASCII.
    pub upper: bool,
    /// Include lowercase ASCII.
    pub lower: bool,
    /// Include ASCII digits.
    pub digits: bool,
    /// Include ASCII symbols.
    pub symbols: bool,
    /// Override character classes with distinct, non-control characters.
    pub chars: Option<String>,
}

impl Default for GenerationOptions {
    fn default() -> Self {
        Self {
            size: 16,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            chars: None,
        }
    }
}

impl GenerationOptions {
    fn groups(&self) -> Result<Vec<Vec<char>>> {
        let invalid = || Error::new(ErrorKind::InvalidInput, "invalid secret generation options");
        if self.size == 0 || self.size > 4096 {
            return Err(invalid());
        }
        if let Some(chars) = &self.chars {
            let chars: Vec<_> = chars.chars().collect();
            if chars.is_empty()
                || chars.iter().any(|c| c.is_control())
                || chars.iter().collect::<std::collections::HashSet<_>>().len() != chars.len()
            {
                return Err(invalid());
            }
            return Ok(vec![chars]);
        }
        let groups: Vec<Vec<char>> = [
            (self.upper, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            (self.lower, "abcdefghijklmnopqrstuvwxyz"),
            (self.digits, "0123456789"),
            (self.symbols, "!@#$%^&*()-_=+[]{}:,.?"),
        ]
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, chars)| chars.chars().collect())
        .collect();
        if groups.is_empty() || self.size < groups.len() {
            return Err(invalid());
        }
        Ok(groups)
    }
    /// Validate the options without generating a value.
    pub fn validate(&self) -> Result<()> {
        self.groups().map(|_| ())
    }

    /// Generate using OS randomness and unbiased rejection sampling.
    pub fn generate(&self) -> Result<SecretValue> {
        let groups = self.groups()?;
        let alphabet: Vec<_> = groups.iter().flatten().copied().collect();
        let mut result = Zeroizing::new(Vec::with_capacity(self.size));
        for group in &groups {
            result.push(group[index(group.len())?]);
        }
        while result.len() < self.size {
            result.push(alphabet[index(alphabet.len())?]);
        }
        for i in (1..result.len()).rev() {
            let j = index(i + 1)?;
            result.swap(i, j);
        }
        let mut output = Zeroizing::new(String::new());
        for ch in result.iter() {
            output.push(*ch);
        }
        Ok(SecretValue::new(std::mem::take(&mut *output).into_bytes()))
    }
}

fn index(bound: usize) -> Result<usize> {
    let bound = u64::try_from(bound)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "generation alphabet too large"))?;
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)
            .map_err(|_| Error::new(ErrorKind::Provider, "secret generation failed"))?;
        let n = u64::from_le_bytes(bytes);
        if n >= threshold {
            return Ok((n % bound) as usize);
        }
    }
}
