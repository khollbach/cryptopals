use std::iter::zip;

use anyhow::Result;
use base64::prelude::*;

pub fn hex_to_base64(hex: &str) -> Result<String> {
    let bytes = hex::decode(hex)?;
    Ok(BASE64_STANDARD_NO_PAD.encode(bytes))
}

pub fn xor_with_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key_repeated = key.iter().cycle();
    zip(bytes, key_repeated).map(|(x, y)| x ^ y).collect()
}

/// Score `s` based on letter frequencies.
///
/// English text should have a higher score than random noise.
pub fn string_score(s: &str) -> u32 {
    s.chars().map(letter_score).sum()
}

fn letter_score(c: char) -> u32 {
    match c.to_ascii_uppercase() {
        ' ' => 13,
        'E' => 12,
        'T' => 11,
        'A' => 10,
        'O' => 9,
        'I' => 8,
        'N' => 7,
        'S' => 6,
        'H' => 5,
        'R' => 4,
        'D' => 3,
        'L' => 2,
        'U' => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::PathBuf,
        rc::Rc,
    };

    use anyhow::Context;
    use itertools::Itertools;

    use super::*;

    fn hex_to_utf8(hex: &str) -> Result<String> {
        let bytes = hex::decode(hex)?;
        let s = String::from_utf8(bytes)?;
        Ok(s)
    }

    #[test]
    fn problem_1_1() -> Result<()> {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let base64 = hex_to_base64(input)?;
        assert_eq!(base64, expected);

        eprintln!("{}", hex_to_utf8(input)?);
        Ok(())
    }

    #[test]
    fn problem_1_2() -> Result<()> {
        let s = "1c0111001f010100061a024b53535009181c";
        let t = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let xor = xor_with_key(&hex::decode(s)?, &hex::decode(t)?);
        assert_eq!(hex::encode(xor), expected);

        eprintln!("{}", hex_to_utf8(t)?);
        eprintln!("{}", hex_to_utf8(expected)?);
        Ok(())
    }

    #[test]
    fn problem_1_3() -> Result<()> {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let bytes = hex::decode(input)?;

        let (best_score, answer) = (0..=u8::MAX)
            .filter_map(|key| try_decode(&bytes, key))
            .max_by_key(|&(score, _)| score)
            .context("some key must produce ascii bytes")?;

        dbg!(best_score, &answer);

        let expected_base64 = "Q29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg";
        assert_eq!(BASE64_STANDARD_NO_PAD.encode(&answer), expected_base64);

        Ok(())
    }

    /// Helper function for problem 1-3.
    fn try_decode(bytes: &[u8], key: u8) -> Option<(u32, String)> {
        let guess = xor_with_key(&bytes, &[key]);
        let s = String::from_utf8(guess).ok()?;
        let score = string_score(&s);
        Some((score, s))
    }

    #[test]
    fn problem_1_4() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-4");
        let file = BufReader::new(File::open(path)?);

        let mut err = anyhow::Ok(());
        let (best_score, answer) = file
            .lines()
            .map(|line| Ok(hex::decode(&line?)?))
            .scan(&mut err, ok)
            .map(Rc::new)
            .cartesian_product(0..=u8::MAX)
            .filter_map(|(bytes, key)| try_decode(&bytes, key))
            .max_by_key(|&(score, _)| score)
            .context("some (line, key) pair must produce ascii bytes")?;
        err?;

        dbg!(best_score, &answer);

        let expected_base64 = "Tm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmcK";
        assert_eq!(BASE64_STANDARD_NO_PAD.encode(&answer), expected_base64);

        Ok(())
    }

    /// Like `result.ok()` but doesn't discard the error.
    ///
    /// Designed to be used with `Iterator::scan`.
    fn ok<T, E>(err: &mut &mut Result<(), E>, item: Result<T, E>) -> Option<T> {
        match item {
            Ok(item) => Some(item),
            Err(e) => {
                **err = Err(e);
                None
            }
        }
    }
}
