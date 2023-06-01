#![cfg(test)]

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, prelude::*, BufReader},
    iter::zip,
    path::PathBuf,
    rc::Rc,
    str,
};

use anyhow::{Context, Result};
use base64::prelude::*;
use itertools::Itertools;
use openssl::symm::{decrypt, Cipher};

#[test]
fn problem_1_1() -> Result<()> {
    let input_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = hex::decode(input_hex)?;
    let base64 = base64_encode(&bytes);
    assert_eq!(base64, expected_b64);

    eprintln!("{}", str::from_utf8(&bytes)?);

    Ok(())
}

fn base64_encode(bytes: impl AsRef<[u8]>) -> String {
    BASE64_STANDARD_NO_PAD.encode(bytes)
}

fn base64_decode(bytes: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let decoded = BASE64_STANDARD.decode(bytes)?;
    Ok(decoded)
}

#[test]
fn problem_1_2() -> Result<()> {
    let input_hex = "1c0111001f010100061a024b53535009181c";
    let key_hex = "686974207468652062756c6c277320657965";
    let expected_hex = "746865206b696420646f6e277420706c6179";

    let input = hex::decode(input_hex)?;
    let key = hex::decode(key_hex)?;
    let answer = xor_with_key(&input, &key);
    assert_eq!(hex::encode(&answer), expected_hex);

    eprintln!("{}", str::from_utf8(&key)?);
    eprintln!("{}", str::from_utf8(&answer)?);

    Ok(())
}

fn xor_with_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key_repeated = key.iter().cycle();
    zip(bytes, key_repeated).map(|(x, y)| x ^ y).collect()
}

#[test]
fn problem_1_3() -> Result<()> {
    let input_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let input = hex::decode(input_hex)?;
    let key = best_key(&input);
    let decoded = xor_with_key(&input, &[key]);
    let text = str::from_utf8(&decoded)?;
    assert!(text.contains("bacon"));

    eprintln!("{text}");

    Ok(())
}

/// Assume that `encoded_bytes` is english text that has been xor'd with a
/// single-byte key.
///
/// Guess the best key to decode it, by trying all possible keys, and looking at
/// letter frequencies in the decoded text.
fn best_key(encoded_bytes: &[u8]) -> u8 {
    (0..=u8::MAX)
        .max_by_key(|&key| key_score(encoded_bytes, key))
        .unwrap()
}

/// Helper function for `best_key`.
fn key_score(encoded_bytes: &[u8], key: u8) -> u32 {
    let maybe_text = xor_with_key(&encoded_bytes, &[key]);
    text_score(&maybe_text)
}

/// Score `s` based on letter frequencies.
///
/// English text should have a higher score than random noise.
fn text_score(s: &[u8]) -> u32 {
    s.iter().copied().map(letter_score).sum()
}

/// Helper function for `text_score`.
fn letter_score(byte: u8) -> u32 {
    match byte.to_ascii_uppercase() {
        b' ' => 150,
        b'E' => 130,
        b'T' => 91,
        b'A' => 82,
        b'O' => 75,
        b'I' => 70,
        b'N' => 67,
        b'S' => 63,
        b'H' => 61,
        b'R' => 60,
        b'D' => 43,
        b'L' => 40,
        b'C' => 28,
        b'U' => 28,
        b'M' => 24,
        b'W' => 24,
        b'F' => 22,
        b'G' => 20,
        b'Y' => 20,
        b'P' => 19,
        b'B' => 15,
        b'V' => 10,
        b'K' => 8,
        b'J' => 2,
        b'X' => 2,
        b'Q' => 1,
        b'Z' => 1,
        _ => 0,
    }
}

#[test]
fn problem_1_4() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-4");
    let file = File::open(path)?;

    let mut err = anyhow::Ok(());
    let (encoded_bytes, key) = BufReader::new(file)
        .lines()
        .map(|line| Ok(hex::decode(&line?)?))
        .scan(&mut err, ok)
        .map(Rc::new)
        .cartesian_product(0..=u8::MAX)
        .max_by_key(|(bytes, key)| key_score(&bytes, *key))
        .context("file must be non-empty")?;
    err?;

    let decoded = xor_with_key(&encoded_bytes, &[key]);
    let text = str::from_utf8(&decoded)?;
    assert!(text.contains("party"));

    eprintln!("{text}");

    Ok(())
}

/// Like `result.ok()` but doesn't discard the error.
///
/// Designed to be used with `Iterator::scan`, to stop on the first error.
fn ok<T, E>(err: &mut &mut Result<(), E>, item: Result<T, E>) -> Option<T> {
    match item {
        Ok(item) => Some(item),
        Err(e) => {
            **err = Err(e);
            None
        }
    }
}

#[test]
fn problem_1_5() {
    let input = b"Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal";
    let key = b"ICE";

    dbg!(input, key);

    let encoded = xor_with_key(input, key);
    let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(hex::encode(encoded), expected_hex);
}

#[test]
fn problem_1_6() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-6");
    let file = File::open(path)?;
    let base64: Vec<_> = BufReader::new(file)
        .lines()
        .map_ok(String::into_bytes)
        .flatten_ok()
        .collect::<io::Result<_>>()?;
    let bytes = base64_decode(base64)?;

    let key_len = best_key_len(&bytes);
    dbg!(key_len);

    let cols = transpose(&bytes, key_len);

    let key_bytes: Vec<u8> = cols.into_iter().map(|col| best_key(&col)).collect();

    // dbg!(&key_bytes, String::from_utf8(&key_bytes));

    let decoded = xor_with_key(&bytes, &key_bytes);
    let text = String::from_utf8(decoded);
    dbg!(text)?;

    Ok(())
}

fn best_key_len(bytes: &[u8]) -> usize {
    let (key_len, _score) = (2..=40)
        .map(|n| {
            let chunk_count = 4;
            let num_combinations = chunk_count * (chunk_count - 1) / 2;
            let avg_dist = bytes
                .chunks(n)
                .take(chunk_count)
                .tuple_combinations()
                .map(|(chunk1, chunk2)| normalized_hamming_distance(chunk1, chunk2))
                .sum::<f64>()
                / num_combinations as f64;

            (n, avg_dist)
        })
        .min_by(|(_, score1), (_, score2)| f64::total_cmp(score1, score2))
        .unwrap();
    key_len
}

#[test]
fn test_hamming() {
    let s = b"this is a test";
    let t = b"wokka wokka!!!";
    let n = s.len();

    let d = normalized_hamming_distance(s, t) * n as f64;
    assert_eq!(d.round() as usize, 37);
}

fn normalized_hamming_distance(s: &[u8], t: &[u8]) -> f64 {
    assert_eq!(s.len(), t.len());
    let n = s.len();

    let d: usize = zip(s, t).map(|(x, y)| (x ^ y).count_ones() as usize).sum();
    d as f64 / n as f64
}

#[test]
fn test_transpose() {
    let bytes: Vec<_> = (0..100).collect();
    let cols = transpose(&bytes, 7);

    for (i, col) in cols.into_iter().enumerate() {
        assert!(col.into_iter().all(|x| x % 7 == i as u8));
    }
}

fn transpose(bytes: &[u8], row_len: usize) -> Vec<Vec<u8>> {
    let num_cols = row_len;

    bytes
        .chunks(row_len)
        .fold(vec![vec![]; num_cols], |mut cols, row| {
            for (col, &x) in zip(&mut cols, row) {
                col.push(x);
            }
            cols
        })
}

#[test]
fn problem_1_7() -> Result<()> {
    let key = b"YELLOW SUBMARINE";

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-7");
    let file = File::open(path)?;
    let base64: Vec<_> = BufReader::new(file)
        .lines()
        .map_ok(String::into_bytes)
        .flatten_ok()
        .collect::<io::Result<_>>()?;
    let bytes = base64_decode(base64)?;

    let cipher = Cipher::aes_128_ecb();
    let decoded = decrypt(cipher, key, None, &bytes)?;

    let answer = String::from_utf8(decoded)?;
    eprintln!("{answer}");

    assert_eq!(count_occurances(&answer, "funky"), 8);
    Ok(())
}

/// Count non-overlapping occurances of `word` in `s`.
fn count_occurances(mut s: &str, word: &str) -> usize {
    if word.is_empty() {
        return 0;
    }

    let mut count = 0;
    while let Some(i) = s.find(word) {
        count += 1;
        s = &s[i + word.len()..];
    }
    count
}

#[test]
fn problem_1_8() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-8");
    let file = File::open(path)?;

    let mut err = Ok(());
    let (answer,) = BufReader::new(file)
        .lines()
        // Stop at the first error; yield only successful values.
        .scan(&mut err, ok)
        // Note that we don't bother to hex-decode the line.
        // Repeated blocks are still repeated blocks, regardless of whether
        // you're looking at hex, or at bytes.
        .filter(|line| detect_aes_ecb(line.as_bytes()))
        .collect_tuple()
        .context("there should be exactly one suspect")?;
    err?;

    let mut seen = HashMap::new();
    for (i, chunk) in answer.as_bytes().chunks(16).enumerate() {
        // Print the chunk, and whether we've seen it before.
        eprint!("{i}: {}", str::from_utf8(chunk)?);
        if let Some(idx) = seen.get(chunk) {
            eprint!(" *** ({idx}) ***");
        }
        eprintln!();

        seen.entry(chunk).or_insert(i);
    }

    Ok(())
}

fn detect_aes_ecb(bytes: &[u8]) -> bool {
    let mut seen = HashSet::new();
    bytes.chunks(16).any(|chunk| {
        let repeated = seen.contains(chunk);
        seen.insert(chunk);
        repeated
    })
}
