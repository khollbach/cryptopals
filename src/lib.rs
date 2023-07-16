#![cfg(test)]

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, prelude::*, BufReader},
    iter::zip,
    path::{Path, PathBuf},
    rc::Rc,
    str,
    sync::Mutex,
};

use anyhow::{ensure, Context, Result};
use base64::prelude::*;
use itertools::Itertools;
use lazy_static::lazy_static;
use openssl::{
    rand,
    symm::{self, Cipher, Crypter},
};
use test_case::test_case;

#[test]
fn challenge_1() -> Result<()> {
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
fn challenge_2() -> Result<()> {
    let input_hex = "1c0111001f010100061a024b53535009181c";
    let key_hex = "686974207468652062756c6c277320657965";
    let expected_hex = "746865206b696420646f6e277420706c6179";

    let input = hex::decode(input_hex)?;
    let key = hex::decode(key_hex)?;
    let answer = xor_with(&input, &key);
    assert_eq!(hex::encode(&answer), expected_hex);

    eprintln!("{}", str::from_utf8(&key)?);
    eprintln!("{}", str::from_utf8(&answer)?);

    Ok(())
}

#[must_use]
fn xor_with(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key_repeated = key.iter().cycle();
    zip(bytes, key_repeated).map(|(x, y)| x ^ y).collect()
}

#[allow(unused)]
fn xor_in_place(bytes: &mut [u8], key: &[u8]) {
    let key_repeated = key.iter().cycle();
    for (x, y) in zip(bytes, key_repeated) {
        *x ^= y;
    }
}

#[test]
fn challenge_3() -> Result<()> {
    let input_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let input = hex::decode(input_hex)?;
    let key = best_key(&input);
    let decoded = xor_with(&input, &[key]);
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
    let maybe_text = xor_with(&encoded_bytes, &[key]);
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
fn challenge_4() -> Result<()> {
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

    let decoded = xor_with(&encoded_bytes, &[key]);
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
fn challenge_5() {
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let encoded = xor_with(input, key);
    let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(hex::encode(encoded), expected_hex);
}

#[test]
fn challenge_6() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-6");
    let input = decode_base64_file(path)?;

    let key_len = best_key_len(&input);
    let columns = transpose(&input, key_len);
    let key: Vec<u8> = columns.into_iter().map(|col| best_key(&col)).collect();

    let decoded = xor_with(&input, &key);
    let text = str::from_utf8(&decoded)?;
    assert_eq!(count_occurances(text, "funky"), 8);

    eprintln!("key: {:?}", str::from_utf8(&key)?);
    eprintln!();
    eprintln!("{text}");

    Ok(())
}

/// Ignores newlines.
fn decode_base64_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let file = File::open(path)?;

    let base64: Vec<u8> = BufReader::new(file)
        .lines()
        // We'd rather map `String::chars`, but that causes lifetime issues.
        .map_ok(String::into_bytes)
        .flatten_ok()
        .collect::<io::Result<_>>()?;

    base64_decode(base64)
}

fn best_key_len(bytes: &[u8]) -> usize {
    let (key_len, _score) = (2..=40)
        .map(|n| {
            let num_blocks = 4;
            let num_pairs = num_blocks * (num_blocks - 1) / 2;

            let avg_dist = bytes
                .chunks(n)
                .take(num_blocks)
                .tuple_combinations()
                .map(|(chunk1, chunk2)| normalized_hamming_distance(chunk1, chunk2))
                .sum::<f64>()
                / num_pairs as f64;

            (n, avg_dist)
        })
        .min_by(|(_, score1), (_, score2)| f64::total_cmp(score1, score2))
        .unwrap();

    key_len
}

fn normalized_hamming_distance(s: &[u8], t: &[u8]) -> f64 {
    assert_eq!(s.len(), t.len());
    hamming_distance(s, t) as f64 / s.len() as f64
}

fn hamming_distance(s: &[u8], t: &[u8]) -> usize {
    assert_eq!(s.len(), t.len());
    zip(s, t).map(|(x, y)| (x ^ y).count_ones() as usize).sum()
}

#[test]
fn test_hamming() {
    let s = b"this is a test";
    let t = b"wokka wokka!!!";
    assert_eq!(hamming_distance(s, t), 37);
}

fn transpose(bytes: &[u8], row_len: usize) -> Vec<Vec<u8>> {
    let mut cols = vec![vec![]; row_len];

    for row in bytes.chunks(row_len) {
        for (col, &x) in zip(&mut cols, row) {
            col.push(x);
        }
    }

    cols
}

#[test]
fn test_transpose() {
    let bytes: Vec<_> = (0..100).collect();
    let cols = transpose(&bytes, 7);

    for (i, col) in cols.into_iter().enumerate() {
        for x in col {
            assert_eq!(x % 7, i as u8);
        }
    }
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
fn challenge_7() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-7");
    let input = decode_base64_file(path)?;

    let cipher = Cipher::aes_128_ecb();
    let key = b"YELLOW SUBMARINE";
    let decoded = symm::decrypt(cipher, key, None, &input)?;
    let text = str::from_utf8(&decoded)?;

    let expected = concat!(env!("CARGO_MANIFEST_DIR"), "/inputs/1-7-decoded");
    let expected = fs::read_to_string(expected)?;
    assert_eq!(expected, text);

    eprintln!("{text}");

    Ok(())
}

#[test]
fn challenge_8() -> Result<()> {
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
        .context("there should be exactly one 'suspect'")?;
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

#[test_case(b"YELLOW SUBMARINE", 20, b"YELLOW SUBMARINE\x04\x04\x04\x04")]
#[test_case(b"YELLOW SUBMARINE", 10, b"YELLOW SUBMARINE\x04\x04\x04\x04")]
#[test_case(b"YELLOW SUBMARINE", 5, b"YELLOW SUBMARINE\x04\x04\x04\x04")]
#[test_case(b"YELLOW SUBMARINE", 3, b"YELLOW SUBMARINE\x02\x02")]
#[test_case(b"SUBMARINE", 2, b"SUBMARINE\x01")]
#[test_case(
    b"YELLOW SUBMARINE",
    16,
    b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
)]
#[test_case(b"YELLOW SUBMARINE", 1, b"YELLOW SUBMARINE\x01")]
#[test_case(b"", 5, b"\x05\x05\x05\x05\x05")]
#[test_case(b"", 1, b"\x01")]
fn challenge_9(input: &[u8], n: usize, expected: &[u8]) {
    let mut buf = Vec::from(input);
    pkcs7_pad(&mut buf, n);
    assert_eq!(expected, buf);
}

/// Pad `buf` so that its length is a multiple of `n`.
///
/// If it's length is already divisible by `n`, pad a whole block.
fn pkcs7_pad(buf: &mut Vec<u8>, n: usize) {
    assert_ne!(n, 0);
    assert!(n < 256);

    // Note the edge-case: if overflow is 0, padding is `n`.
    let overflow = buf.len() % n;
    let padding = n - overflow;

    let new_len = buf.len() + padding;
    debug_assert_eq!(new_len % n, 0);

    buf.resize(new_len, padding as u8);
}

#[test]
fn challenge_10() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/2-10");
    let input = decode_base64_file(path)?;

    let iv = vec![0u8; 16];
    let key = b"YELLOW SUBMARINE";
    let decoded = cbc_decrypt(&input, key, &iv)?;

    let text = str::from_utf8(&decoded)?;
    eprintln!("{text}");

    Ok(())
}

#[test]
fn challenge_11() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("inputs/1-7-decoded");
    let text = fs::read_to_string(path)?;
    let text_bytes = text.as_bytes();
    let encypted_bytes = encryption_sphinx(text_bytes)?;
    encryption_oracle(&encypted_bytes);
    Ok(())
}

fn cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(ciphertext.len() % 16, 0);
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev_cipher_block = Vec::from(iv);

    let cipher = Cipher::aes_128_ecb();
    let cipher_len = cipher.block_size();
    for block in ciphertext.chunks(16) {
        assert_eq!(block.len(), 16);

        let mut decryptor = Crypter::new(cipher, symm::Mode::Decrypt, key, None)?;
        decryptor.pad(false); // !!!!!!!!!

        let mut decrypted_text = vec![0; block.len() + cipher_len];

        let mut bytes_written = decryptor.update(&block, &mut decrypted_text)?;
        bytes_written += decryptor.finalize(&mut decrypted_text)?;

        assert_eq!(bytes_written, 16);
        decrypted_text.truncate(bytes_written);

        let plain_text = xor_with(&decrypted_text, &prev_cipher_block);

        out.extend_from_slice(&plain_text);
        prev_cipher_block = Vec::from(block);
    }

    Ok(out)
}

fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    assert!(plaintext.len() % 16 == 0);

    let mut out = Vec::with_capacity(plaintext.len());

    let mut prev_cipher_block = Vec::from(iv);

    for block in plaintext.chunks(16) {
        assert_eq!(block.len(), 16); // b/c of padding

        let salted_block = xor_with(block, &prev_cipher_block);
        let mut cipher_block = symm::encrypt(Cipher::aes_128_ecb(), &key, None, &salted_block)?;
        cipher_block.truncate(16);
        assert_eq!(cipher_block.len(), 16);

        out.extend_from_slice(&cipher_block);
        prev_cipher_block = cipher_block;
    }

    Ok(out)
}

// fn cbc_block(
//     block: &[u8],
//     prev_cipher_block: &[u8],
//     key: &[u8],
//     mode: Mode,
//     // out: &mut Vec<u8>,
// ) -> Result<Vec<u8>> {
//     let salted_block = if mode == Mode::Encrypt {
//         xor_with(block, prev_cipher_block)
//     } else {
//         Vec::from(block)
//     };

//     let cipher = Cipher::aes_128_ecb();
//     let crypted_block = if mode == Mode::Encrypt {
//         symm::encrypt(cipher, key, None, &salted_block)?

//         // TODO(kevan): clean this up, test it against an input of your choice.

//         // let mut decryptor = Crypter::new(cipher, symm::Mode::Encrypt, key, None)?;
//         // decryptor.pad(false); // !!!!!!!!!

//         // let mut decrypted_text = vec![0; block.len() + cipher_len];

//         // let mut bytes_written = decryptor.update(&block, &mut decrypted_text)?;
//         // bytes_written += decryptor.finalize(&mut decrypted_text)?;
//     } else {
//         symm::decrypt(cipher, key, None, &salted_block)?
//     };

//     let unsalted_block = if mode == Mode::Encrypt {
//         Vec::from(block)
//     } else {
//         xor_with(&crypted_block, prev_cipher_block)
//     };

//     Ok(unsalted_block)
// }
#[test]
fn cbc_test() -> Result<()> {
    let block_len = 16;
    let plaintext = b"Now that the party is jumpin'";
    let mut padded = plaintext.to_vec();
    pkcs7_pad(&mut padded, 16);

    let key = random_aes_key()?;
    let iv = random_aes_key()?;
    let ciphertext = cbc_encrypt(&padded, &key, &iv)?;
    let mut decrypted = cbc_decrypt(&ciphertext, &key, &iv)?;
    print!("Decrypted string: {}", String::from_utf8_lossy(&decrypted));
    pkcs7_unpad(&mut decrypted, block_len)?;
    assert_eq!(plaintext.as_slice(), decrypted);
    Ok(())
}

fn random_aes_key() -> Result<[u8; 16]> {
    let mut key = [0; 16];
    openssl::rand::rand_bytes(&mut key)?;
    Ok(key)
}

fn encryption_oracle(encypted_bytes: &[u8]) {
    if detect_aes_ecb(encypted_bytes) {
        println!("[Oracle] Is ECB!");
    } else {
        println!("[Oracle] Is CBC!");
    }
}

fn encryption_sphinx(bytes: &[u8]) -> Result<Vec<u8>> {
    let key = random_aes_key()?;
    let is_ecb = key[0] < 128;
    let iv = random_aes_key()?;

    let mut encypted_text = bytes.to_vec();
    // Prepend/append bytes
    let num_prepend = key[1] % 6;
    let num_append = key[2] % 6;
    encypted_text.extend(vec![0; (5 + num_append) as usize]);
    // Weird way of prepending a vector to another vector
    encypted_text.splice(0..0, vec![0u8; (5 + num_prepend) as usize]);

    if is_ecb {
        println!("[Sphinx]: I am encrypting using ecb.");
        encypted_text = symm::encrypt(Cipher::aes_128_ecb(), &key, None, &encypted_text)?;
    } else {
        println!("[Sphinx]: now using cbc.");
        encypted_text = symm::encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), &encypted_text)?;
    }

    Ok(encypted_text)
}

#[test]
fn challenge_12() -> Result<()> {
    let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let secret_message = base64_decode(secret_b64)?;
    let sphinx = SuffixSphinx::new(secret_message)?;

    // find the block size (todo)
    let block_size = 16;

    // Verify ECB mode.
    let identical_blocks = vec![0; block_size * 2];
    let cipher_text = sphinx.encrypt(&identical_blocks)?;
    assert_eq!(
        &cipher_text[..block_size],
        &cipher_text[block_size..block_size * 2]
    );

    // Test Decode
    let decoded = decrypt_suffix_sphinx(sphinx, block_size);
    let text = str::from_utf8(&decoded)?;
    println!("Challenge 12: {}", text);
    Ok(())
}

struct SuffixSphinx {
    key: Vec<u8>,
    plaintext_suffix: Vec<u8>,
}

impl SuffixSphinx {
    fn new(plaintext_suffix: Vec<u8>) -> Result<Self> {
        let key = random_aes_key()?.to_vec();
        Ok(Self {
            key,
            plaintext_suffix,
        })
    }

    fn encrypt(&self, plaintext_prefix: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![];
        plaintext.extend_from_slice(plaintext_prefix);
        plaintext.extend_from_slice(&self.plaintext_suffix);

        Ok(symm::encrypt(
            Cipher::aes_128_ecb(),
            &self.key,
            None,
            &plaintext,
        )?)
    }
}

fn secret_sphinx_suffix_len(sphinx: &SuffixSphinx, block_size: usize) -> usize {
    let init_len = sphinx.encrypt(&[]).unwrap().len();
    for i in 1..block_size {
        let new_len = sphinx.encrypt(&vec![0u8; i]).unwrap().len();
        if new_len != init_len {
            return new_len - block_size - i;
        }
    }
    unreachable!()
}

fn decrypt_suffix_sphinx(sphinx: SuffixSphinx, block_size: usize) -> Vec<u8> {
    let suffix_len = secret_sphinx_suffix_len(&sphinx, block_size);
    //println!("--> Length of encrypted text: {}", suffix_len);
    let mut suffix = vec![0; suffix_len];

    for i in 0..suffix_len {
        let pad_len = block_size - (i % block_size) - 1;
        let block_index = i / block_size;
        let base = block_index * block_size;

        let padding = vec![0u8; pad_len];
        let expected_cipher = sphinx.encrypt(&padding).unwrap();
        let expected_cipher_block = expected_cipher[base..][..block_size].to_vec();

        let mut prefix_pad = vec![0u8; pad_len];
        let mut cipher_to_byte = HashMap::new();
        for j in 0..=u8::MAX {
            prefix_pad.extend_from_slice(&suffix[..i]);
            prefix_pad.push(j);

            let cipher = sphinx.encrypt(&prefix_pad).unwrap();
            let cipher_block = cipher[base..][..block_size].to_vec();
            cipher_to_byte.insert(cipher_block, j);

            prefix_pad.truncate(pad_len);
        }
        assert!(cipher_to_byte.contains_key(&expected_cipher_block));
        suffix[i] = cipher_to_byte[&expected_cipher_block];
    }

    suffix
}

/*

[x] Sphinx

[ ] GOAL: create a ciphertext which decrypts to a user-object w/ role=admin

allowed to ask the sphinx any # of Qs, with any usernames
* (but not "&" or "=")
* OR MAYBE we accept & and =, but escape them when parsing
    (and maybe this matters? so that the sphinx accepts arbitrary bytes... we'll see)

*/

// Normal:
// email=foo@bar.com&uid=10&role=user
// Mine:
// (1) Isolate the user in its own block
// email=aaaaa@mail|.com&uid=1&role=|user
// (2) Find a replacement block
// email=aaaaaaaaaa|admin\x0b-\x0b|@mail.com&uid=1&|role=user
// (3) Replace the last block of the first email with the second block of the second

#[test]
fn challenge_13() {
    // let emails = ["bob", "joe", "jane", "annie"];
    // for email in emails {
    //     dbg!(str::from_utf8(&serialized_profile(email.as_bytes())).unwrap());
    // }
    let sphinx = ProfileSphinx::new().unwrap();
    let admin_cipher_text = generate_admin_cipher_text(&sphinx);
    assert!(sphinx.decrypt_for(&admin_cipher_text));
}

struct ProfileSphinx {
    key: Vec<u8>,
}

impl ProfileSphinx {
    fn new() -> Result<Self> {
        Ok(Self {
            key: random_aes_key()?.to_vec(),
        })
    }

    fn profile_for(&self, email: &[u8]) -> Result<Vec<u8>> {
        let serialized_user_object = serialized_profile(email);
        // println!("SSS -> Profile for: {:?} ({})", serialized_user_object, serialized_user_object.len());
        // Done automatically
        // pkcs7_pad(&mut serialized_user_object, 16);
        // println!("SSS -> Padded: {:?}", serialized_user_object);

        Ok(symm::encrypt(
            Cipher::aes_128_ecb(),
            &self.key,
            None,
            &serialized_user_object,
        )?)
    }

    fn decrypt_for(&self, cipher_text: &[u8]) -> bool {
        assert!(cipher_text.len() % 16 == 0);
        let plain_text =
            symm::decrypt(Cipher::aes_128_ecb(), &self.key, None, &cipher_text).unwrap();
        let plain_text = String::from_utf8(plain_text).unwrap();
        plain_text.ends_with("admin")
    }
}

fn serialized_profile(email: &[u8]) -> Vec<u8> {
    let user = User::new(email);
    user.serialize()
}

#[derive(Debug)]
struct User {
    email: Vec<u8>,
    uid: u32,
    role: Vec<u8>,
}

impl User {
    fn new(email: &[u8]) -> Self {
        // Global incrementing sequence number.
        lazy_static! {
            static ref UID: Mutex<u32> = Default::default();
        }
        *UID.lock().unwrap() += 1;

        Self {
            email: email.to_vec(),
            uid: *UID.lock().unwrap(),
            role: b"user".to_vec(),
        }
    }

    // TODO: escape special chars '=' and '&' !!!
    fn serialize(&self) -> Vec<u8> {
        let mut out = vec![];
        write!(out, "email=").unwrap();
        out.extend_from_slice(&self.email);
        write!(out, "&uid={}", self.uid).unwrap();
        write!(out, "&role=").unwrap();
        out.extend_from_slice(&self.role);
        out
    }
}

fn generate_admin_cipher_text(sphinx: &ProfileSphinx) -> Vec<u8> {
    let block_len = 16;
    let email = b"aaaaa@mail.com";

    let mut encrypted_email = sphinx.profile_for(email).unwrap();
    let encrypted_len = encrypted_email.len();
    // println!("Encrypted {:?}", encrypted_email);

    let mut place_holder = b"aaaaaaaaaa".to_vec();
    // println!("Placeholder length: {}", b"email=aaaaaaaaaa".len());
    place_holder.extend(b"admin".to_vec());
    place_holder.extend(vec![11; 11]);
    place_holder.extend(b"@mail.com".to_vec());
    // println!("Placeholder: {:?}, length: {}", place_holder, place_holder.len());
    let encrypted_place_holder = sphinx.profile_for(place_holder.as_slice()).unwrap();
    // println!("Placeholder {:?}", encrypted_place_holder);
    let encrypted_place_holder = encrypted_place_holder
        .get(block_len..2 * block_len)
        .unwrap();

    // println!("encrypted {:?} ({})", encrypted_email, encrypted_email.len());
    encrypted_email.truncate(encrypted_len - block_len);
    encrypted_email.extend(encrypted_place_holder.to_vec());
    // println!("encrypted {:?} ({})", encrypted_email, encrypted_email.len());

    encrypted_email
}

#[test]
fn challenge_14() -> Result<()> {
    let b64 = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let mut secret_string = base64_decode(b64)?;
    secret_string.truncate(16);

    let sphinx = RandomPrefixSphinx::new(secret_string.clone())?;
    let message = decrypt_prefix_sphinx(&sphinx)?;

    assert_eq!(message, secret_string);

    Ok(())
}

// assumptions:
// * secret suffix length = 16

// 1. call Sphinx::encrypt("x") 160 times
// 2. look at the distribution of lengths
// * ~10 times, we expect to see 48 bytes of ciphertext
//   (15 random padding, 1 byte "x", 16 bytes suffix, 16 bytes padding)

// 3. for all A,
//    call Sphinx::encrypt("x | 000...000A") 160 times
//                              ^ 15 zeros and A (where A \in {0..256})
// 4. 1/16 of the time, ciphertext will be length 64
//    and there's a block boundary at the '|'
//    in all of these cases, we can write down the ciphertext for the block
//    00..00A and we now want to compare this against the "true" ciphertext,
//    so that we've brute-forced the "true" value of A.
// 5. find the "true" ciphertext by calling Sphinx::encrypt("x | 000...000")
//    (without the A) some number of times (details.......?)
// 6. 1/16 of the time, this will result in a cipherblock we've seen before
//    from step 4 (yay! that means the random padding was len=15; done.)

fn brute_force_next_byte(sphinx: &RandomPrefixSphinx, current_guess: &[u8]) -> Result<u8> {
    let block_size = 16;
    let mut input = generate_padding(current_guess, block_size);

    // cipherblock -> guess-byte
    let mut map = HashMap::new();

    // let mut input = vec![0; 17];
    // input[0] = b'x';

    for guess in 0..=u8::MAX {
        input.push(guess);

        let cipherblock = loop {
            let ciphertext = sphinx.encrypt(&input)?;
            // dbg!((input.len(), guess, ciphertext.len()));
            assert!([48, 64].contains(&ciphertext.len()));
            if ciphertext.len() == 64 {
                // in this case, the random padding is a "nice" length.
                break ciphertext[16..32].to_vec();
            }
        };

        map.insert(cipherblock, guess);
        input.pop();
    }

    // find one of these cipherblocks
    input.truncate(input.len() - current_guess.len());
    let first_byte = loop {
        // let mut input = vec![0; 16];
        // input[0] = b'x';
        let ciphertext = sphinx.encrypt(&input)?;
        let cipherblock = &ciphertext[16..32];
        if let Some(&guess_byte) = map.get(cipherblock) {
            break guess_byte;
        }
    };

    Ok(first_byte)
}

fn generate_padding(current_guess: &[u8], block_size: usize) -> Vec<u8> {
    let current_len = current_guess.len();
    let pad_len = block_size - (current_len % block_size);
    let mut pad = vec![0u8; pad_len];
    pad[0] = b'x';
    pad.extend_from_slice(current_guess);
    pad
}

fn decrypt_prefix_sphinx(sphinx: &RandomPrefixSphinx) -> Result<Vec<u8>> {
    let suffix_len = 16;
    //println!("--> Length of encrypted text: {}", suffix_len);
    let mut suffix = vec![0; suffix_len];

    for i in 0..suffix_len {
        suffix[i] = brute_force_next_byte(sphinx, &suffix[..i])?;
    }

    Ok(suffix)
}

struct RandomPrefixSphinx {
    key: Vec<u8>,
    plaintext_suffix: Vec<u8>,
}

impl RandomPrefixSphinx {
    fn new(plaintext_suffix: Vec<u8>) -> Result<Self> {
        let key = random_aes_key()?.to_vec();
        Ok(Self {
            key,
            plaintext_suffix,
        })
    }

    fn encrypt(&self, plaintext_infix: &[u8]) -> Result<Vec<u8>> {
        // generate a random prefix
        let prefix_len = random_aes_key()?[0] % 16;
        let mut prefix = vec![0; prefix_len as usize];
        rand::rand_bytes(&mut prefix)?;

        let mut plaintext = vec![];
        plaintext.extend_from_slice(&prefix);
        plaintext.extend_from_slice(plaintext_infix);
        plaintext.extend_from_slice(&self.plaintext_suffix);

        Ok(symm::encrypt(
            Cipher::aes_128_ecb(),
            &self.key,
            None,
            &plaintext,
        )?)
    }
}

#[test_case(b"ICE ICE BABY\x04\x04\x04\x04", 16, Some(b"ICE ICE BABY"))]
#[test_case(b"ICE ICE BABY\x05\x05\x05\x05", 16, None)]
#[test_case(b"ICE ICE BABY\x01\x02\x03\x04", 16, None)]
fn challenge_15(input: &[u8], block_len: usize, expected: Option<&[u8]>) {
    let mut buf = Vec::from(input);
    let result = pkcs7_unpad(&mut buf, block_len);

    if let Some(expected) = expected {
        assert!(result.is_ok());
        assert_eq!(buf, expected);
    } else {
        assert!(result.is_err());
    }
}

fn pkcs7_unpad(buf: &mut Vec<u8>, block_len: usize) -> Result<()> {
    ensure!(buf.len() % block_len == 0);

    let pad_len = *buf.last().context("buffer can't be empty")?;
    ensure!(pad_len != 0);
    ensure!(pad_len as usize <= block_len);

    let new_len = buf.len() - pad_len as usize;
    ensure!(buf[new_len..].iter().all(|&byte| byte == pad_len));

    buf.truncate(new_len);
    Ok(())
}

#[test_case(b";hello=world;", false)]
#[test_case(b";admin=true;", false)]
#[test_case(b"", false)]
fn challenge_16(input: &[u8], expected: bool) -> Result<()> {
    let sphinx = BitFlipSphinx::new()?;
    let ciphertext = sphinx.encrypt(input)?;
    assert!(sphinx.decrypt(&ciphertext).unwrap() == expected);
    Ok(())
}

#[test]
fn break_bitflip_sphinx() -> Result<()> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let _suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
    let target_text = b";admin=true";
    //                  0123456

    let sphinx = BitFlipSphinx::new()?;

    // one block of padding, plus enough space for the target text.
    let mut input = vec![b'a'; 16];
    input.extend_from_slice(target_text);

    // Flip bits so that these characters don't get escaped.
    input[16] ^= 1; // ; becomes :
    input[16 + 6] ^= 1; // = becomes <

    let mut cipher = sphinx.encrypt(&input)?;

    // Flip bits in the padding block, to make the target text appear.
    let offset = prefix.len();
    cipher[offset] ^= 1;
    cipher[offset + 6] ^= 1;

    let success = sphinx.decrypt(&cipher)?;
    assert!(success);

    Ok(())
}

struct BitFlipSphinx {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl BitFlipSphinx {
    fn new() -> Result<Self> {
        let key = random_aes_key()?.to_vec();
        let iv = random_aes_key()?.to_vec();

        Ok(Self { key, iv })
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // generate a random prefix
        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

        let mut clean_plaintext = vec![];
        let mut escaped = escaped_special_characters(plaintext);
        // dbg!(String::from_utf8(escaped.clone()));
        clean_plaintext.extend_from_slice(prefix);
        clean_plaintext.append(&mut escaped);
        clean_plaintext.extend_from_slice(suffix);
        // dbg!(String::from_utf8(clean_plaintext.clone()));

        Ok(symm::encrypt(
            Cipher::aes_128_cbc(),
            &self.key,
            Some(&self.iv),
            &clean_plaintext,
        )?)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<bool> {
        let plaintext =
            symm::decrypt(Cipher::aes_128_cbc(), &self.key, Some(&self.iv), ciphertext).unwrap();
        dbg!(String::from_utf8_lossy(&plaintext));
        Ok(contains_needle(&plaintext, b";admin=true;"))
    }
}

fn contains_needle(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn escaped_special_characters(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len());

    for &c in plaintext {
        let c_slice = [c];
        let bytes = match c {
            b'=' => b"%3D".as_slice(),
            b';' => b"%3B".as_slice(),
            b'%' => b"%25".as_slice(),
            _ => &c_slice,
        };
        out.extend_from_slice(bytes);
    }

    out

    // plaintext
    //     .iter()
    //     .flat_map(|h| match h {
    //         b'=' => {
    //             Either::Left(b"%3D".into_iter())
    //         },
    //         b';' => {
    //             Either::Left(b"%3B".into_iter())
    //         },
    //         b'%' => {
    //             Either::Left(b"%25".into_iter())
    //         }
    //         _ => {
    //             Either::Right([h].into_iter())
    //         }
    //     })
    //     .copied()
    //     .collect()
}

fn decode_base64_file_into_lines(path: impl AsRef<Path>) -> io::Result<Vec<Vec<u8>>> {
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    let file = File::open(full_path)?;

    BufReader::new(file)
        .lines()
        .map_ok(String::into_bytes)
        .map_ok(|bytes| base64_decode(bytes).unwrap())
        .collect()
}

struct CbcPaddingSphoracle {
    key: Vec<u8>,
}

impl CbcPaddingSphoracle {
    fn new() -> Result<Self> {
        let key = random_aes_key()?.to_vec();
        Ok(Self { key })
    }

    fn encrypt(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let iv = random_aes_key()?.to_vec();
        let mut rand_byte = [0; 1];
        openssl::rand::rand_bytes(&mut rand_byte)?;
        let [rand_byte] = rand_byte;

        let input_strings = decode_base64_file_into_lines("inputs/3-17")?;
        let mut rand_string = input_strings[rand_byte as usize % 10].clone();
        pkcs7_pad(&mut rand_string, 16);

        // Ok((
        //     symm::encrypt(Cipher::aes_128_cbc(), &self.key, Some(&iv), &rand_string)?,
        //     iv,
        // ))
        Ok((cbc_encrypt(&rand_string, &self.key, &iv)?, iv))
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<bool> {
        let mut plaintext = cbc_decrypt(ciphertext, &self.key, &iv)?;
        // symm::decrypt(Cipher::aes_128_cbc(), &self.key, Some(&iv), &ciphertext)?;
        // dbg!(String::from_utf8_lossy(&plaintext));
        Ok(pkcs7_unpad(&mut plaintext, 16).is_ok())
    }
}

#[test]
fn challenge_17() -> Result<()> {
    let sphoracle = CbcPaddingSphoracle::new()?;

    let (ciphertext, iv) = sphoracle.encrypt()?;
    assert_eq!(ciphertext.len() % 16, 0);

    let mut message = Vec::with_capacity(ciphertext.len());

    let mut prev = iv.as_slice();
    for cipherblock in ciphertext.chunks(16) {
        assert_eq!(cipherblock.len(), 16);

        let block = guess_block(&sphoracle, Iv(prev.try_into().unwrap()), cipherblock)?;
        dbg!(String::from_utf8_lossy(&block));
        message.extend_from_slice(&block);

        prev = cipherblock;
    }

    // dbg!(String::from_utf8_lossy(&message));

    Ok(())
}

struct Iv([u8; 16]);

fn guess_block(sphoracle: &CbcPaddingSphoracle, Iv(iv): Iv, cipherblock: &[u8]) -> Result<Vec<u8>> {
    // Fills up from the back.
    let mut known = vec![0; 16];

    for num_padding in 1..=16 {
        // goal: guess i-th last byte of first plainblock
        for mask in 0.. {
            if mask >= 256 {
                panic!("couldn't guess byte {num_padding}");
            }

            let target_idx = 16 - num_padding;

            // copy iv and leave the original unchanged, for the next iteration.
            let mut iv = iv;

            // flip known bytes (0s in prefix of `known` get ignored)
            xor_in_place(&mut iv, &known);
            // enforce padding bytes in those positions
            for j in target_idx + 1..16 {
                iv[j] ^= num_padding as u8;
            }

            // flip bits in ith last byte of IV
            iv[target_idx] ^= mask as u8;

            // check if that is creating a valid-ly padded plainblock
            let success = sphoracle.decrypt(cipherblock, &iv)?;
            if success {
                let guess = mask as u8 ^ num_padding as u8;
                // dbg!(guess, guess as char);

                known[target_idx] = guess;
                break;
            }
        }
    }

    // let s = String::from_utf8_lossy(&known);
    // dbg!(s);
    Ok(known)
}
