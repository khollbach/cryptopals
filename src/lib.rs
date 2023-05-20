use anyhow::Result;
use base64::prelude::*;
use std::iter::zip;

pub fn hex_to_base64(hex: &str) -> Result<String> {
    let bytes = hex::decode(hex)?;
    Ok(BASE64_STANDARD_NO_PAD.encode(bytes))
}

pub fn fixed_xor(s: &[u8], t: &[u8]) -> Vec<u8> {
    assert_eq!(s.len(), t.len());
    zip(s, t).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
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

        let base64 = hex_to_base64(input).unwrap();
        assert_eq!(base64, expected);

        eprintln!("{}", hex_to_utf8(input)?);
        Ok(())
    }

    #[test]
    fn problem_1_2() -> Result<()> {
        let s = "1c0111001f010100061a024b53535009181c";
        let t = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let xor = fixed_xor(&hex::decode(s)?, &hex::decode(t)?);
        assert_eq!(hex::encode(xor), expected);

        eprintln!("{}", hex_to_utf8(t)?);
        eprintln!("{}", hex_to_utf8(expected)?);
        Ok(())
    }
}
