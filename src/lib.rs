use anyhow::Result;
use base64::prelude::*;

pub fn hex_to_base64(hex: &str) -> Result<String> {
    let bytes = hex::decode(hex)?;
    Ok(BASE64_STANDARD_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_1_1() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let actual = hex_to_base64(input).unwrap();
        assert_eq!(actual, expected)
    }
}
