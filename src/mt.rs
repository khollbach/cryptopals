use std::io::Read;
const W: u32 = 32;
const N: u32 = 624;
const M: u32 = 397;
const R: u32 = 31;

const A: u32 = 0x9908_B0DF;

const U: u32 = 11;
const D: u32 = 0xFFFF_FFFF;

const S: u32 = 7;
const B: u32 = 0x9D2C_5680;

const T: u32 = 15;
const C: u32 = 0xEFC6_0000;

const L: u32 = 18;

const F: u32 = 1_812_433_253;

const LOWER_MASK: u32 = (1 << R) - 1; // That is, the binary number of r 1's
const UPPER_MASK: u32 = !LOWER_MASK;

const DEFAULT_SEED: u32 = 5489;

struct MersenneTwister19937 {
    index: usize,
    mt: [u32; N as usize],
}

impl Default for MersenneTwister19937 {
    fn default() -> Self {
        let mut ret = MersenneTwister19937 { index: 0, mt: [0; N as usize] };
        ret.seed(DEFAULT_SEED);
        ret
    }
}

impl MersenneTwister19937 {
    fn seed(&mut self, seed: u32) {
        self.index = N as usize;
        self.mt[0] = seed;
        for i in 1.. N as usize { // loop over each element
            self.mt[i] = F.wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (W - 2))).wrapping_add(i as u32);
        }
    }

    fn twist(&mut self) {
        for i in 0.. N as usize{
            let x = (self.mt[i] & UPPER_MASK)
                    | (self.mt[(i+1) % N as usize] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 { // lowest bit of x is 1
                x_a = x_a ^ A;
            }
            self.mt[i] = self.mt[(i + M as usize) % N as usize] ^ x_a;
        }
        self.index = 0;
    }

    fn extract(&mut self) -> u32 {
        if self.index >= N as usize {
            self.twist();
        }
    
        let mut y = self.mt[self.index];
        self.index += 1;
        temper(y)
    }
}

fn temper(mut y: u32) -> u32 {
    y ^= (y >> U) & D; // U=11 D=all_ones
    y ^= (y << S) & B; // S=7  B=9D2C_5680
    y ^= (y << T) & C;
    y ^= y >> L;
    y
}

fn invert_temper(mut y: u32) -> u32 {
    y = invert_xor_shift_right_and_mask(y, L, !0);
    y = invert_xor_shift_left_and_mask(y, T, C);
    y = invert_xor_shift_left_and_mask(y, S, B);
    y = invert_xor_shift_right_and_mask(y, U, D);
    y
}


/// Inverse of x ^= (x >> shift) & mask
fn invert_xor_shift_right_and_mask(x: u32, shift: u32, mask: u32) -> u32 {
    invert_xor_shift_left_and_mask(x.reverse_bits(), shift, mask.reverse_bits()).reverse_bits()
}

/// Inverse of x ^= (x << shift) & mask
fn invert_xor_shift_left_and_mask(x: u32, shift: u32, mask: u32) -> u32 {
    assert!(shift >= 1);
    let mut res = 0;
    for bit in 0.. 32 {
        // If bit < shift
        // or mask[bit] == 0
        // or res[bit - shift] == 0 // Note we've filled in res=x for bits before bit.
        // then (x << shift) & mask is 0,
        // so we just copy the bit
        if bit < shift 
        || (mask & (1 << bit)) == 0
        || (bit >= shift && (res & (1 << (bit - shift))) == 0) {
            // res[bit] = x[bit]
            res = (res & !(1 << bit)) | (x & (1 << bit));
        }
        // Otherwise, (x << shift) & mask is 1
        // so we set res[bit] to !x[bit]
        else {
            // res[bit] = !x[bit]
            res = (res & !(1 << bit)) | (!x & (1 << bit));
        }

    }
    res
}

#[test]
fn test_invert_temper() {
    for i in 0.. 2u32.pow(20) {
        assert_eq!(i, invert_temper(temper(i)));
    }
}

#[test]
fn invert_xor_shift_and_mask_test() {
    for shift in 1.. 32 {
        for mask in [0x1010_1010, 0xffff_ffff, 0] {
            for x in 0.. 100_000 {
                let x = x * 1027;
                assert_eq!(x, invert_xor_shift_left_and_mask(x ^ (x << shift) & mask, shift, mask));
                assert_eq!(x, invert_xor_shift_right_and_mask(x ^ (x >> shift) & mask, shift, mask));
            }
        }
    }
}

#[test]
fn compare_to_test_vector(){
    let mut mt = MersenneTwister19937::default();

    const TEST_VECTOR: [u32; 1000] = include!("mt/mt_19937_test_vector");

    for expected in TEST_VECTOR {
        let actual = mt.extract();
        assert_eq!(expected, actual);
    }
}

// #[test]
// fn invert_bit_shift(){
//     let mut mt = MersenneTwister19937::default();
//     mt.test();
// }

// let t = Instant::now();

#[test]
fn challenge_22 (){
    let target = {
        let random_time = 123498798;

        let mut rng = MersenneTwister19937::default();
        rng.seed(random_time);
        rng.extract()
    };

    let end_time = 123498798 + 1900;

    for i in end_time - 2000.. end_time {
        let mut rng = MersenneTwister19937::default();

        rng.seed(i as u32);
        let y = rng.extract();

        if y == target {
            eprintln!("Seed is probably {i}");
            assert_eq!(i, 123498798);
            return
        }
    }
    panic!("Failed to find seed");

    // // Forwards was
    // {
    //     let x = self.mt[0] & UPPER_MASK | self.mt[1] & LOWER_MASK;
    //     x_a = x >> 1;
    //     if x % 2 != 0 {
    //         x_a = x_a ^ A
    //     }
    //     self.mt[0] = self.mt[M] % x_a
    // }

    //t_0 = invert_temper(out);
    // GOAL: Find seed from out.
}

fn crypt_mt(key: u32, plaintext: Vec<u8>) -> Vec<u8> {
    let mut bytes = plaintext;
    let mut rng = MersenneTwister19937::default();
    rng.seed(key);
    for b in &mut bytes {
        *b ^= (rng.extract() % 256) as u8
    }
    bytes
}

trait ReadArray: Read {
    fn read_array<const N: usize>(&mut self) -> std::io::Result<[u8; N]>;

    fn read_le_u8(&mut self) -> std::io::Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_le_u16(&mut self) -> std::io::Result<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    fn read_le_u128(&mut self) -> std::io::Result<u128> {
        Ok(u128::from_le_bytes(self.read_array::<16>()?))
    }
}

impl<T: Read> ReadArray for T {
    fn read_array<const N: usize>(&mut self) -> std::io::Result<[u8; N]> {
        let mut arr = [0; N];
        self.read_exact(&mut arr)?;
        Ok(arr)
    }
}

#[test]
fn challenge_24_a() {
    let known_text = b"aaaaaaaaaaaaaa";

    let mut urandom = std::fs::File::open("/dev/urandom").unwrap();
    // let mut randLen: = [u8; 100];
    let key = urandom.read_le_u16().unwrap();
    let prefixLen = urandom.read_le_u8().unwrap();
    let mut plaintext: Vec<u8> = urandom.bytes().take(prefixLen as usize).collect::<Result<_, _>>().unwrap();
    plaintext.extend_from_slice(known_text);
    let ciphertext = crypt_mt(key as u32, plaintext);

    for potential_key in 0.. 2u32.pow(16) {
        let mut rng = MersenneTwister19937::default();
        rng.seed(potential_key as u32);
        let mut bytes: Vec<u8> = std::iter::from_fn(|| Some(rng.extract() as u8)).take(ciphertext.len()).collect();
        crate::xor_in_place(&mut bytes, &ciphertext);
        if &bytes[bytes.len() - known_text.len()..] == known_text {
            assert_eq!(potential_key as u16, key);
            return
        }
    }
    panic!("Failed to find key");
}

#[test]
fn challenge_23() {
    let mut original_rng = MersenneTwister19937::default();
    let output: [u32; N as usize] = std::array::from_fn(|_| original_rng.extract());
    let untempered = output.map(invert_temper);
    let mut new_rng = MersenneTwister19937::default();
    new_rng.mt = untempered;

    assert_eq!(new_rng.index, original_rng.index);
    assert_eq!(new_rng.mt[..5], original_rng.mt[..5]);

    for i in 0..888 {
        assert_eq!(original_rng.extract(), new_rng.extract());
    }
}

#[ignore] // Not one to one, panics.
#[test]
fn is_it_1_to_1() {
    let mut out = vec![None; 2usize.pow(32)];
    let mut rng = MersenneTwister19937::default();
    for i in 0.. 2usize.pow(32) {
        rng.seed(i as u32);
        let y = rng.extract();
        if let Some(j) = out[y as usize] {
            panic!("{j} == {i}");
        } else {
            out[y as usize] = Some(i as u32)
        }   
    }
}