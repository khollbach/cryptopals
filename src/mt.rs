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
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);
    
        self.index += 1;
        return y
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
