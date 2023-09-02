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
        y ^= (y >> U) & D; // U=11 D=all_ones

        // The above line converts y to y'
        // Given y' we want to recover y.

        // Adversary runs this code:
        // y:
        // aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh
        // y >> 11  -- original mask
        // 0000-0000-000a-aaab-bbbc-cccd-ddde-eeef
        // y' := y ^ (y>>11)
        // aaaa-bbbb-ccc?-????-????-????-????-????

        // Then we are given y'
        // And we run this code:

        // y' >> 11
        // aaaa-bbbb-ccc?-????-????-????-????-????
        //              ^^^^^^^^^^^^^ kill these

        // y''    :=  y'  ^ ( (y'>>11) & !ten_ones )    -- ten_ones := ((1 << 10) - 1)
        // aaaa-bbbb-cccc-dddd-eeee-ff??-????-????

        // y=y''' :=  y'' ^ ( (y''>>11) & eleven_ones )  -- Kevan's initial idea
        // y=y''' :=  y'  ^ (  y''>>11 )  -- Lily's idea
        // aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh

        // (in the given y' the first 11 bits are correct)

        //y ^= y >> 11;
        //y ^= (y ^ (y >> 11)) >> 11;  // THIS

        // first 22 bits are correct
        // y_temp = y ^ (y >> U);

        // // shift off all 10 of the garbage bits;
        // // and xor, so that all bits are now correct
        // let new_y = y ^ (y_temp >> U);

        y ^= (y << S) & B; // S=7  B=9D2C_5680
        // let mut mask: u32 = y;
        // for _ in 0..W/S {
        //     mask = y ^ (mask << S) & B;
        // }


        // PAUSE this for now ....

        // aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh  y

        // bccc-cddd-deee-efff-fggg-ghhh-h000-0000  y << 7
        // 1001-1101-0010-1100-0101-0110-1000-0000  B
        // b00c-cd0d-00e0-ef00-0g0g-0hh0-h000-0000  (y << 7) & B  -- "mask"

        // aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh  y
        // b00c-cd0d-00e0-ef00-0g0g-0hh0-h000-0000  mask
        // =======================================
        // ?aa?-??b?-cc?c-??dd-e?e?-f??f-?ggg-hhhh  y' := y ^ mask
        //                               ^
        //                             g1 xor h4

        //                   e2 xor g1
        //                      v
        // ?cc?-c??d-de?e-?f??-f?gg-ghhh-h000-0000  y' << 7
        // 1001-1101-0010-1100-0101-0110-1000-0000  B



        // ?00?-c?0d-00?0-?f00-0?0g-0hh0-h000-0000  mask' := (y' << 7) & B


        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;
        y
    }
}

fn invert_temper(mut y: u32) -> u32 {
    // aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh-iiii
    // 0000-0000-0000-0000-00aa-aabb-bbcc-ccdd-ddee   ("mask" -- y>>L)

    y = invert_xor_shift_right_and_mask(y, L, 0);
    y = invert_xor_shift_left_and_mask(y, T, C);
    y = invert_xor_shift_left_and_mask(y, S, B);
    y = invert_xor_shift_right_and_mask(y, U, D);
    y

    // y ^= y >> L;

    // // v                 <<<<                   v
    // // aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh  y

    // // deee-efff-fggg-ghhh-h000-0000-0000-0000  ((y: u32)<<T) : u32
    // // &
    // // 1110-1111-1100-0110-0000-0000-0000-0000  C
    // // ---------------------------------------
    // // dee0-efff-fg00-0hh0-0000-0000-0000-0000  (y<<T) & C

    // // 0000-0000-0000-000d-eeee-ffff-gggg-hhhh  (y' := y xor above)
    // // ^^^^ the transformed y (aka y').
    // // y_{i+1} = y_{i} ^ ((y_i << T) & C)     
    // // y_{i+1} ^ ((y_i << T) & C) = y_{i}
    // // (y_i << T) & ABC6_0000 = (y_{i+1} << T) & ABC6_0000 <- WTS... 

    // // to undo: want to xor y' with the SAME mask: (!)
    // // dee0-efff-fg00-0hh0-0000-0000-0000-0000  (y<<T) & C   ==== (y' << T) & C

    // y ^= (y << T) & C;

    // y ^= (y ^ (y >> U)) >> U; // apply the op floor(32/U) times   
    // y 
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

    
}