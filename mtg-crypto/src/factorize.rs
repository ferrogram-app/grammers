// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let (na, nb) = (b, a % b);
        a = na;
        b = nb;
    }
    a
}

/// Factorize the given number into its two prime factors.
///
/// The algorithm here is a faster variant of [Pollard's rho algorithm],
/// published by [Richard Brent], based on
/// <https://comeoncodeon.wordpress.com/2010/09/18/pollard-rho-brent-integer-factorization/>.
///
/// Pollard's rho algorithm: <https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm>
/// Richard Brent: <https://maths-people.anu.edu.au/~brent/pd/rpb051i.pdf>
#[allow(clippy::many_single_char_names)]
pub fn factorize(pq: u64) -> Option<(u64, u64)> {
    const ATTEMPTS: [u64; 5] = [43, 47, 53, 59, 61];
    for attempt in ATTEMPTS {
        // > Note that this algorithm may not find the factors and will return failure for composite n.
        // > In that case, use a different f(x) and try again [...] We choose f(x) = x*x + c
        // Thus by choosing a different `c` we're changing `f(x)` and can try again.
        // Prime factors are used for the attempts in the hopes they'll be more likely to work.
        let c = attempt * (pq / 103);
        let (p, q) = factorize_with_param(pq, c);
        // `pq` comes from the server: a prime, 0 or 1 must fail instead of looping or lying.
        if p > 1 && q > 1 && p.checked_mul(q) == Some(pq) {
            return Some((p, q));
        }
    }
    None
}

/// Upper bound on Pollard's rho rounds. Two 32-bit primes need about 2^17 steps, so this is
/// generous, yet a hostile prime `pq` costs milliseconds instead of hanging the client.
const MAX_ROUNDS: u128 = 1 << 19;

fn factorize_with_param(pq: u64, c: u64) -> (u64, u64) {
    if pq.is_multiple_of(2) {
        return (2, pq / 2);
    }

    let pq = pq as u128;
    fn abs_sub(a: u128, b: u128) -> u128 {
        a.max(b) - a.min(b)
    }

    // Random values in the range of 1..pq, chosen by fair dice roll.
    // c is an input free to change in case the chosen value fails.
    let mut y = 3 * (pq / 7);
    let c = c as u128;
    // 0 for pq < 13 would never advance `k`
    let m = (7 * (pq / 13)).max(1);
    let mut g = 1u128;
    let mut r = 1u128;
    let mut q = 1u128;
    let mut x = 0u128;
    let mut ys = 0u128;

    while g == 1 {
        if r > MAX_ROUNDS {
            return (1, pq as u64);
        }
        x = y;
        for _ in 0..r {
            y = (y * y % pq + c) % pq;
        }

        let mut k = 0;
        while k < r && g == 1 {
            ys = y;
            for _ in 0..m.min(r - k) {
                y = (y * y % pq + c) % pq;
                q = (q * abs_sub(x, y)) % pq;
            }

            g = gcd(q, pq);
            k += m;
        }

        r *= 2;
    }

    if g == pq {
        for _ in 0..MAX_ROUNDS {
            ys = (ys * ys % pq + c) % pq;
            g = gcd(abs_sub(x, ys), pq);
            if g > 1 {
                break;
            }
        }
    }

    let (p, q) = (g as u64, (pq / g) as u64);
    (p.min(q), p.max(q))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factorization_1() {
        let pq = factorize(1470626929934143021);
        assert_eq!(pq, Some((1206429347, 1218991343)));
    }

    #[test]
    fn test_factorization_2() {
        let pq = factorize(2363612107535801713);
        assert_eq!(pq, Some((1518968219, 1556064227)));
    }

    #[test]
    fn test_factorization_3() {
        let pq = factorize(2804275833720261793);
        assert_eq!(pq, Some((1555252417, 1803100129)));
    }

    #[test]
    fn a_prime_cannot_be_factorized() {
        // 2^61 - 1 is prime: the server sent us something that is not p * q
        assert_eq!(factorize(2305843009213693951), None);
        for pq in [0, 1, 2, 3, 4] {
            // 4 = 2 * 2 is a valid product; 0..=3 are not
            assert_eq!(factorize(pq).is_some(), pq == 4, "{pq}");
        }
    }
}
