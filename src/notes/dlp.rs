//! # Discrete Logarithm Problem
//!
//! In a cyclic group `G` with generator `g` where the Computational Diffie-Hellman problem holds, given an element `h` in this group, the Discrete Logarithm Problems (DLP) consist in finding the element `x` such that:
//!
//! ``` text
//! h = g~g~g~...~g`
//!     |_________|
//!       x times
//! ```
//!
//! where `~` i the group law. Using the additive notation (as it is used in elliptic curves), this can be written:
//!
//! ``` text
//! h = x.g
//! ```
//!
//! ## Diffie-Hellman algorithm
//!
//! Let be `M` such that `x < M` and that it exists `(m,n)` such that `M = m.n`. Then `x` can be rewritten `x = k.m + i`, with `0 <= k < n` and `0 <= i < m`.
//! ``` text
//! x.g = h
//! k.(m.g) + i.g = h
//! i.g = h + k.(-m.g)
//! ```
//!
//! The Diffie-Hellman algorithm consists in:
//!
//! ``` text
//! for i in range(0,m):
//!     v <- (i.g)
//!     store (i,v)
//!
//! a <- (-m.g)
//!
//! for k in range(0,n):
//!     w <- (h + k.a)
//!     if w matches a v of a stored (i,v) pair:
//!         return (k,i)
//! ```
//!
//! When using a hashed map to store the `(i,v)` pairs, the lookup is made in `O(1)`. Therefore the following complexities can be achieved:
//! - time complexity: O(n+m)
//! - space complexity: O(m)
//!
//!
//! ## Benchmark
//!
//! The DLP was solved for a 114-bit long order in 6 months with 2000 CPU cores [^1]. Since our algorithm aims at being used for instantaneous encryption/decryption, a lower upper bound should be chosen. The following table gives a survey of the time and space efficiency of our algorithm given the size of the upper bound.
//!
//! [^1] Solving 114-bit ECDLP for a Barreto-Naehrig curve: <https://hal.archives-ouvertes.fr/hal-01633653/file/article.pdf>
