# DMCFE
Implementation of the DMCFE algorithm

## TODO

- optimize IPFE: how?
- optimize BSGS:
	+ parallelize: how to do?
	OK: try to change the recurring computation of `g^n` into a non-recurring suite.
	OK: implement better exponentiation
OK: implement functional tests
OK: implement MCFE
- implement DMCFE
- implement a better generic hash-to-curve function
- see if #[bench] can be used for benchmarks
- full documentation review
- review type sizes
- review Cargo.toml: see if it can be improved
OK: transform the crate into a library one
- see how to use the DST for the the hash-to-curve function
- use Dsum from the cosmian repo
- setup Github CI
- complete bibliography
- complete notes
- write a real and nice README file :)
- see how to return `Result<T>` in closures for `map` and `for_each` methods

## Bibliography

[1] Shi Bai, Richard P.Brent, On the Efficiency of Pollard's Rho Method for Discrete Logarithms
[2] Teske (1998), Speeding up Pollard's rho method for computing discrete logarithms
