# DMCFE
Implementation of the DMCFE algorithm

Clients are supposed to be honest-but-curious. This means that they will play by the rules when sharing data with others (e.g. no client will try to retain information). This algorithm do no protect the user against malicious clients!

## TODO

- optimize IPFE: how?
- optimize BSGS:
	+ parallelize: how to do?
	OK: try to change the recurring computation of `g^n` into a non-recurring suite.
	OK: implement better exponentiation
OK implement functional tests
OK implement MCFE
OK implement DMCFE
- implement a better generic hash-to-curve function
OK see if #[bench] can be used for benchmarks
- full documentation review
- review type sizes
- review Cargo.toml: see if it can be improved
OK transform the crate into a library one
OK see how to use the DST for the the hash-to-curve function
OK use Dsum from the cosmian repo
OK setup Github CI
- complete bibliography
- complete notes
- write a real nice README file :)
OK see how to return `Result<T>` in closures for `map` and `for_each` methods => collect() can transpose `Result`, with `T`
OK find a way to attribute a number to each client without central instance => use lock (mutex) on shared value => no need, use public key order
- implement `hash_to_scalar` (maybe hash256 + `from_raw`)
OK implement `h_i_j`
- review variable notation for making it more consistent (e.g. capital letters for group members and small letters for scalars, add `mat_` or `vec_` prefix to give indications?)
- add a timeout system when getting data from the bus (in case a client crashes or give the wrong number of contributions, one does not want to wait indefinitly):
	+ where to put it ?
		- directly into the `ibus::get` function
		- create a new `ibus::wait(n)` function
		- the user of the ibus should manage it:
OK should the DMCFE manage the thread message passing part? Or should the DSum to it? => NO, communication should be on the user side
- add a flag to deactivate at setup the use of the IPFE in the MCFE with repetition

## Notes

- the dimension 2 in the MCFE is used to bring more security (see proof).
- the IPFE in the MCFE with repetition is useless if `m = 1` => add a flag to deactivate it at setup


## Bibliography

[1] Shi Bai, Richard P.Brent, On the Efficiency of Pollard's Rho Method for Discrete Logarithms

[2] Teske (1998), Speeding up Pollard's rho method for computing discrete logarithms
