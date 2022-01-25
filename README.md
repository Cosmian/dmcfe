# DMCFE &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

## Introduction

Functional Encryption (FE) is a new encryption paradigm which extends the "all-or-nothing" requirement of public encryption in a much more flexible way. It allows different parties to compute the result of a given function on encrypted data. Given a function f, a decryption key dk<sub>f</sub> can be computed such that given a cyphertext c of the underlying plaintext x, any user can use dk<sub>f</sub> to compute f(x) without gaining any knowledge about x.

This crate gives an implementation of three functional encryption algorithms:

- the Inner Product Functional Encryption (IPFE) [[1]](#Bibliography);
- the Multi-Client IPFE (MCFE) [[2]](#Bibliography);
- the Distributed MCFE (DMCFE) [[3]](#Bibliography).

These implementations are based on the [BLS12-381](#BLS12-381) elliptic curve.

**Note**: these implementations do not try to solve the final Discrete Logarithm Problem (DLP) for generality purpose. The user needs to solve it in order to get the inner product <x,y>. This is possible using the Pollard's kangaroo method. The complexity of such a method is in _O(L<sup>1/2</sup>)_ where L is an upper bound on the DLP solution, which implies that use cases shall try to keep this inner product as small as possible in order to speedup the decryption process.

## Quick start

See the examples in `tests`, which extensive documentation should allow one to understand the library usage.

## IPFE

The IPFE algorithm is an FE algorithm which allows to compute the inner product of two encrypted vectors. This implementation is secure under the DDH assumption and uses the cyclic group **G<sub>1</sub>** of the BLS12-381 elliptic curve.

Steps:

1. generate the couple (msk, mpk) using the `setup` function;
2. generate the decryption key sk<sub>y</sub> for a given vector y with msk and the `key_gen` function;
3. the client encrypts its vector x in the cyphertext c using the mpk and the `encrypt` function;
4. compute g<sup><x,y></sup> using c, sk<sub>y</sub> and the `decrypt` function.

## MCFE

The MCFE algorithm is an evolution of the IPFE. It allows n different clients to encrypt data, share it to a trusted party which will compute the inner product <X,Y>, with X = [X1,...,X<sub>n</sub>] where X<sub>i</sub> is the contribution (the encrypted data) of the client i. To avoid reuse of previously encrypted data, a label is used. The decryption is possible only if all cyphertexts has been encrypted for the same label.

Steps:

1. generate the encryption key ek<sub>i</sub> for each client using the `setup` function;
2. generate the decryption key dk<sub>y</sub> for a given vector y with msk and the `dkey_gen` function;
3. clients encrypt their vector x<sub>i</sub> in the cyphertext c<sub>i</sub> for a given label using their encryption key ek<sub>i</sub> and the `encrypt` function;
4. compute g<sup><x,y></sup> using c, dk<sub>y</sub> and the `decrypt` function.

**Note**: the use of secret keys to encrypt data prevents clients from encrypting data instead of other clients to gain knowledge about the data of another client.

## DSum

The DSum is an algorithm described in [[2]](#Bibliography) (see _7.2 Distributed Sum_) which aims to encrypt data in such a way that the sum of these encrypted data is equal to the sum of the plaintext data, and so without the need of a trusted third-party.

## DMCFE

The DMCFE algorithm is an evolution of the MCFE. It removes the need for a trusted third-party while limiting the need for communication among clients to the setup phase.

In this scheme, each client is able to generate its own secret key used to encrypt data, and to generate a partial decryption key for a given vector y. The partial decryption keys of all the clients can then be combined to build the final decryption key. In this step, the use of the DSum gives the guarantee that if one partial decryption key is missing, no meaningful data can be decrypted. It also guarantees the unforgability of the partial decryption keys since a given partial decryption key is built using the secret key of the corresponding client.

The cyphertext space is the group **G<sub>1</sub>** of the BLS12-381 curve while the decryption key space is the group **G<sub>2</sub>** of the same curve. The pairing-friendly characteristic of this curve makes the decryption process possible. The final DLP to solve is in the **G<sub>T</sub>** group.

Client side:
- Setup phase:
	1. each client generates its DSum (dsk<sub>i</sub>, dpk<sub>i</sub>) couple using the `dsum::setup` function;
	2. the DSum public key dpk<sub>i</sub> of each client is broadcasted;
	3. each client generates its secret key sk<sub>i</sub> using its DSum secret key dsk<sub>i</sub>, the list of dsum public keys all clients the `setup` function.

- Partial decryption phase:
	1. upon reception of a vector y, a client generates a partial decryption key pdk<sub>i</sub>;
	2. each client sends its partial decryption key back to the user.

- Encryption phase:
	1. each client encrypts its data using an agreed-upon label, its private key sk<sub>i</sub> and the `encrypt` function;
	2. each client sends its generated cyphertext to the user.


User side:
- Decryption key generation:
	1. generate the vector y and send it to every client;
	2. gather the partial decryption keys sent back by the clients;
	3. compute the final decryption key using the `key_comb` function.

- Decryption phase:
	1. wait for all client contributions;
	2. use the decryption key with the `decrypt` function to get g<sub>T</sub><sup><x,y></sup>.


All the aforementioned steps are relatively independent. The setup phase implies a lot communication. It should be executed first but only once. Both the partial decryption and the encryption phase are asynchronous jobs that can (and should) run concurrently.

**Note**: as for the MCFE, the label is used here to prevent the reuse of previously encrypted data. To avoid adding communication cost to the encryption step, timestamps can be used. For example, if the clients have to encrypt a data every hour, a combination of the date and hour can be used as label.


## BLS12-381

This KP-ABE implementation is based on the crate [bls12_381](https://crates.io/crates/cosmian_bls12_381), a pairing-friendly elliptic curve construction from the [BLS family](https://eprint.iacr.org/2002/088), with embedding degree 12. It is built over a 381-bit prime field `GF(p)` with...

* `z = -0xd201000000010000`
* `p = (z - 1)<sup>2</sup>(z<sup>4</sup> - z<sup>2</sup> + 1) / 3 + z = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`
* `q = z<sup>4</sup> - z<sup>2</sup> + 1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`

... yielding two _source groups_ **G<sub>1</sub>** and **G<sub>2</sub>**, each of 255-bit prime order `q`, such that an efficiently computable non-degenerate bilinear pairing function `e` exists into a third _target group_ **G<sub>T</sub>**. Specifically, **G<sub>1</sub>** is the `q`-order subgroup of E(F<sub>p</sub>) : y<sup>2</sup> = x<sup>3</sup> + 4 and **G<sub>2</sub>** is the `q`-order subgroup of E'(F<sub>p<sup>2</sup></sub>) : y<sup>2</sup> = x<sup>3</sup> + 4(u + 1) where the extension field F<sub>p<sup>2</sup></sub> is defined as F<sub>p</sub>(u) / (u<sup>2</sup> + 1).

BLS12-381 is chosen so that `z` has small Hamming weight (to improve pairing performance) and also so that `GF(q)` has a large 2<sup>32</sup> primitive root of unity for performing radix-2 fast Fourier transforms for efficient multipoint evaluation and interpolation. It is also chosen so that it exists in a particularly efficient and rigid subfamily of BLS12-381 curves.

## Bibliography

[1] Michel Abdalla, Florian Bourse, Angelo De Caro, and David Pointcheval, Simple Functional Encryption Schemes for Inner Products, [https://eprint.iacr.org/2015/017.pdf](https://eprint.iacr.org/2015/017.pdf)

[2] Jérémy Chotard, Edouard Dufour-Sans, Romain Gay, Duong Hieu Phan, and David Pointcheval, Multi-Client Functonal Encryption with Repetition for Inner Product, [https://eprint.iacr.org/2018/1021.pdf](https://eprint.iacr.org/2018/1021.pdf)

[3] Jérémy Chotard, Edouard Dufour-Sans, Romain Gay, Duong Hieu Phan, and David Pointcheval, Decentralized Multi-Client Functional Encryption for Inner Product, [https://eprint.iacr.org/2017/989.pdf](https://eprint.iacr.org/2017/989.pdf)
