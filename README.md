# ECDSA for [Your Package Manager]

A fork of [herumi/ecdsa-motoko](https://github.com/herumi/ecdsa-motoko), providing ECDSA-SHA-256 implementation.

## Original Project Credits

- **Author**: MITSUNARI Shigeo (herumi@nifty.com)
- **Original Repository**: https://github.com/herumi/ecdsa-motoko

## License

Apache 2.0 with LLVM Exception

This project is a fork of the original ECDSA implementation by MITSUNARI Shigeo, maintaining the same license.

## Installation

```bash
mops install ecdsa
```

To setup MOPS package manage, follow the instructions from the
[MOPS Site](https://j4mwm-bqaaa-aaaam-qajbq-cai.ic0.app/)

## API Reference

### Key Generation and Management

```motoko
// Generate a secret key from random bytes
public func getSecretKey(rand : Iter.Iter<Nat8>) : ?SecretKey

// Derive public key from secret key
public func getPublicKey(sec : SecretKey) : PublicKey
```

### Signing and Verification

```motoko
// Sign a message using SHA-256
public func sign(sec : SecretKey, msg : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : ?Signature

// Verify a signature
public func verify(pub : PublicKey, msg : Iter.Iter<Nat8>, sig : Signature) : Bool

// Sign pre-hashed message
public func signHashed(sec : SecretKey, hashed : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : ?Signature

// Verify pre-hashed message
public func verifyHashed(pub : PublicKey, hashed : Iter.Iter<Nat8>, sig : Signature) : Bool
```

### Key Serialization

```motoko
// Serialize public key (uncompressed format)
public func serializePublicKeyUncompressed(key : Curve.Affine) : Blob

// Serialize public key (compressed format)
public func serializePublicKeyCompressed(key : Curve.Affine) : Blob

// Deserialize public key (uncompressed format)
public func deserializePublicKeyUncompressed(b : Blob) : ?PublicKey

// Deserialize public key (compressed format)
public func deserializePublicKeyCompressed(b : Blob) : ?PublicKey
```

### Signature Serialization

```motoko
// Serialize signature to DER format
public func serializeSignatureDer(sig : Signature) : Blob

// Deserialize signature from DER format
public func deserializeSignatureDer(b : Blob) : ?Signature
```

## Changes from Original

Adapted it to use for the MOPS package manager

## Original Project

If you'd like to support the original project:

- Original repository: https://github.com/herumi/ecdsa-motoko
- [GitHub Sponsor](https://github.com/sponsors/herumi)
