# ECDSA Library for Motoko

A comprehensive ECDSA implementation for Motoko, supporting secp256k1 and prime256v1 curves with SHA-256 hashing.

## Original Project Credits

- **Author**: MITSUNARI Shigeo (herumi@nifty.com)
- **Original Repository**: https://github.com/herumi/ecdsa-motoko

## License

Apache 2.0 with LLVM Exception

This project is a fork of the original ECDSA implementation by MITSUNARI Shigeo, maintaining the same license.

## Installation

```bash
mops add ecdsa
```

To set up the MOPS package manager, follow the instructions from the
[MOPS Site](https://j4mwm-bqaaa-aaaam-qajbq-cai.ic0.app/)

## Quick Start

### Generate Key Pair and Sign a Message

```motoko
import ECDSA "mo:ecdsa";
import Iter "mo:base/Iter";

// Generate entropy (in a real application, use a secure random source)
let entropy : [Nat8] = [/* 32 bytes of secure random data */];
let randomK : [Nat8] = [/* 32 bytes of secure random data */];
let message : [Nat8] = [/* message bytes */];

// Create a key pair using secp256k1
let curve = ECDSA.secp256k1Curve();
let privateKeyResult = ECDSA.generatePrivateKey(entropy.vals(), curve);

switch (privateKeyResult) {
  case (#ok(privateKey)) {
    let publicKey = privateKey.getPublicKey();

    // Sign the message
    let signatureResult = privateKey.sign(message.vals(), randomK.vals());

    switch (signatureResult) {
      case (#ok(signature)) {
        // Verify the signature
        let isValid = publicKey.verify(message.vals(), signature);

        // Export keys in various formats
        let publicKeyHex = publicKey.toText(#hex({
          byteEncoding = #compressed;
          format = #lowercase;
        }));

        let privateKeyPem = privateKey.toText(#pem);
      };
      case (#err(e)) { /* Handle error */ };
    };
  };
  case (#err(e)) { /* Handle error */ };
};
```

### Import Keys and Verify a Signature

```motoko
import ECDSA "mo:ecdsa";
import BaseX "mo:base-x-encoder";

// Import a public key from hex format
let publicKeyHex = "02..."; // Compressed public key in hex
let publicKeyResult = ECDSA.fromText(publicKeyHex, #hex({
  byteEncoding = #raw({ curve = ECDSA.secp256k1Curve() });
  format = {
    prefix = #none;
  };
}));

// Import a signature and verify it
switch (publicKeyResult) {
  case (#ok(publicKey)) {
    let signatureBase64 = "..."; // Base64-encoded signature
    let signatureResult = ECDSA.signatureFromBytes(
      BaseX.fromBase64(signatureBase64).vals(),
      ECDSA.secp256k1Curve(),
      #der
    );

    switch (signatureResult) {
      case (#ok(signature)) {
        let message = [/* message bytes */];
        let isValid = publicKey.verify(message.vals(), signature);
      };
      case (#err(e)) { /* Handle error */ };
    };
  };
  case (#err(e)) { /* Handle error */ };
};
```

## API Reference

### Curve Types and Constants

```motoko
// Curve types
public type CurveKind = { #secp256k1; #prime256v1 };
public type Curve = CurveModule.Curve;

// Create curves
public func Curve(kind : CurveKind) : Curve
public func secp256k1Curve() : Curve
public func prime256v1Curve() : Curve
```

### Key Types

```motoko
// Public and Private Key types
public type PublicKey = PublicKeyModule.PublicKey;
public type PrivateKey = PrivateKeyModule.PrivateKey;
public type Signature = SignatureModule.Signature;

// Byte encoding types for input and output
public type InputByteEncoding = { #raw : { curve : Curve }; #der };
public type OutputByteEncoding = { #der; #raw } or { #der; #compressed; #uncompressed };
```

### Key Generation and Conversion

```motoko
// Create a Private Key from a secret scalar d
public func PrivateKey(d : Nat, curve : Curve) : PrivateKey

// Generate a Private Key from random entropy
public func generatePrivateKey(entropy : Iter.Iter<Nat8>, curve : Curve) : Result.Result<PrivateKey, Text>

// Create a Public Key from coordinates
public func PublicKey(x : Nat, y : Nat, curve : Curve) : PublicKey

// Derive Public Key from Private Key
public func getPublicKey() : PublicKey  // Method on PrivateKey
```

### Signing and Verification

```motoko
// Sign methods (on PrivateKey)
public func sign(msg : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : Result.Result<Signature, Text>
public func signHashed(hashedMsg : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : Result.Result<Signature, Text>

// Verify methods (on PublicKey)
public func verify(msg : Iter.Iter<Nat8>, sig : Signature) : Bool
public func verifyHashed(hashedMsg : Iter.Iter<Nat8>, sig : Signature) : Bool
```

### Serialization and Deserialization

```motoko
// Key and Signature Constructors
public func Signature(r : Nat, s : Nat, curve : Curve) : Signature

// Import from bytes
public func publicKeyFromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text>
public func privateKeyFromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PrivateKey, Text>
public func signatureFromBytes(bytes : Iter.Iter<Nat8>, curve : Curve, encoding : InputByteEncoding) : Result.Result<Signature, Text>

// Import from text
public func fromText(value : Text, format : InputTextFormat) : Result.Result<PublicKey or PrivateKey, Text>

// Export to text formats
public func toText(format : OutputTextFormat) : Text  // Method on keys and signatures

// Export to bytes
public func toBytes(encoding : OutputByteEncoding) : [Nat8]  // Method on keys and signatures
```

### Text Format Options

```motoko
// Input text formats
public type InputTextFormat = {
  #base64 : { byteEncoding : InputByteEncoding };
  #hex : { byteEncoding : InputByteEncoding; format : BaseX.HexInputFormat };
  #pem;  // For DER-encoded keys in PEM format
};

// Output text formats
public type OutputTextFormat = {
  #base64 : { byteEncoding : OutputByteEncoding; isUriSafe : Bool };
  #hex : { byteEncoding : OutputByteEncoding; format : BaseX.HexOutputFormat };
  #pem;  // For DER-encoded keys in PEM format
  #jwk;  // JSON Web Key format (PublicKey only)
};
```

## Changes from Original

- Completely redesigned API with object-oriented approach
- Support for multiple key and signature formats (DER, raw, PEM, JWK)
- Better error handling with Result type
- More comprehensive serialization options
- Support for compressed and uncompressed public keys

## Original Project

If you'd like to support the original project:

- Original repository: https://github.com/herumi/ecdsa-motoko
- [GitHub Sponsor](https://github.com/sponsors/herumi)
