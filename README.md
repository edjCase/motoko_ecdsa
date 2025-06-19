# ECDSA Library for Motoko

A comprehensive ECDSA implementation for Motoko, supporting secp256k1 and prime256v1 curves with SHA-256 hashing.

## Original Project Credits

- **Author**: MITSUNARI Shigeo (herumi@nifty.com)
- **Original Repository**: https://github.com/herumi/ecdsa-motoko

## License

Apache 2.0

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
          format = {
            isUpper = false;
            prefix = #single("0x");
          };
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
let publicKeyResult = ECDSA.publicKeyFromText(publicKeyHex, #hex({
  byteEncoding = #raw({ curve = ECDSA.secp256k1Curve() });
  format = {
    prefix = #none;
  };
}));

// Import a signature and verify it
switch (publicKeyResult) {
  case (#ok(publicKey)) {
    let signatureBase64 = "..."; // Base64-encoded signature
    let signatureResult = ECDSA.signatureFromText(
      signatureBase64,
      ECDSA.secp256k1Curve(),
      #base64({ byteEncoding = #der })
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

### Main Module Types and Functions

From the lib.mo file, these are the main types and functions available when you import ECDSA:

```motoko

// New Private Key generation
public func generatePrivateKey(entropy : Iter.Iter<Nat8>, curve : Curve) : Result.Result<PrivateKey, Text>;

// Import from bytes
public func publicKeyFromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text>;
public func privateKeyFromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PrivateKey, Text>;
public func signatureFromBytes(bytes : Iter.Iter<Nat8>, curve : Curve, encoding : InputByteEncoding) : Result.Result<Signature, Text>;

// Import from text
public func publicKeyFromText(text : Text, format : InputTextFormat) : Result.Result<PublicKey, Text>;
public func privateKeyFromText(text : Text, format : InputTextFormat) : Result.Result<PrivateKey, Text>;
public func signatureFromText(text : Text, curve : Curve, format : InputTextFormat) : Result.Result<Signature, Text>;

// Manual Creation Functions
public func PublicKey(x : Nat, y : Nat, curve : Curve) : PublicKey;
public func PrivateKey(d : Nat, curve : Curve) : PrivateKey;
public func Signature(r : Nat, s : Nat, curve : Curve) : Signature;


// Curve Functions
public type CurveKind = { #secp256k1; #prime256v1 };

public func Curve(kind : CurveKind) : Curve;
public func secp256k1Curve() : Curve;
public func prime256v1Curve() : Curve;
```

### PublicKey Methods

```motoko
// Methods on PublicKey objects
public func equal(other : PublicKey) : Bool;
public func verify(msg : Iter.Iter<Nat8>, sig : Signature) : Bool;
public func verifyHashed(hashedMsg : Iter.Iter<Nat8>, sig : Signature) : Bool;
public func toText(format : OutputTextFormat) : Text;
public func toBytes(encoding : OutputByteEncoding) : [Nat8];
```

### PrivateKey Methods

```motoko
// Methods on PrivateKey objects
public func getPublicKey() : PublicKey;
public func sign(msg : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : Result.Result<Signature, Text>;
public func signHashed(hashedMsg : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : Result.Result<Signature, Text>;
public func toText(format : OutputTextFormat) : Text;
public func toBytes(encoding : OutputByteEncoding) : [Nat8];
```

### Signature Methods

```motoko
// Methods on Signature objects
public func equal(other : Signature) : Bool;
public func toText(format : OutputTextFormat) : Text;
public func toBytes(encoding : OutputByteEncoding) : [Nat8];
```

### Byte and Text Format Types

```motoko
// Input text formats for keys
public type InputTextFormat = {
  #base64 : { byteEncoding : InputByteEncoding };
  #hex : { byteEncoding : InputByteEncoding; format : BaseX.HexInputFormat };
  #pem;  // For DER-encoded keys in PEM format
};

// Output text formats for public keys
public type PublicKeyOutputTextFormat = {
  #base64 : { byteEncoding : PublicKeyOutputByteEncoding; format : BaseX.Base64OutputFormat };
  #hex : { byteEncoding : PublicKeyOutputByteEncoding; format : BaseX.HexOutputFormat };
  #pem;  // For DER-encoded keys in PEM format
  #jwk;  // JSON Web Key format (PublicKey only)
};

// Output text formats for private keys
public type PrivateKeyOutputTextFormat = {
  #base64 : { byteEncoding : PrivateKeyOutputByteEncoding; format : BaseX.Base64OutputFormat };
  #hex : { byteEncoding : PrivateKeyOutputByteEncoding; format : BaseX.HexOutputFormat };
  #pem;  // For DER-encoded keys in PEM format
};

// Output text formats for signatures
public type SignatureOutputTextFormat = {
  #base64 : { byteEncoding : SignatureOutputByteEncoding; format : BaseX.Base64OutputFormat };
  #hex : { byteEncoding : SignatureOutputByteEncoding; format : BaseX.HexOutputFormat };
};
```

## Original Project

If you'd like to support the original project:

- Original repository: https://github.com/herumi/ecdsa-motoko
- [GitHub Sponsor](https://github.com/sponsors/herumi)
