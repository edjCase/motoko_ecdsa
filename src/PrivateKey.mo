/// ECDSA private keys: storage, ASN.1 / PEM encoding, and signing.
///
/// ```motoko name=import
/// import PrivateKey "mo:ecdsa/PrivateKey";
/// ```

import Iter "mo:core@2/Iter";
import Nat8 "mo:core@2/Nat8";
import Result "mo:core@2/Result";
import Runtime "mo:core@2/Runtime";
import Text "mo:core@2/Text";

import ASN1 "mo:asn1@3";
import Sha256 "mo:sha2@0/Sha256";

import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";
import KeyCommon "KeyCommon";
import Util "Util";

module {

  /// Byte encodings that can be wrapped inside PEM.
  /// `#sec1` is the SEC1 EC private key DER (RFC 5915);
  /// `#pkcs8` is the PKCS#8 `PrivateKeyInfo` DER (RFC 5208).
  public type PEMInputByteEncoding = {
    #sec1 : {
      curve : Curve.Curve;
    }; // SEC1 format
    #pkcs8; // PKCS#8 format
  };

  /// All supported byte encodings for `fromBytes`. Adds `#raw` (32-byte
  /// big-endian scalar) to the PEM-wrappable encodings.
  public type InputByteEncoding = PEMInputByteEncoding or KeyCommon.CommonInputByteEncoding;

  /// Byte encodings that can be wrapped inside PEM on output.
  /// Same shape as `PEMInputByteEncoding` but without the `curve` payload
  /// (the curve is already known from the `PrivateKey` itself).
  public type PEMOutputByteEncoding = {
    #sec1; // SEC1 format
    #pkcs8; // PKCS#8 format
  };

  /// All supported byte encodings for `toBytes`. Adds `#raw` (32-byte
  /// big-endian scalar) to the PEM-wrappable encodings.
  public type OutputByteEncoding = PEMOutputByteEncoding or {
    #raw;
  };

  /// All supported text formats for `toText`: hex, base64 (each carrying
  /// an inner `OutputByteEncoding`), or PEM-armored DER.
  public type OutputTextFormat = KeyCommon.CommonOutputTextFormat<OutputByteEncoding> or {
    #pem : {
      byteEncoding : PEMOutputByteEncoding;
    };
  };

  /// All supported text formats for `fromText`: hex, base64 (each carrying
  /// an inner `InputByteEncoding`), or PEM-armored DER.
  public type InputTextFormat = KeyCommon.CommonInputTextFormat<InputByteEncoding> or {
    #pem : {
      byteEncoding : PEMInputByteEncoding;
    };
  };

  /// An ECDSA private key consisting of the scalar `d` and the curve it
  /// was generated for. Construct via `PrivateKey(d, curve)` or one of the
  /// `from*` parsers.
  ///
  /// `d` must be in the range `1 .. r-1` for signing to succeed, where
  /// `r` is the curve order. The constructor itself does not enforce
  /// this.
  public class PrivateKey(
    d_ : Nat,
    curve_ : Curve.Curve,
  ) {
    /// The scalar value of this key, `1 <= d < r`.
    public let d = d_;
    /// The curve this key was generated for.
    public let curve = curve_;

    /// Derives the corresponding `PublicKey` by computing `d * G`, where
    /// `G` is the curve generator.
    ///
    /// Traps if the multiplication produces the point at infinity, which
    /// can only happen when `d` is `0` or a multiple of the curve order.
    public func getPublicKey() : PublicKey.PublicKey {
      switch (curve.fromJacobi(curve.mul_base(#fr(d)))) {
        case (#zero) Runtime.trap("Unable to get public key from private key, point was zero");
        case (#affine(x, y)) {
          let #fp(x_val) = x;
          let #fp(y_val) = y;
          PublicKey.PublicKey(x_val, y_val, curve);
        };
      };
    };

    /// Hashes `msg` with SHA-256 and produces an ECDSA signature.
    ///
    /// `rand` must yield at least 32 bytes of cryptographically secure
    /// randomness; they are used as the per-signature nonce `k`. Reusing
    /// the same `rand` for two different messages leaks the private key.
    ///
    /// Returns `#err(msg)` if `rand` is too short, if the derived nonce
    /// or the resulting `r` happens to be `0` (negligible probability),
    /// or if `msg` cannot be drained for hashing.
    public func sign(
      msg : Iter.Iter<Nat8>,
      rand : Iter.Iter<Nat8>,
    ) : Result.Result<Signature.Signature, Text> {
      let hashAlg = switch (curve.getBitSize()) {
        case (#b256) #sha256;
      };
      let hashedMsg = Sha256.fromIter(hashAlg, msg);
      signHashed(hashedMsg.vals(), rand);
    };

    /// Like `sign`, but takes an already-hashed message. `hashedMsg` must
    /// yield exactly 32 bytes (the SHA-256 digest of the original
    /// message); only the first 32 bytes are consumed.
    ///
    /// Returns `#err(msg)` for the same reasons as `sign`.
    public func signHashed(
      hashedMsg : Iter.Iter<Nat8>,
      rand : Iter.Iter<Nat8>,
    ) : Result.Result<Signature.Signature, Text> {
      let ?k = curve.getExponent(rand) else return #err("Not enough entropy bytes");
      let x = switch (curve.fromJacobi(curve.mul_base(k))) {
        case (#zero) return #err("Unable to get x from k, point was zero");
        case (#affine(x, _)) x;
      };
      let #fr(r) = curve.Fr.fromNat(curve.Fp.toNat(x));
      if (r == 0) return #err("Bad luck with x, r is 0");
      let ?z = curve.getExponent(hashedMsg) else return #err("Hashed message did not have enough bytes");
      // s = (r * sec + z) / k
      let #fr(s) = curve.Fr.div(curve.Fr.add(curve.Fr.mul(#fr(r), #fr(d)), z), k);
      #ok(Signature.Signature(r, s, curve));
    };

    /// Serialises the key to text in the chosen `format` (hex, base64, or
    /// PEM-armored DER). For PEM, the wrapper line uses `EC PRIVATE KEY`
    /// for SEC1 and `PRIVATE KEY` for PKCS#8.
    public func toText(format : OutputTextFormat) : Text {
      switch (format) {
        case (#hex(hex)) {
          let bytes = toBytes(hex.byteEncoding);
          KeyCommon.toText(bytes, #hex(hex));
        };
        case (#base64(base64)) {
          let bytes = toBytes(base64.byteEncoding);
          KeyCommon.toText(bytes, #base64(base64));
        };
        case (#pem({ byteEncoding })) {
          let bytes = toBytes(byteEncoding);
          let keyType = switch (byteEncoding) {
            case (#pkcs8) ("PRIVATE");
            case (#sec1) ("EC PRIVATE");
          };
          KeyCommon.toText(bytes, #pem({ keyType }));
        };
      };
    };

    /// Serialises the key to bytes in the chosen `encoding`.
    ///
    /// - `#raw` returns the 32-byte big-endian scalar.
    /// - `#sec1` returns the DER-encoded SEC1 EC private key (RFC 5915).
    /// - `#pkcs8` returns the DER-encoded PKCS#8 `PrivateKeyInfo`
    ///   (RFC 5208), wrapping the SEC1 form.
    public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
      switch (encoding) {
        case (#sec1) {
          let publicKeyBytes = getPublicKey().toBytes(#uncompressed);
          let privateKeyBytes = toBytes(#raw);
          let ecPrivateKey : ASN1.ASN1Value = #sequence([
            #integer(1), // EC private key version
            #octetString(privateKeyBytes),
            #contextSpecific({
              tagNumber = 0; // Curve
              value = ?#objectIdentifier([1, 2, 840, 10045, 3, 1, 7]); // prime256v1
              constructed = true;
            }),
            #contextSpecific({
              tagNumber = 1; // Public key
              value = ?#bitString({
                data = publicKeyBytes;
                unusedBits = 0;
              });
              constructed = true;
            }),
          ]);
          ASN1.toBytes(ecPrivateKey, #der);
        };
        case (#pkcs8) {
          let curveOid = switch (curve.kind) {
            case (#secp256k1) [1, 3, 132, 0, 10];
            case (#prime256v1) [1, 2, 840, 10045, 3, 1, 7];
          };

          // Create ASN.1 structure for EC private key

          let ecPrivateKeyDerBytes = toBytes(#sec1);

          // Wrap in PKCS#8 structure
          let pkcs8 : ASN1.ASN1Value = #sequence([
            #integer(0), // PKCS#8 version
            #sequence([
              #objectIdentifier([1, 2, 840, 10045, 2, 1]), // EC algorithm OID
              #objectIdentifier(curveOid),
            ]),
            #octetString(ecPrivateKeyDerBytes),
          ]);

          ASN1.toBytes(pkcs8, #der);
        };

        case (#raw) {
          let n = 32; // 32 bytes for 256-bit curves
          Util.toBigEndianPad(n, curve.Fp.toNat(#fp(d)));
        };
      };
    };

  };

  /// Generates a `PrivateKey` from a stream of random bytes.
  ///
  /// Consumes 32 bytes of `entropy`, interprets them as a big-endian
  /// integer, and reduces modulo the curve order. Returns
  /// `#err("Not enough entropy bytes")` if fewer than 32 bytes are
  /// available, or `#err("Bad entropy, the value is 0")` if the reduced
  /// scalar is zero.
  public func generate(
    entropy : Iter.Iter<Nat8>,
    curve : Curve.Curve,
  ) : Result.Result<PrivateKey, Text> {
    switch (curve.getExponent(entropy)) {
      case (null) return #err("Not enough entropy bytes");
      case (?#fr(0)) return #err("Bad entropy, the value is 0");
      case (?#fr(s)) #ok(PrivateKey(s, curve));
    };
  };

  /// Decodes a `PrivateKey` from a byte stream in the chosen `encoding`.
  ///
  /// See `InputByteEncoding` for the supported wire formats. Returns
  /// `#err(msg)` on malformed input, an out-of-range scalar (`d == 0`
  /// or `d >= r`), an unknown curve OID in the SEC1 / PKCS#8 wrapper, or
  /// any structural mismatch in the DER tree.
  public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PrivateKey, Text> {
    switch (encoding) {
      case (#raw({ curve })) {

        let ?d = Util.toNatAsBigEndian(bytes.take(32)) else return #err("Invalid private key: failed to decode d from bytes");

        // Validate the key is in range for the curve
        if (d == 0 or d >= curve.params.r) {
          return #err("Invalid private key: d is out of range for the curve");
        };

        #ok(PrivateKey(d, curve));
      };
      case (#sec1({ curve })) {
        let keyAsn1 = switch (ASN1.fromBytes(bytes, #der)) {
          case (#err(e)) return #err("Invalid DER format for inner key bytes: " # e);
          case (#ok(keyAsn1)) keyAsn1;
        };
        let #sequence(keySequence) = keyAsn1 else return #err("Invalid DER format: expected sequence for key bytes");
        if (keySequence.size() < 2) return #err("Invalid DER format: expected key sequence with 4 elements, got " # debug_show (keySequence.size()));
        // First element is the version (should be 1)
        let #integer(1) = keySequence[0] else return #err("Invalid DER format: expected version 1, got " # debug_show (keySequence[0]));
        // Second element is the private key as OCTET STRING
        let #octetString(privateKeyBytes) = keySequence[1] else return #err("Invalid DER format: expected private key as OCTET STRING");

        if (keySequence.size() > 2) {
          let #contextSpecific(context) = keySequence[2] else return #err("Invalid DER format: expected context for public key or ECParameters, got " # debug_show (keySequence[2]));
          switch (context.tagNumber) {
            case (0) {
              // This is the public key, we can ignore it
            };
            case (1) {
              // This is the ECParameters, we can ignore it
            };
            case (_) return #err("Invalid DER format: expected context for public key or ECParameters, got " # debug_show (context));
          };
        };

        // Validate the key
        fromBytes(privateKeyBytes.vals(), #raw({ curve }));
      };
      case (#pkcs8) {
        switch (ASN1.fromBytes(bytes, #der)) {
          case (#err(e)) return #err("Invalid DER format: " # e);
          case (#ok(#sequence(sequence))) {
            if (sequence.size() < 3) return #err("Invalid DER format: expected at least 3 elements");

            // First element is version (should be 0)
            let #integer(0) = sequence[0] else return #err("Invalid DER format: expected version 0, got " # debug_show (sequence[0]));

            // Second element is the algorithm identifier
            let #sequence(algorithmIdSequence) = sequence[1] else return #err("Invalid DER format: expected algorithm identifier");
            if (algorithmIdSequence.size() != 2) return #err("Invalid DER format: expected algorithm identifier with 2 elements");
            let #objectIdentifier(algorithmOid) = algorithmIdSequence[0] else return #err("Invalid DER format: expected algorithm OID");
            if (algorithmOid != [1, 2, 840, 10045, 2, 1]) return #err("Invalid DER format: expected algorithm OID for EC private key");
            let #objectIdentifier(algorithmCurveOid) = algorithmIdSequence[1] else return #err("Invalid DER format: expected expected algorithm curve OID");
            let curve = if (algorithmCurveOid == [1, 3, 132, 0, 10]) {
              Curve.secp256k1();
            } else if (algorithmCurveOid == [1, 2, 840, 10045, 3, 1, 7]) {
              Curve.prime256v1();
            } else {
              return #err("Invalid DER format: unsupported algorithm curve OID - " # debug_show (algorithmCurveOid));
            };

            // Third element is the private key as OCTET STRING
            let #octetString(keyBytes) = sequence[2] else return #err("Invalid DER format: expected private key as OCTET STRING");

            fromBytes(keyBytes.vals(), #sec1({ curve }));
          };
          case (#ok(_)) return #err("Invalid DER format: expected sequence");
        };
      };
    };
  };

  /// Decodes a `PrivateKey` from a textual representation.
  ///
  /// See `InputTextFormat` for the supported text formats. Returns
  /// `#err(msg)` on malformed text (bad hex/base64/PEM framing) or
  /// invalid inner bytes (see `fromBytes`).
  public func fromText(value : Text, format : InputTextFormat) : Result.Result<PrivateKey, Text> {
    let (internalFormat, byteEncoding) = switch (format) {
      case (#hex({ format; byteEncoding })) (#hex({ format }), byteEncoding);
      case (#base64({ byteEncoding })) (#base64, byteEncoding);
      case (#pem({ byteEncoding })) switch (byteEncoding) {
        case (#pkcs8) (#pem({ keyType = "PRIVATE" }), #pkcs8);
        case (#sec1({ curve })) (#pem({ keyType = "EC PRIVATE" }), #sec1({ curve }));
      };
    };
    KeyCommon.fromText<PrivateKey>(
      value,
      internalFormat,
      func(bytes : Iter.Iter<Nat8>) : Result.Result<PrivateKey, Text> {
        switch (fromBytes(bytes, byteEncoding)) {
          case (#ok(key)) #ok(key);
          case (#err(e)) #err("Invalid key bytes: " # e);
        };
      },
    );
  };
};
