/// ECDSA public keys: storage, signature verification, and ASN.1 / PEM /
/// JWK encoding.
///
/// ```motoko name=import
/// import PublicKey "mo:ecdsa/PublicKey";
/// ```

import Array "mo:core@2/Array";
import Iter "mo:core@2/Iter";
import Nat "mo:core@2/Nat";
import Nat8 "mo:core@2/Nat8";
import Result "mo:core@2/Result";
import Text "mo:core@2/Text";

import ASN1 "mo:asn1@3";
import BaseX "mo:base-x-encoder@2";
import Sha256 "mo:sha2@0/Sha256";

import Curve "./Curve";
import Signature "./Signature";
import Util "./Util";
import KeyCommon "KeyCommon";

module {

  /// Byte encodings that can be wrapped inside PEM on input.
  /// `#spki` is X.509 SubjectPublicKeyInfo (RFC 5280); `#ec_public` is the
  /// bare DER `BIT STRING` containing a SEC1 point (the curve must be
  /// supplied explicitly since the bare encoding does not carry an OID).
  public type PEMInputByteEncoding = {
    #spki;
    #ec_public : {
      curve : Curve.Curve;
    };
  };

  /// All supported byte encodings for `fromBytes`. Adds `#raw` (a SEC1
  /// point: 33-byte compressed or 65-byte uncompressed) to the
  /// PEM-wrappable encodings.
  public type InputByteEncoding = PEMInputByteEncoding or KeyCommon.CommonInputByteEncoding;

  /// Byte encodings that can be wrapped inside PEM on output. Same
  /// shape as `PEMInputByteEncoding` but without the `curve` payload.
  public type PEMOutputEncoding = {
    #spki; // Subject Public Key Info
    #ec_public; // EC public key in ASN.1 DER format
  };

  /// All supported byte encodings for `toBytes`. Adds `#compressed` (33
  /// bytes, leading `0x02` / `0x03`) and `#uncompressed` (65 bytes,
  /// leading `0x04`) to the PEM-wrappable encodings.
  public type OutputByteEncoding = PEMOutputEncoding or {
    #compressed;
    #uncompressed;
  };

  /// All supported text formats for `toText`: hex, base64 (each carrying
  /// an inner `OutputByteEncoding`), PEM-armored DER, or JWK
  /// (RFC 7517 / 7518: a JSON object `{kty, crv, x, y}` with
  /// base64url-encoded coordinates).
  public type OutputTextFormat = KeyCommon.CommonOutputTextFormat<OutputByteEncoding> or {
    #jwk;
    #pem : {
      byteEncoding : PEMOutputEncoding;
    };
  };

  /// All supported text formats for `fromText`: hex, base64 (each carrying
  /// an inner `InputByteEncoding`), or PEM-armored DER. JWK input is not
  /// supported.
  public type InputTextFormat = KeyCommon.CommonInputTextFormat<InputByteEncoding> or {
    #pem : {
      byteEncoding : PEMInputByteEncoding;
    };
  };

  /// An ECDSA public key represented as the affine point `(x, y)` on
  /// `curve`.
  ///
  /// The constructor does not validate that `(x, y)` lies on the curve;
  /// callers are expected to use the `from*` parsers when ingesting
  /// untrusted data.
  public class PublicKey(
    x_ : Nat,
    y_ : Nat,
    curve_ : Curve.Curve,
  ) {
    /// The affine x-coordinate of this point, `0 <= x < p`.
    public let x = x_;
    /// The affine y-coordinate of this point, `0 <= y < p`.
    public let y = y_;
    /// The curve this public key belongs to.
    public let curve = curve_;

    /// Returns `true` when `other` denotes the same point on the same curve.
    public func equal(other : PublicKey) : Bool {
      curve.kind == other.curve.kind and curve.isEqual((#fp(x), #fp(y), #fp(1)), (#fp(other.x), #fp(other.y), #fp(1)));
    };

    /// Hashes `msg` with SHA-256 and verifies `sig` against the digest.
    /// Returns `true` iff `sig` is a valid ECDSA signature of the hashed
    /// message under this public key. The signature must be in low-S
    /// form (BIP 62); higher-S signatures are rejected.
    public func verify(
      msg : Iter.Iter<Nat8>,
      sig : Signature.Signature,
    ) : Bool {
      let hashAlg = switch (curve.getBitSize()) {
        case (#b256) #sha256;
      };
      let hashedMsg = Sha256.fromIter(hashAlg, msg).vals();
      verifyHashed(hashedMsg, sig);
    };

    /// Like `verify`, but takes an already-hashed message. `hashedMsg`
    /// must yield exactly 32 bytes (the SHA-256 digest); only the first
    /// 32 bytes are consumed.
    public func verifyHashed(
      hashedMsg : Iter.Iter<Nat8>,
      signature : Signature.Signature,
    ) : Bool {
      if (signature.r == 0) return false;
      if (signature.s == 0) return false;
      if (curve.Fr.toNat(#fr(signature.s)) >= curve.params.rHalf) return false;
      let ?#fr(hash_z) = curve.getExponent(hashedMsg) else return false;
      let w = curve.Fr.inv(#fr(signature.s));
      let u1 = curve.Fr.mul(#fr(hash_z), w);
      let u2 = curve.Fr.mul(#fr(signature.r), w);
      let xyz = (#fp(x), #fp(y), #fp(1)); // Z-coordinate should be 1 for affine point
      let true = curve.isValid(xyz) else return false;
      let r = curve.add(curve.mul_base(u1), curve.mul(xyz, u2));
      switch (curve.fromJacobi(r)) {
        case (#zero) false;
        case (#affine(x, _)) curve.Fr.fromNat(curve.Fp.toNat(x)) == #fr(signature.r);
      };
    };

    /// Serialises the key to text in the chosen `format`.
    ///
    /// `#hex` and `#base64` wrap the byte encoding selected inside the
    /// variant. `#pem` produces a PEM-armored DER block (`PUBLIC KEY` for
    /// SPKI, `EC PUBLIC KEY` for the bare encoding). `#jwk` produces a
    /// JSON Web Key string with base64url-encoded `x` and `y` and a `crv`
    /// of `"secp256k1"` or `"P-256"`.
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
            case (#spki) ("PUBLIC");
            case (#ec_public) ("EC PUBLIC");
          };
          KeyCommon.toText(bytes, #pem({ keyType }));
        };
        case (#jwk) {
          // JWK format is specific to public keys, keep it in PublicKey module
          // Get uncompressed point format (0x04 + X + Y coordinates)
          let bytes = toBytes(#uncompressed);

          // Extract X and Y coordinates (32 bytes each after 0x04 prefix)
          let xCoord = Array.tabulate<Nat8>(32, func(i) { bytes[i + 1] });
          let yCoord = Array.tabulate<Nat8>(32, func(i) { bytes[i + 33] });

          // Base64URL encode coordinates
          let xB64 = BaseX.toBase64(xCoord.vals(), #url({ includePadding = false }));
          let yB64 = BaseX.toBase64(yCoord.vals(), #url({ includePadding = false }));

          // Get curve name
          let curveName = switch (curve.kind) {
            case (#secp256k1) "secp256k1";
            case (#prime256v1) "P-256";
          };

          // Format as JWK JSON
          "{\"kty\":\"EC\",\"crv\":\"" # curveName # "\",\"x\":\"" # xB64 # "\",\"y\":\"" # yB64 # "\"}";
        };
      };
    };

    /// Serialises the key to bytes in the chosen `encoding`.
    ///
    /// - `#compressed` returns 33 bytes: a `0x02`/`0x03` prefix
    ///   indicating y-parity, followed by the 32-byte big-endian x.
    /// - `#uncompressed` returns 65 bytes: a `0x04` prefix followed by
    ///   32-byte big-endian x and y.
    /// - `#ec_public` wraps the uncompressed point in a DER `BIT STRING`.
    /// - `#spki` wraps the uncompressed point in a DER
    ///   SubjectPublicKeyInfo with the appropriate algorithm and curve
    ///   OIDs.
    public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
      switch (encoding) {
        case (#spki) {
          let uncompressed = toBytesUncompressed();
          let curveOid = switch (curve.kind) {
            case (#secp256k1) [1, 3, 132, 0, 10];
            case (#prime256v1) [1, 2, 840, 10045, 3, 1, 7];
          };
          let asn1 : ASN1.ASN1Value = #sequence([
            #sequence([
              #objectIdentifier([1, 2, 840, 10_045, 2, 1]),
              #objectIdentifier(curveOid),
            ]),
            #bitString({ data = uncompressed; unusedBits = 0 }),
          ]);
          ASN1.toBytes(asn1, #der);
        };
        case (#ec_public) {
          let uncompressed = toBytesUncompressed();
          let asn1 : ASN1.ASN1Value = #bitString({
            data = uncompressed;
            unusedBits = 0;
          });
          ASN1.toBytes(asn1, #der);
        };
        case (#uncompressed) toBytesUncompressed();
        case (#compressed) toBytesCompressed();
      };
    };

    /// return 0x02 + bigEndian(x) if y is even
    /// return 0x03 + bigEndian(x) if y is odd
    private func toBytesCompressed() : [Nat8] {
      let prefix : Nat8 = if ((curve.Fp.toNat(#fp(y)) % 2) == 0) 0x02 else 0x03;
      let n = 32;
      let x_bytes = Util.toBigEndianPad(n, curve.Fp.toNat(#fp(x)));

      Array.tabulate<Nat8>(
        1 + n,
        func(i : Nat) : Nat8 {
          if (i == 0) {
            prefix;
          } else {
            x_bytes[i - 1];
          };
        },
      );
    };

    /// return 0x04 + bigEndian(x) + bigEndian(y)
    private func toBytesUncompressed() : [Nat8] {
      let prefix = 0x04 : Nat8;
      let n = 32;
      let x_bytes = Util.toBigEndianPad(n, curve.Fp.toNat(#fp(x)));
      let y_bytes = Util.toBigEndianPad(n, curve.Fp.toNat(#fp(y)));
      Array.tabulate<Nat8>(
        1 + n * 2,
        func(i : Nat) : Nat8 {
          if (i == 0) {
            prefix;
          } else if (i <= n) {
            x_bytes[i - 1];
          } else {
            y_bytes[i - 1 - n];
          };
        },
      );
    };
  };

  /// Decodes a `PublicKey` from a byte stream in the chosen `encoding`.
  ///
  /// See `InputByteEncoding` for the supported wire formats. Returns
  /// `#err(msg)` on malformed input, an unknown SEC1 prefix byte, an
  /// out-of-range coordinate, a point that is not on the curve, or an
  /// unknown curve OID in the SPKI wrapper.
  public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text> {
    switch (encoding) {
      case (#raw({ curve })) {
        let even = switch (bytes.next()) {
          case (?0x02) true;
          case (?0x03) false;
          case (?0x04) {
            // Uncompressed key
            let n = 32;
            let ?x = Util.toNatAsBigEndian(bytes.take(n)) else return #err("Unable to parse x coordinate");
            let ?y = Util.toNatAsBigEndian(bytes.take(n)) else return #err("Unable to parse y coordinate");
            if (x >= curve.params.p) return #err("Invalid x coordinate, out of range");
            if (y >= curve.params.p) return #err("Invalid y coordinate, out of range");
            let pub = (#fp(x), #fp(y));
            if (not curve.isValidAffine(pub)) return #err("Invalid x and y points, not on curve");
            return #ok(PublicKey(x, y, curve));
          };
          case (?prefix) return #err("Invalid key prefix: " # prefix.toText());
          case (null) return #err("Not enough bytes for key");
        };
        // Compressed key
        let ?x = Util.toNatAsBigEndian(bytes) else return #err("Unable to parse x coordinate");
        if (x >= curve.params.p) return #err("Invalid x coordinate, out of range");
        let ?#fp(y) = curve.getYfromX(#fp(x), even) else return #err("Unable to calculate y coordinate");
        #ok(PublicKey(x, y, curve));
      };
      case (#ec_public({ curve })) {
        let asn1 = ASN1.fromBytes(bytes, #der);
        switch (asn1) {
          case (#err(e)) return #err("Invalid ANS1 DER format: " # e);
          case (#ok(#bitString({ data = keyBytes; unusedBits = 0 }))) {
            fromBytes(keyBytes.vals(), #raw({ curve }));
          };
          case (#ok(_)) return #err("Invalid DER format: expected sequence");
        };
      };
      case (#spki) {
        let asn1 = ASN1.fromBytes(bytes, #der);
        switch (asn1) {
          case (#err(e)) return #err("Invalid ANS1 DER format: " # e);
          case (#ok(#sequence(sequence))) {
            if (sequence.size() < 2) return #err("Invalid DER format: expected sequence of length 2");

            // First element is the algorithm identifier
            let #sequence(algorithmIdSequence) = sequence[0] else return #err("Invalid DER format: expected algorithm identifier sequence");
            if (algorithmIdSequence.size() != 2) return #err("Invalid DER format: expected algorithm identifier sequence of length 2");

            // Check algorithm OID
            let #objectIdentifier(algorithmOid) = algorithmIdSequence[0] else return #err("Invalid DER format: expected algorithm OID");
            if (algorithmOid != [1, 2, 840, 10_045, 2, 1]) return #err("Invalid DER format: unsupported algorithm OID");

            let #objectIdentifier(algorithmCurveOid) = algorithmIdSequence[1] else return #err("Invalid DER format: expected algorithm curve OID");
            let curve = if (algorithmCurveOid == [1, 3, 132, 0, 10]) {
              Curve.secp256k1();
            } else if (algorithmCurveOid == [1, 2, 840, 10045, 3, 1, 7]) {
              Curve.prime256v1();
            } else {
              return #err("Invalid DER format: unsupported curve OID - " # debug_show algorithmCurveOid);
            };

            // Second element is the public key as BIT STRING
            let #bitString({ data = keyBytes; unusedBits = 0 }) = sequence[1] else return #err("Invalid DER format: expected BIT STRING");

            fromBytes(keyBytes.vals(), #raw({ curve }));
          };
          case (#ok(_)) return #err("Invalid DER format: expected sequence");
        };
      };
    };
  };
  /// Decodes a `PublicKey` from a textual representation.
  ///
  /// See `InputTextFormat` for the supported text formats. Returns
  /// `#err(msg)` on malformed text or invalid inner bytes (see
  /// `fromBytes`). JWK input is not supported.
  public func fromText(value : Text, format : InputTextFormat) : Result.Result<PublicKey, Text> {
    let (internalFormat, byteEncoding) = switch (format) {
      case (#hex({ format; byteEncoding })) (#hex({ format }), byteEncoding);
      case (#base64({ byteEncoding })) (#base64, byteEncoding);
      case (#pem({ byteEncoding })) switch (byteEncoding) {
        case (#spki) (#pem({ keyType = "PUBLIC" }), #spki);
        case (#ec_public({ curve })) (#pem({ keyType = "EC PUBLIC" }), #ec_public({ curve }));
      };
    };
    KeyCommon.fromText<PublicKey>(
      value,
      internalFormat,
      func(bytes : Iter.Iter<Nat8>) : Result.Result<PublicKey, Text> {
        fromBytes(bytes, byteEncoding);
      },
    );
  };

};
