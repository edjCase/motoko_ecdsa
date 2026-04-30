/// ECDSA digital signatures over the secp256k1 and prime256v1 (NIST P-256)
/// curves.
///
/// This module is the main entry point. It re-exports the `Curve`,
/// `PrivateKey`, `PublicKey` and `Signature` types and provides convenience
/// constructors and parsers for each. Use the constructors below to create
/// keys from an integer or random entropy, then sign messages with
/// `PrivateKey.sign` and verify them with `PublicKey.verify`.
///
/// All hashing is performed with SHA-256 (matching both supported curves'
/// 256-bit field size).
///
/// ```motoko name=import
/// import ECDSA "mo:ecdsa";
/// ```

import Iter "mo:core@2/Iter";
import Result "mo:core@2/Result";
import Option "mo:core/Option";

import CurveModule "./Curve";
import PrivateKeyModule "PrivateKey";
import PublicKeyModule "PublicKey";
import SignatureModule "Signature";

module {

  /// Tag identifying which standard elliptic curve is in use.
  /// Either `#secp256k1` (used by Bitcoin and ICP) or `#prime256v1`
  /// (a.k.a. NIST P-256, used in WebAuthn / TLS).
  public type CurveKind = CurveModule.CurveKind;

  /// An elliptic curve instance carrying its parameters and field
  /// arithmetic. Construct one with `Curve(kind)`, `secp256k1Curve()`, or
  /// `prime256v1Curve()`. The same `Curve` value should be reused for many
  /// keys and signatures (it caches parameter tables).
  public type Curve = CurveModule.Curve;

  /// Constructs the `Curve` for the given `kind`.
  public func Curve(kind : CurveKind) : Curve = CurveModule.Curve(kind);

  /// Returns the secp256k1 curve.
  public func secp256k1Curve() : Curve = CurveModule.secp256k1();

  /// Returns the prime256v1 (NIST P-256) curve.
  public func prime256v1Curve() : Curve = CurveModule.prime256v1();

  /// An ECDSA public key: an affine point `(x, y)` on `curve`.
  public type PublicKey = PublicKeyModule.PublicKey;

  /// Constructs a `PublicKey` from raw affine coordinates.
  ///
  /// `x` and `y` must be field elements satisfying the curve equation; this
  /// constructor does not validate them. Prefer `publicKeyFromBytes` /
  /// `publicKeyFromText` when ingesting external data, since those check
  /// that the point is on the curve.
  public func PublicKey(
    x : Nat,
    y : Nat,
    curve : CurveModule.Curve,
  ) : PublicKey = PublicKeyModule.PublicKey(x, y, curve);

  /// Decodes a `PublicKey` from a byte stream.
  ///
  /// `encoding` selects the wire format:
  /// - `#raw({ curve })` — SEC1 point: leading byte `0x02`/`0x03`
  ///   (compressed, 33 bytes total) or `0x04` (uncompressed, 65 bytes).
  /// - `#ec_public({ curve })` — DER `BIT STRING` wrapping the SEC1 point.
  /// - `#spki` — DER SubjectPublicKeyInfo (RFC 5280); the curve OID is read
  ///   from the structure, so no `curve` argument is required.
  ///
  /// Returns `#err(msg)` on malformed input, an unknown curve OID, an
  /// unsupported point prefix, an out-of-range coordinate, or a point that
  /// is not on the curve.
  public func publicKeyFromBytes(
    bytes : Iter.Iter<Nat8>,
    encoding : PublicKeyModule.InputByteEncoding,
  ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromBytes(bytes, encoding);

  /// Decodes a `PublicKey` from a textual representation.
  ///
  /// `encoding` selects the text format and inner byte encoding:
  /// - `#hex` — hex string of the inner byte encoding.
  /// - `#base64` — base64 of the inner byte encoding.
  /// - `#pem` — PEM-armored DER (`PUBLIC KEY` for SPKI, `EC PUBLIC KEY`
  ///   for the bare EC public key).
  ///
  /// Returns `#err(msg)` on malformed text or invalid inner bytes (see
  /// `publicKeyFromBytes`).
  public func publicKeyFromText(
    text : Text,
    encoding : PublicKeyModule.InputTextFormat,
  ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromText(text, encoding);

  /// An ECDSA private key: a scalar `d` modulo the curve order `r`.
  public type PrivateKey = PrivateKeyModule.PrivateKey;

  /// Constructs a `PrivateKey` from a raw scalar `d` and a curve.
  ///
  /// `d` is taken modulo the curve order; supplying `0` produces an
  /// unusable key (signing will fail later). Prefer `generatePrivateKey`
  /// when the scalar comes from a random source.
  public func PrivateKey(
    d : Nat,
    curve : CurveModule.Curve,
  ) : PrivateKey = PrivateKeyModule.PrivateKey(d % curve.params.r, curve);

  /// Decodes a `PrivateKey` from a byte stream.
  ///
  /// `encoding` selects the wire format:
  /// - `#raw({ curve })` — 32-byte big-endian scalar.
  /// - `#sec1({ curve })` — SEC1 EC private key DER structure (RFC 5915).
  /// - `#pkcs8` — PKCS#8 `PrivateKeyInfo` DER (RFC 5208); the curve OID is
  ///   read from the structure.
  ///
  /// Returns `#err(msg)` if the input is malformed, the scalar is `0`, the
  /// scalar is `>= r`, or the curve OID is unknown.
  public func privateKeyFromBytes(
    bytes : Iter.Iter<Nat8>,
    encoding : PrivateKeyModule.InputByteEncoding,
  ) : Result.Result<PrivateKey, Text> = PrivateKeyModule.fromBytes(bytes, encoding);

  /// Decodes a `PrivateKey` from a textual representation.
  ///
  /// `encoding` selects the text format and inner byte encoding:
  /// - `#hex` / `#base64` — string-encoded form of the inner bytes.
  /// - `#pem` — PEM-armored DER (`PRIVATE KEY` for PKCS#8, `EC PRIVATE
  ///   KEY` for SEC1).
  ///
  /// Returns `#err(msg)` on malformed text or invalid inner bytes (see
  /// `privateKeyFromBytes`).
  public func privateKeyFromText(
    text : Text,
    encoding : PrivateKeyModule.InputTextFormat,
  ) : Result.Result<PrivateKey, Text> = PrivateKeyModule.fromText(text, encoding);

  /// Generates a `PrivateKey` from a stream of random bytes.
  ///
  /// `entropy` must yield at least 32 bytes. They are interpreted as a
  /// big-endian 256-bit integer and reduced modulo the curve order.
  ///
  /// Returns `#err("Not enough entropy bytes")` when fewer than 32 bytes
  /// are available, or `#err("Bad entropy, the value is 0")` in the
  /// astronomically unlikely case that the reduced scalar is zero.
  public func generatePrivateKey(
    entropy : Iter.Iter<Nat8>,
    curve : CurveModule.Curve,
  ) : Result.Result<PrivateKey, Text> = PrivateKeyModule.generate(entropy, curve);

  /// An ECDSA signature: a pair `(r, s)` of integers modulo the curve order.
  ///
  /// On construction, `s` is normalised to the lower half of the field
  /// (low-S form, BIP 62) for cross-implementation compatibility.
  public type Signature = SignatureModule.Signature;

  /// Constructs a `Signature` from raw scalar values.
  ///
  /// The original `r` and `s` are preserved verbatim on the `original_r`
  /// and `original_s` fields, while the normalised low-S `s` is exposed as
  /// `s`. No validity check is performed; prefer `signatureFromBytes` /
  /// `signatureFromText` when the signature comes from external data.
  public func Signature(
    r : Nat,
    s : Nat,
    curve : CurveModule.Curve,
  ) : Signature = SignatureModule.Signature(r, s, curve);

  /// Decodes a `Signature` from a byte stream.
  ///
  /// `encoding` selects the wire format:
  /// - `#raw` — `r ‖ s`, each as a 32-byte big-endian integer.
  /// - `#der` — DER `SEQUENCE { INTEGER r, INTEGER s }` (X.509).
  ///
  /// Returns `#err(msg)` on malformed input or negative `r`/`s`.
  public func signatureFromBytes(
    bytes : Iter.Iter<Nat8>,
    curve : CurveModule.Curve,
    encoding : SignatureModule.InputByteEncoding,
  ) : Result.Result<Signature, Text> = SignatureModule.fromBytes(bytes, curve, encoding);

  /// Decodes a `Signature` from a textual representation.
  ///
  /// `encoding` selects the text format (`#hex` or `#base64`) along with
  /// the inner byte encoding (`#raw` or `#der`).
  ///
  /// Returns `#err(msg)` on malformed text or invalid inner bytes (see
  /// `signatureFromBytes`).
  public func signatureFromText(
    text : Text,
    curve : CurveModule.Curve,
    encoding : SignatureModule.InputTextFormat,
  ) : Result.Result<Signature, Text> = SignatureModule.fromText(text, curve, encoding);
};
