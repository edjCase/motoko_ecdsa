/// ECDSA signatures: storage, raw / DER encoding, and hex / base64 text
/// formatting.
///
/// ```motoko name=import
/// import Signature "mo:ecdsa/Signature";
/// ```

import Int "mo:core@2/Int";
import Iter "mo:core@2/Iter";
import List "mo:core@2/List";
import Nat "mo:core@2/Nat";
import Nat8 "mo:core@2/Nat8";
import Result "mo:core@2/Result";

import ASN1 "mo:asn1@3";
import BaseX "mo:base-x-encoder@2";
import Buffer "mo:buffer@0";
import NatX "mo:xtended-numbers@2/NatX";

import Curve "./Curve";
import Util "Util";

module {
  /// Wire formats accepted by `fromBytes`.
  /// `#raw` is `r ‖ s`, each as a 32-byte big-endian integer.
  /// `#der` is the X.509 DER encoding `SEQUENCE { INTEGER r, INTEGER s }`.
  public type InputByteEncoding = {
    #der;
    #raw;
  };

  /// Wire formats produced by `toBytes`. Same shape as
  /// `InputByteEncoding`.
  public type OutputByteEncoding = {
    #der;
    #raw;
  };

  /// Text formats produced by `toText`: hex or base64, each carrying an
  /// inner `OutputByteEncoding`.
  public type OutputTextFormat = {
    #base64 : {
      byteEncoding : OutputByteEncoding;
      format : BaseX.Base64OutputFormat;
    };
    #hex : {
      byteEncoding : OutputByteEncoding;
      format : BaseX.HexOutputFormat;
    };
  };

  /// Text formats accepted by `fromText`: hex (with input format hints)
  /// or base64, each carrying an inner `InputByteEncoding`.
  public type InputTextFormat = {
    #base64 : {
      byteEncoding : InputByteEncoding;
    };
    #hex : {
      byteEncoding : InputByteEncoding;
      format : BaseX.HexInputFormat;
    };
  };

  /// An ECDSA signature `(r, s)` over `curve`.
  ///
  /// The constructor preserves the inputs verbatim on `original_r` /
  /// `original_s`, and additionally exposes the canonical low-S form on
  /// `r` / `s` (BIP 62: when `s_ > r/2`, the stored `s` is `r - s_`).
  /// `equal` and the cryptographic operations work on the low-S form;
  /// the `original_*` fields are kept so that re-encoded signatures
  /// match the original byte-for-byte when round-tripped through
  /// `toBytes`.
  public class Signature(r_ : Nat, s_ : Nat, curve_ : Curve.Curve) {
    /// The curve this signature is over.
    public let curve = curve_;

    /// The `r` value as supplied to the constructor (also equal to `r`).
    public let original_r = r_;
    /// The `s` value as supplied to the constructor, before low-S
    /// normalisation.
    public let original_s = s_;

    /// The signature components used for verification: `r` is unchanged,
    /// `s` is the low-S canonical form (`min(s_, r - s_)`).
    public let (r, s) : (Nat, Nat) = if (curve.Fr.toNat(#fr(s_)) < curve.params.rHalf) {
      (r_, s_);
    } else {
      let #fr(s) = curve.Fr.neg(#fr(s_));
      (r_, s);
    };

    /// Returns `true` when `other` has the same curve and the same
    /// normalised `(r, s)` pair.
    public func equal(other : Signature) : Bool {
      curve.equal(other.curve) and r == other.r and s == other.s;
    };

    /// Serialises the signature to bytes.
    ///
    /// - `#raw` returns 64 bytes: `r ‖ s`, each as a 32-byte big-endian
    ///   integer (left-padded with zeros if needed). The `original_*`
    ///   values are written, not the low-S form.
    /// - `#der` returns the X.509 DER encoding
    ///   `SEQUENCE { INTEGER r, INTEGER s }`.
    public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
      switch (encoding) {
        case (#raw) {
          let size = switch (curve.getBitSize()) {
            case (#b256) 32;
          };

          let buf = List.empty<Nat8>();
          let encodeAndPad = func(value : Nat) {
            let natBuffer = List.empty<Nat8>();
            NatX.toNatBytesBuffer(Buffer.fromList(natBuffer), value, #msb);
            let padding : Nat = size - natBuffer.size();
            // Left-pad with zeros if needed
            if (padding > 0) {
              for (i in Nat.range(0, padding)) {
                buf.add(0 : Nat8);
              };
            };
            buf.addAll(natBuffer.values());
          };

          // Encode r
          encodeAndPad(original_r);
          // Encode s
          encodeAndPad(original_s);

          buf.toArray();
        };
        case (#der) {
          let asn1Value : ASN1.ASN1Value = #sequence([#integer(original_r), #integer(original_s)]);
          ASN1.toBytes(asn1Value, #der);
        };
      };
    };

    /// Serialises the signature to text in the chosen `format` (hex or
    /// base64), wrapping the bytes produced by `toBytes` in the inner
    /// `byteEncoding`.
    public func toText(format : OutputTextFormat) : Text {
      switch (format) {
        case (#hex(hex)) {
          let bytes = toBytes(hex.byteEncoding);
          BaseX.toHex(bytes.vals(), hex.format);
        };
        case (#base64(base64)) {
          let bytes = toBytes(base64.byteEncoding);
          BaseX.toBase64(bytes.vals(), base64.format);
        };
      };
    };
  };

  /// Decodes a `Signature` from a byte stream.
  ///
  /// `encoding` selects between `#raw` (`r ‖ s`, 32 bytes each, big
  /// endian) and `#der` (`SEQUENCE { INTEGER r, INTEGER s }`). Returns
  /// `#err(msg)` on malformed input or negative `r` / `s` in the DER
  /// form.
  public func fromBytes(bytes : Iter.Iter<Nat8>, curve : Curve.Curve, encoding : InputByteEncoding) : Result.Result<Signature, Text> {
    switch (encoding) {
      case (#raw) {
        // Extract r and s values
        let rBytes = bytes.take(32);

        let ?r = Util.toNatAsBigEndian(rBytes) else return #err("Invalid signature: failed to decode r from bytes");
        let sBytes = bytes.take(32);
        let ?s = Util.toNatAsBigEndian(sBytes) else return #err("Invalid signature: failed to decode s from bytes");

        #ok(Signature(r, s, curve));
      };
      case (#der) {
        switch (ASN1.fromBytes(bytes, #der)) {
          case (#err(e)) return #err("Invalid DER format: " # e);
          case (#ok(#sequence(sequence))) {
            if (sequence.size() != 2) return #err("Invalid DER format: expected 2 elements");
            let #integer(r) = sequence[0] else return #err("Invalid DER format: expected integer for r");
            if (r < 0) return #err("Invalid DER format: r is negative");

            let #integer(s) = sequence[1] else return #err("Invalid DER format: expected integer for s");
            if (s < 0) return #err("Invalid DER format: s is negative");
            return #ok(Signature(Int.abs(r), Int.abs(s), curve));
          };
          case (#ok(_)) return #err("Invalid DER format: expected sequence");
        };
      };

    };
  };

  /// Decodes a `Signature` from a textual representation.
  ///
  /// `encoding` selects the text format (`#hex` or `#base64`) and the
  /// inner byte encoding (`#raw` or `#der`). Returns `#err(msg)` on
  /// malformed text or invalid inner bytes (see `fromBytes`).
  public func fromText(value : Text, curve : Curve.Curve, encoding : InputTextFormat) : Result.Result<Signature, Text> {
    switch (encoding) {
      case (#hex({ byteEncoding; format })) {
        // Convert hex to bytes
        switch (BaseX.fromHex(value, format)) {
          case (#ok(bytes)) {
            switch (fromBytes(bytes.vals(), curve, byteEncoding)) {
              case (#ok(signature)) #ok(signature);
              case (#err(e)) #err("Invalid signature bytes: " # e);
            };
          };
          case (#err(e)) #err("Invalid hex format: " # e);
        };
      };
      case (#base64({ byteEncoding })) {
        // Convert base64 to bytes
        switch (BaseX.fromBase64(value)) {
          case (#ok(bytes)) {
            switch (fromBytes(bytes.vals(), curve, byteEncoding)) {
              case (#ok(signature)) #ok(signature);
              case (#err(e)) #err("Invalid signature bytes: " # e);
            };
          };
          case (#err(e)) #err("Invalid base64 format: " # e);
        };
      };
    };
  };
};
