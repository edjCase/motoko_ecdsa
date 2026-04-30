/// Internal helpers shared between `PrivateKey` and `PublicKey` for
/// converting key bytes to and from hex / base64 / PEM text.
///
/// ```motoko name=import
/// import KeyCommon "mo:ecdsa/KeyCommon";
/// ```

import Iter "mo:core@2/Iter";
import Result "mo:core@2/Result";
import Text "mo:core@2/Text";

import BaseX "mo:base-x-encoder@2";
import PeekableIter "mo:xtended-iter@1/PeekableIter";

import Curve "Curve";

module {

  /// Common shape for byte-encoding inputs that include `#raw`. The
  /// payload carries the curve to use for parsing.
  public type CommonInputByteEncoding = {
    #raw : {
      curve : Curve.Curve;
    };
  };

  /// Common shape for text-encoding outputs (hex or base64), parameterised
  /// over the inner byte encoding produced for the key.
  public type CommonOutputTextFormat<OutputByteEncoding> = {
    #base64 : {
      byteEncoding : OutputByteEncoding;
      format : BaseX.Base64OutputFormat;
    };
    #hex : {
      byteEncoding : OutputByteEncoding;
      format : BaseX.HexOutputFormat;
    };
  };

  /// Common shape for text-encoding inputs (hex or base64), parameterised
  /// over the inner byte encoding the parsed bytes will be interpreted as.
  public type CommonInputTextFormat<TInputTypeEncoding> = {
    #base64 : {
      byteEncoding : TInputTypeEncoding;
    };
    #hex : {
      byteEncoding : TInputTypeEncoding;
      format : BaseX.HexInputFormat;
    };
  };

  type InternalInputTextFormat = {
    #base64;
    #hex : {
      format : BaseX.HexInputFormat;
    };
    #pem : {
      keyType : Text;
    };
  };

  type InternalOutputTextFormat = {
    #pem : {
      keyType : Text;
    };
    #base64 : {
      format : BaseX.Base64OutputFormat;
    };
    #hex : {
      format : BaseX.HexOutputFormat;
    };
  };

  /// Encodes raw key bytes as hex, base64, or PEM-armored base64.
  /// `format` carries the keyType for the PEM `BEGIN/END` lines.
  // Generic function to convert key bytes to text format
  public func toText(
    bytes : [Nat8],
    format : InternalOutputTextFormat,
  ) : Text {
    switch (format) {
      case (#hex({ format })) BaseX.toHex(bytes.vals(), format);
      case (#base64({ format })) BaseX.toBase64(bytes.vals(), format);
      case (#pem({ keyType })) {
        let base64 = BaseX.toBase64(bytes.vals(), #standard({ includePadding = true }));

        let iter = PeekableIter.fromIter(base64.chars());
        var formatted = Text.fromIter(iter.take(64));
        while (iter.peek() != null) {
          formatted #= "\n" # Text.fromIter(iter.take(64));
        };

        "-----BEGIN " # keyType # " KEY-----\n" # formatted # "\n-----END " # keyType # " KEY-----\n";
      };
    };
  };

  /// Decodes hex, base64, or PEM-armored base64 text into key bytes,
  /// then forwards them to `fromBytes` to build the typed key.
  /// Returns `#err(msg)` on text-format errors or whatever `fromBytes`
  /// returns.
  // Generic function to convert text to key bytes
  public func fromText<TKey>(
    value : Text,
    format : InternalInputTextFormat,
    fromBytes : (Iter.Iter<Nat8>) -> Result.Result<TKey, Text>,
  ) : Result.Result<TKey, Text> {
    switch (format) {
      case (#hex({ format })) {
        // Convert hex to bytes
        switch (BaseX.fromHex(value, format)) {
          case (#ok(bytes)) {
            switch (fromBytes(bytes.vals())) {
              case (#ok(key)) #ok(key);
              case (#err(e)) #err("Invalid key bytes: " # e);
            };
          };
          case (#err(e)) #err("Invalid hex format: " # e);
        };
      };

      case (#base64()) {
        // Convert base64 to bytes
        switch (BaseX.fromBase64(value)) {
          case (#ok(bytes)) {
            switch (fromBytes(bytes.vals())) {
              case (#ok(key)) #ok(key);
              case (#err(e)) #err("Invalid key bytes: " # e);
            };
          };
          case (#err(e)) #err("Invalid base64 format: " # e);
        };
      };

      case (#pem({ keyType })) {
        // Parse PEM format
        switch (extractPEMContent(value, keyType)) {
          case (#ok(base64Content)) {
            switch (BaseX.fromBase64(base64Content)) {
              case (#ok(bytes)) {
                switch (fromBytes(bytes.vals())) {
                  case (#ok(key)) #ok(key);
                  case (#err(e)) #err("Invalid key bytes: " # e);
                };
              };
              case (#err(e)) #err("Failed to decode PEM base64: " # e);
            };
          };
          case (#err(e)) #err(e);
        };
      };
    };
  };

  // Helper function to extract content from PEM format for public keys
  private func extractPEMContent(pem : Text, keyType : Text) : Result.Result<Text, Text> {
    let header = "-----BEGIN " # keyType # " KEY-----";
    let ?headerTrimmedPem = pem.stripStart(#text(header)) else return #err("Invalid PEM format: missing header " # header);
    let footer = "-----END " # keyType # " KEY-----\n";
    let ?trimmedPem = headerTrimmedPem.stripEnd(#text(footer)) else return #err("Invalid PEM format: missing footer " # footer);
    #ok(trimmedPem.split(#char('\n')).join(""));
  };

};
