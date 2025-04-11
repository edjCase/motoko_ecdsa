import BaseX "mo:base-x-encoder";
import Text "mo:new-base/Text";
import Result "mo:new-base/Result";
import Iter "mo:base/Iter";
import IterTools "mo:itertools/Iter";
import PeekableIter "mo:itertools/PeekableIter";
import Curve "Curve";

module {

    public type InputByteEncoding = {
        #der;
        #raw : {
            curve : Curve.Curve;
        };
    };

    public type OutputTextFormat<OutputByteEncoding> = {
        #pem;
        #base64 : {
            byteEncoding : OutputByteEncoding;
            isUriSafe : Bool;
        };
        #hex : {
            byteEncoding : OutputByteEncoding;
            format : BaseX.HexOutputFormat;
        };
    };

    public type InputTextFormat = {
        #pem;
        #base64 : {
            byteEncoding : InputByteEncoding;
        };
        #hex : {
            byteEncoding : InputByteEncoding;
            format : BaseX.HexInputFormat;
        };
    };

    type InternalOutputTextFormat = {
        #pem;
        #base64 : {
            isUriSafe : Bool;
        };
        #hex : {
            format : BaseX.HexOutputFormat;
        };
    };

    // Generic function to convert key bytes to text format
    public func toText(
        bytes : [Nat8],
        format : InternalOutputTextFormat,
        isPrivate : Bool,
    ) : Text {
        switch (format) {
            case (#hex({ format })) BaseX.toHex(bytes.vals(), format);
            case (#base64({ isUriSafe })) BaseX.toBase64(bytes.vals(), isUriSafe);
            case (#pem) {
                let base64 = BaseX.toBase64(bytes.vals(), false);

                let iter = PeekableIter.fromIter(base64.chars());
                var formatted = Text.fromIter(IterTools.take(iter, 64));
                while (iter.peek() != null) {
                    formatted #= "\n" # Text.fromIter(IterTools.take(iter, 64));
                };
                let (header, footer) = getPEMHeaderFooter(isPrivate);

                header # "\n" # formatted # "\n" # footer;
            };
        };
    };

    // Generic function to convert text to key bytes
    public func fromText<TKey>(
        value : Text,
        format : InputTextFormat,
        fromBytes : (Iter.Iter<Nat8>, InputByteEncoding) -> Result.Result<TKey, Text>,
        isPrivate : Bool,
    ) : Result.Result<TKey, Text> {
        switch (format) {
            case (#hex({ byteEncoding; format })) {
                // Convert hex to bytes
                switch (BaseX.fromHex(value, format)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(key)) #ok(key);
                            case (#err(e)) #err("Invalid key bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid hex format: " # e);
                };
            };

            case (#base64({ byteEncoding })) {
                // Convert base64 to bytes
                switch (BaseX.fromBase64(value)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(key)) #ok(key);
                            case (#err(e)) #err("Invalid key bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid base64 format: " # e);
                };
            };

            case (#pem) {
                // Parse PEM format
                switch (extractPEMContent(value, isPrivate)) {
                    case (#ok(base64Content)) {
                        switch (BaseX.fromBase64(base64Content)) {
                            case (#ok(bytes)) {
                                switch (fromBytes(bytes.vals(), #der)) {
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
    private func extractPEMContent(pem : Text, isPrivate : Bool) : Result.Result<Text, Text> {
        let (header, footer) = getPEMHeaderFooter(isPrivate);
        let ?headerTrimmedPem = Text.stripStart(pem, #text(header)) else return #err("Invalid PEM format: missing header");
        let ?trimmedPem = Text.stripEnd(headerTrimmedPem, #text(footer)) else return #err("Invalid PEM format: missing footer");
        #ok(Text.join("", Text.split(trimmedPem, #char('\n'))));
    };

    private func getPEMHeaderFooter(isPrivate : Bool) : (Text, Text) {
        let header = if (isPrivate) "-----BEGIN PRIVATE KEY-----" else "-----BEGIN PUBLIC KEY-----";
        let footer = if (isPrivate) "-----END PRIVATE KEY-----" else "-----END PUBLIC KEY-----";
        (header, footer);
    };
};
