import BaseX "mo:base-x-encoder";
import Text "mo:new-base/Text";
import Result "mo:new-base/Result";
import Iter "mo:base/Iter";
import IterTools "mo:itertools/Iter";
import PeekableIter "mo:itertools/PeekableIter";
import Curve "Curve";

module {

    public type CommonInputByteEncoding = {
        #raw : {
            curve : Curve.Curve;
        };
    };

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
                var formatted = Text.fromIter(IterTools.take(iter, 64));
                while (iter.peek() != null) {
                    formatted #= "\n" # Text.fromIter(IterTools.take(iter, 64));
                };

                "-----BEGIN " # keyType # " KEY-----\n" # formatted # "\n-----END " # keyType # " KEY-----\n";
            };
        };
    };

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
        let ?headerTrimmedPem = Text.stripStart(pem, #text(header)) else return #err("Invalid PEM format: missing header " # header);
        let footer = "-----END " # keyType # " KEY-----\n";
        let ?trimmedPem = Text.stripEnd(headerTrimmedPem, #text(footer)) else return #err("Invalid PEM format: missing footer " # footer);
        #ok(Text.join("", Text.split(trimmedPem, #char('\n'))));
    };

};
