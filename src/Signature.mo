import Curve "./Curve";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Util "Util";
import ASN1 "mo:asn1";
import Int "mo:new-base/Int";
import Iter "mo:new-base/Iter";
import Result "mo:new-base/Result";
import Nat "mo:new-base/Nat";
import IterTools "mo:itertools/Iter";
import BaseX "mo:base-x-encoder";
import NatX "mo:xtended-numbers/NatX";

module {
    public type InputByteEncoding = {
        #der;
        #raw;
    };

    public type OutputByteEncoding = {
        #der;
        #raw;
    };

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

    public type InputTextFormat = {
        #base64 : {
            byteEncoding : InputByteEncoding;
        };
        #hex : {
            byteEncoding : InputByteEncoding;
            format : BaseX.HexInputFormat;
        };
    };

    public class Signature(r_ : Nat, s_ : Nat, curve_ : Curve.Curve) {
        public let curve = curve_;

        public let original_r = r_;
        public let original_s = s_;

        // Normalized values for cryptographic operations
        public let (r, s) : (Nat, Nat) = if (curve.Fr.toNat(#fr(s_)) < curve.params.rHalf) {
            (r_, s_);
        } else {
            let #fr(s) = curve.Fr.neg(#fr(s_));
            (r_, s);
        };

        public func equal(other : Signature) : Bool {
            return curve.equal(other.curve) and r == other.r and s == other.s;
        };

        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#raw) {
                    let size = switch (curve.getBitSize()) {
                        case (#b256) 32;
                    };

                    let buf = Buffer.Buffer<Nat8>(64);
                    let encodeAndPad = func(value : Nat) {
                        let natBuffer = Buffer.Buffer<Nat8>(size);
                        NatX.encodeNat(natBuffer, value, #msb);
                        let padding : Nat = size - natBuffer.size();
                        // Left-pad with zeros if needed
                        if (padding > 0) {
                            for (i in Nat.range(0, padding)) {
                                buf.add(0);
                            };
                        };
                        buf.append(natBuffer);
                    };

                    // Encode r
                    encodeAndPad(original_r);
                    // Encode s
                    encodeAndPad(original_s);

                    Buffer.toArray(buf);
                };
                case (#der) {
                    let asn1Value : ASN1.ASN1Value = #sequence([#integer(original_r), #integer(original_s)]);
                    ASN1.encodeDER(asn1Value);
                };
            };
        };

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

    public func fromBytes(bytes : Iter.Iter<Nat8>, curve : Curve.Curve, encoding : InputByteEncoding) : Result.Result<Signature, Text> {
        switch (encoding) {
            case (#raw) {
                // Extract r and s values
                let rBytes = IterTools.take(bytes, 32);

                let ?r = Util.toNatAsBigEndian(rBytes) else return #err("Invalid signature: failed to decode r from bytes");
                let sBytes = IterTools.take(bytes, 32);
                let ?s = Util.toNatAsBigEndian(sBytes) else return #err("Invalid signature: failed to decode s from bytes");

                #ok(Signature(r, s, curve));
            };
            case (#der) {
                switch (ASN1.decodeDER(bytes)) {
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
