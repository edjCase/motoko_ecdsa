import Curve "./Curve";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Sha256 "mo:sha2/Sha256";
import Signature "./Signature";
import Util "./Util";
import ASN1 "mo:asn1";
import IterTools "mo:itertools/Iter";
import BaseX "mo:base-x-encoder";
import Nat "mo:new-base/Nat";
import Nat8 "mo:new-base/Nat8";
import Text "mo:new-base/Text";
import Result "mo:new-base/Result";
import KeyCommon "KeyCommon";

module {

    public type InputByteEncoding = KeyCommon.InputByteEncoding;

    public type OutputByteEncoding = {
        #der;
        #compressed;
        #uncompressed;
    };

    public type OutputTextFormat = KeyCommon.OutputTextFormat<OutputByteEncoding> or {
        #jwk;
    };

    public type InputTextFormat = KeyCommon.InputTextFormat;

    public class PublicKey(
        x_ : Nat,
        y_ : Nat,
        curve_ : Curve.Curve,
    ) {
        public let x = x_;
        public let y = y_;
        public let curve = curve_;

        public func equal(other : PublicKey) : Bool {
            return curve.kind == curve.kind and curve.isEqual((#fp(x), #fp(y), #fp(1)), (#fp(other.x), #fp(other.y), #fp(1)));
        };

        public func verify(
            msg : Iter.Iter<Nat8>,
            sig : Signature.Signature,
        ) : Bool {
            let hashedMsg = Sha256.fromIter(#sha256, msg).vals();
            verifyHashed(hashedMsg, sig);
        };

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

        public func toText(format : OutputTextFormat) : Text {
            switch (format) {
                case (#hex(hex)) {
                    let bytes = toBytes(hex.byteEncoding);
                    KeyCommon.toText(bytes, #hex(hex), false);
                };
                case (#base64(base64)) {
                    let bytes = toBytes(base64.byteEncoding);
                    KeyCommon.toText(bytes, #base64(base64), false);
                };
                case (#pem) {
                    let derBytes = toBytes(#der);
                    KeyCommon.toText(derBytes, #pem, false);
                };
                case (#jwk) {
                    // JWK format is specific to public keys, keep it in PublicKey module
                    // Get uncompressed point format (0x04 + X + Y coordinates)
                    let bytes = toBytes(#uncompressed);

                    // Extract X and Y coordinates (32 bytes each after 0x04 prefix)
                    let xCoord = Array.tabulate<Nat8>(32, func(i) { bytes[i + 1] });
                    let yCoord = Array.tabulate<Nat8>(32, func(i) { bytes[i + 33] });

                    // Base64URL encode coordinates
                    let xB64 = BaseX.toBase64(xCoord.vals(), true);
                    let yB64 = BaseX.toBase64(yCoord.vals(), true);

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

        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#der) {
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
                    ASN1.encodeDER(asn1);
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

    public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text> {
        switch (encoding) {
            case (#raw({ curve })) {
                let even = switch (bytes.next()) {
                    case (?0x02) true;
                    case (?0x03) false;
                    case (?0x04) {
                        // Uncompressed key
                        let n = 32;
                        let ?x = Util.toNatAsBigEndian(IterTools.take(bytes, n)) else return #err("Unable to parse x coordinate");
                        let ?y = Util.toNatAsBigEndian(IterTools.take(bytes, n)) else return #err("Unsable to parse y coordinate");
                        if (x >= curve.params.p) return #err("Invalid x coordinate, out of range");
                        if (y >= curve.params.p) return #err("Invalid y coordinate, out of range");
                        let pub = (#fp(x), #fp(y));
                        if (not curve.isValidAffine(pub)) return #err("Invalid x and y points, not on curve");
                        return #ok(PublicKey(x, y, curve));
                    };
                    case (?prefix) return #err("Invalid key prefix: " # Nat8.toText(prefix));
                    case (null) return #err("Not enough bytes for key");
                };
                // Compressed key
                let ?x = Util.toNatAsBigEndian(bytes) else return #err("Unable to parse x coordinate");
                if (x >= curve.params.p) return #err("Invalid x coordinate, out of range");
                let ?#fp(y) = curve.getYfromX(#fp(x), even) else return #err("Unable to calculate y coordinate");
                #ok(PublicKey(x, y, curve));
            };
            case (#der) {
                let asn1 = ASN1.decodeDER(bytes);
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
    public func fromText(value : Text, format : InputTextFormat) : Result.Result<PublicKey, Text> {
        KeyCommon.fromText<PublicKey>(value, format, fromBytes, false);
    };

};
