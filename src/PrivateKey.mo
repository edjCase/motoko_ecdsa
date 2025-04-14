import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";
import Iter "mo:base/Iter";
import Nat8 "mo:base/Nat8";
import Sha256 "mo:sha2/Sha256";
import Util "Util";
import ASN1 "mo:asn1";
import IterTools "mo:itertools/Iter";
import Text "mo:new-base/Text";
import Result "mo:new-base/Result";
import Runtime "mo:new-base/Runtime";
import KeyCommon "KeyCommon";

module {

    public type PEMInputByteEncoding = {
        #sec1 : {
            curve : Curve.Curve;
        }; // SEC1 format
        #pkcs8; // PKCS#8 format
    };

    public type InputByteEncoding = PEMInputByteEncoding or KeyCommon.CommonInputByteEncoding;

    public type PEMOutputByteEncoding = {
        #sec1; // SEC1 format
        #pkcs8; // PKCS#8 format
    };

    public type OutputByteEncoding = PEMOutputByteEncoding or {
        #raw;
    };

    public type OutputTextFormat = KeyCommon.CommonOutputTextFormat<OutputByteEncoding> or {
        #pem : {
            byteEncoding : PEMOutputByteEncoding;
        };
    };

    public type InputTextFormat = KeyCommon.CommonInputTextFormat<InputByteEncoding> or {
        #pem : {
            byteEncoding : PEMInputByteEncoding;
        };
    };

    public class PrivateKey(
        d_ : Nat,
        curve_ : Curve.Curve,
    ) {
        public let d = d_;
        public let curve = curve_;

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
                    ASN1.encodeDER(ecPrivateKey);
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

                    ASN1.encodeDER(pkcs8);
                };

                case (#raw) {
                    let n = 32; // 32 bytes for 256-bit curves
                    Util.toBigEndianPad(n, curve.Fp.toNat(#fp(d)));
                };
            };
        };

    };

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

    public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PrivateKey, Text> {
        switch (encoding) {
            case (#raw({ curve })) {

                let ?d = Util.toNatAsBigEndian(IterTools.take(bytes, 32)) else return #err("Invalid private key: failed to decode d from bytes");

                // Validate the key is in range for the curve
                if (d == 0 or d >= curve.params.r) {
                    return #err("Invalid private key: d is out of range for the curve");
                };

                #ok(PrivateKey(d, curve));
            };
            case (#sec1({ curve })) {
                let keyAsn1 = switch (ASN1.decodeDER(bytes)) {
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
                switch (ASN1.decodeDER(bytes)) {
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
