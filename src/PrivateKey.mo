import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";
import Iter "mo:base/Iter";
import Debug "mo:base/Debug";
import Prelude "mo:base/Prelude";
import Sha256 "mo:sha2/Sha256";
import Util "Util";
import ASN1 "mo:asn1";
import IterTools "mo:itertools/Iter";
import PeekableIter "mo:itertools/PeekableIter";
import BaseX "mo:base-x-encoder";
import Text "mo:new-base/Text";
import Result "mo:new-base/Result";

module {

    public type InputKeyEncoding = {
        #der;
        #raw : {
            curve : Curve.Curve;
        };
    };

    public type OutputKeyEncoding = {
        #der;
        #raw;
    };

    public type OutputTextFormat = {
        #pem;
        #base64 : {
            byteEncoding : OutputKeyEncoding;
            isUriSafe : Bool;
        };
        #hex : {
            byteEncoding : OutputKeyEncoding;
            format : BaseX.HexOutputFormat;
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
                case (#zero) Debug.trap("Unable to get public key from private key, point was zero");
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
            let hashedMsg = Sha256.fromIter(#sha256, msg);
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
                case (#hex({ byteEncoding; format })) {
                    let bytes = toBytes(byteEncoding);
                    BaseX.toHex(bytes.vals(), format);
                };
                case (#base64({ byteEncoding; isUriSafe })) {
                    let bytes = toBytes(byteEncoding);
                    BaseX.toBase64(bytes.vals(), isUriSafe);
                };
                case (#pem) {
                    let derBytes = toBytes(#der);
                    let base64 = BaseX.toBase64(derBytes.vals(), false);

                    let iter = PeekableIter.fromIter(base64.chars());
                    var formatted = Text.fromIter(IterTools.take(iter, 64));
                    while (iter.peek() != null) {
                        formatted #= "\n" # Text.fromIter(IterTools.take(iter, 64));
                    };

                    "-----BEGIN PRIVATE KEY-----\n"
                    # formatted
                    # "\n-----END PRIVATE KEY-----";
                };
            };
        };

        public func toBytes(encoding : OutputKeyEncoding) : [Nat8] {
            switch (encoding) {
                case (#der) {
                    // For PKCS#8 DER format
                    let privateKeyBytes = toBytes(#raw);
                    let publicKeyBytes = getPublicKey().toBytes(#uncompressed);

                    let curveOid = switch (curve.kind) {
                        case (#secp256k1) [1, 3, 132, 0, 10];
                        case (#prime256v1) [1, 2, 840, 10045, 3, 1, 7];
                    };

                    // Create ASN.1 structure for EC private key
                    let ecPrivateKey : ASN1.ASN1Value = #sequence([
                        #integer(1), // EC private key version
                        #octetString(privateKeyBytes),
                        #null_,
                        #bitString({ data = publicKeyBytes; unusedBits = 0 }),
                    ]);

                    let ecPrivateKeyDerBytes = switch (ASN1.encodeDER(ecPrivateKey)) {
                        case (#err(_)) Prelude.unreachable(); // TODO?
                        case (#ok(derBytes)) derBytes;
                    };

                    // Wrap in PKCS#8 structure
                    let pkcs8 : ASN1.ASN1Value = #sequence([
                        #integer(0), // PKCS#8 version
                        #sequence([
                            #objectIdentifier([1, 2, 840, 10045, 2, 1]), // EC algorithm OID
                            #objectIdentifier(curveOid),
                        ]),
                        #octetString(ecPrivateKeyDerBytes),
                    ]);

                    let #ok(bytes) = ASN1.encodeDER(pkcs8) else Prelude.unreachable(); // TODO?
                    bytes;
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

    public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputKeyEncoding) : Result.Result<PrivateKey, Text> {
        switch (encoding) {
            case (#raw({ curve })) {

                let ?d = Util.toNatAsBigEndian(IterTools.take(bytes, 32)) else return #err("Invalid private key: failed to decode d from bytes");

                // Validate the key is in range for the curve
                if (d == 0 or d >= curve.params.r) {
                    return #err("Invalid private key: d is out of range for the curve");
                };

                #ok(PrivateKey(d, curve));
            };
            case (#der) {
                switch (ASN1.decodeDER(bytes)) {
                    case (#err(e)) return #err("Invalid DER format: " # e);
                    case (#ok(#sequence(sequence))) {
                        if (sequence.size() < 3) return #err("Invalid DER format: expected at least 3 elements");

                        // First element is version (should be 1)
                        let #integer(1) = sequence[0] else return #err("Invalid DER format: expected version 1");

                        // Second element is the algorithm identifier
                        let #sequence(algorithmIdSequence) = sequence[1] else return #err("Invalid DER format: expected algorithm identifier");
                        if (algorithmIdSequence.size() != 2) return #err("Invalid DER format: expected algorithm identifier with 2 elements");
                        let #objectIdentifier(algorithmOid) = algorithmIdSequence[0] else return #err("Invalid DER format: expected algorithm OID");
                        let #null_ = algorithmIdSequence[1] else return #err("Invalid DER format: expected null for algorithm identifier parameter");
                        let curve = if (algorithmOid == [1, 3, 132, 0, 10]) {
                            Curve.secp256k1();
                        } else if (algorithmOid == [1, 2, 840, 10045, 3, 1, 7]) {
                            Curve.prime256v1();
                        } else {
                            return #err("Invalid DER format: unsupported algorithm OID - " # debug_show (algorithmOid));
                        };

                        // Third element is the private key as OCTET STRING
                        let #octetString(keyBytes) = sequence[2] else return #err("Invalid DER format: expected private key as OCTET STRING");

                        // TODO private key attributes?

                        // Validate the key
                        fromBytes(keyBytes.vals(), #raw({ curve }));
                    };
                    case (#ok(_)) return #err("Invalid DER format: expected sequence");
                };
            };
        };
    };
};
