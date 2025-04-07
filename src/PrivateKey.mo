import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";
import Iter "mo:base/Iter";
import Debug "mo:base/Debug";
import Sha256 "mo:sha2/Sha256";
import Util "Util";
import ASN1 "mo:asn1";

module {

    public type KeyEncoding = {
        #der;
        #raw : {
            curve : Curve.Curve;
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
        ) : ?Signature.Signature {
            let hashedMsg = Sha256.fromIter(#sha256, msg);
            signHashed(hashedMsg.vals(), rand);
        };

        public func signHashed(
            hashedMsg : Iter.Iter<Nat8>,
            rand : Iter.Iter<Nat8>,
        ) : ?Signature.Signature {
            let k = curve.getExponent(rand);
            let x = switch (curve.fromJacobi(curve.mul_base(k))) {
                case (#zero) return null; // k was 0, bad luck with rand
                case (#affine(x, _)) x;
            };
            let #fr(r) = curve.Fr.fromNat(curve.Fp.toNat(x));
            if (r == 0) return null; // x was 0 mod r, bad luck with rand
            let z = curve.getExponent(hashedMsg);
            // s = (r * sec + z) / k
            let #fr(s) = curve.Fr.div(curve.Fr.add(curve.Fr.mul(#fr(r), #fr(d)), z), k);
            ?Signature.Signature(r, s, curve);
        };

    };

    public func generate(
        entropy : Iter.Iter<Nat8>,
        curve : Curve.Curve,
    ) : ?PrivateKey {
        switch (curve.getExponent(entropy)) {
            case (#fr(0)) null; // bad luck with entropy
            case (#fr(s)) ?PrivateKey(s, curve);
        };
    };

    public func fromBytes(bytes : [Nat8], encoding : KeyEncoding) : ?PrivateKey {
        switch (encoding) {
            case (#raw({ curve })) {
                // For raw format, just convert bytes to a Nat
                // Assuming standard EC key size (32 bytes for most curves)
                if (bytes.size() != 32) {
                    return null;
                };

                let d = Util.toNatAsBigEndian(bytes.vals());

                // Validate the key is in range for the curve
                if (d == 0 or d >= curve.params.r) {
                    return null;
                };

                ?PrivateKey(d, curve);
            };
            case (#der) {
                switch (ASN1.decodeDER(bytes.vals())) {
                    case (#err(_)) return null;
                    case (#ok(#sequence(sequence))) {
                        if (sequence.size() < 3) return null;

                        // First element is version (should be 1)
                        let #integer(1) = sequence[0] else return null;

                        // Second element is the algorithm identifier
                        let #sequence(algorithmIdSequence) = sequence[1] else return null;
                        if (algorithmIdSequence.size() != 2) return null;
                        let #objectIdentifier(algorithmOid) = algorithmIdSequence[0] else return null;
                        let #null_ = algorithmIdSequence[1] else return null;
                        let curve = if (algorithmOid == [1, 3, 132, 0, 10]) {
                            Curve.secp256k1();
                        } else if (algorithmOid == [1, 2, 840, 10045, 3, 1, 7]) {
                            Curve.prime256v1();
                        } else {
                            return null; // Unsupported curve
                        };

                        // Third element is the private key as OCTET STRING
                        let #octetString(keyBytes) = sequence[2] else return null;

                        // TODO private key attributes?

                        // Validate the key
                        fromBytes(keyBytes, #raw({ curve }));
                    };
                    case (#ok(_)) return null; // Invalid DER format
                };
            };
        };
    };
};
