import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";
import Iter "mo:base/Iter";

module {

    public class PrivateKey(
        r_ : Nat,
        s_ : Nat,
        curveKind_ : Curve.CurveKind,
    ) {
        public let r = r_;
        public let s = s_;
        public let curveKind = curveKind_;
        public let curve = Curve.Curve(curveKind);

        public func getPublicKey() : PublicKey.PublicKey {
            curve.mul_base(s);
        };

        public func sign(
            msg : Iter.Iter<Nat8>,
            rand : Iter.Iter<Nat8>,
        ) : ?Signature.Signature {
            signHashed(curve, sec, sha2(msg).vals(), rand);
        };

        public func signHashed(
            hashed : Iter.Iter<Nat8>,
            rand : Iter.Iter<Nat8>,
        ) : ?Signature.Signature {
            let k = getExponent(curve, rand);
            let x = switch (curve.fromJacobi(curve.mul_base(k))) {
                case (#zero) return null; // k was 0, bad luck with rand
                case (#affine(x, _)) x;
            };
            let r = curve.Fr.fromNat(curve.Fp.toNat(x));
            if (r == #fr(0)) return null; // x was 0 mod r, bad luck with rand
            let z = getExponent(curve, hashed);
            // s = (r * sec + z) / k
            let s = curve.Fr.div(curve.Fr.add(curve.Fr.mul(r, sec), z), k);
            ?normalizeSignature(curve, (r, s));
        };

    };

    public type GeneratePrivateKeyError = {
        #entropyError : Text;
    };

    public func generate(
        rand : [Nat8],
        kind : CurveKind,
    ) : Result.Result<PrivateKey, GeneratePrivateKeyError> {
        if (rand.size() != 32) {
            return #err(#entropyError("Random input must be 32 bytes"));
        };
        let s = switch (getExponent(curve, rand)) {
            case (#fr(0)) #err(#entropyError("Random exponent was 0, try again"));
            case (s) #ok(PrivateKey(s));
        };
    };
};
