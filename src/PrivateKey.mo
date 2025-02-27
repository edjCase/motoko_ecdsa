import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Sha256 "mo:sha2/Sha256";

module {

    public class PrivateKey(
        d_ : Nat,
        curve_ : Curve.Curve,
    ) {
        public let d = d_;
        public let curve = curve_;

        public func getPublicKey() : PublicKey.PublicKey {
            let (#fp(x), #fp(y), #fp(_z)) = curve.mul_base(#fr(d));
            PublicKey.PublicKey(x, y, curve);
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

    public type GeneratePrivateKeyError = {
        #entropyError : Text;
    };

    public func generate(
        rand : Iter.Iter<Nat8>,
        curve : Curve.Curve,
    ) : Result.Result<PrivateKey, GeneratePrivateKeyError> {
        switch (curve.getExponent(rand)) {
            case (#fr(0)) #err(#entropyError("Random exponent was 0, try again"));
            case (#fr(s)) #ok(PrivateKey(s, curve));
        };
    };
};
