import Curve "./Curve";
import PublicKey "./PublicKey";
import Signature "./Signature";

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

        public func getPublicKey() : PublicKey {
            curve.mul_base(s);
        };

        /// Sign hashed by sec and rand return lower S signature (r, s) such that s < rHalf
        /// hashed : 32-byte SHA-256 value of a message.
        /// rand : 32-byte random value.
        public func signHashed(
            curve : Curve.Curve,
            hashed : Iter.Iter<Nat8>,
            rand : Iter.Iter<Nat8>,
        ) : ?Signature {
            if (sec == #fr(0)) Prelude.unreachable(); // type error
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

        /// Sign a message by sec and rand with SHA-256
        public func sign(curve : Curve.Curve, sec : SecretKey, msg : Iter.Iter<Nat8>, rand : Iter.Iter<Nat8>) : ?Signature {
            signHashed(curve, sec, sha2(msg).vals(), rand);
        };

        /// serialize to DER format
        /// https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html
        public func serializeSignatureDer(sig : Signature) : Blob {
            let buf = Buffer.Buffer<Nat8>(80);
            buf.add(0x30); // top marker
            buf.add(0); // modify later
            let append = func(x : Nat) {
                buf.add(0x02); // marker
                let a = Util.toBigEndian(x);
                let adj = if (a[0] >= 0x80) 1 else 0;
                buf.add(Nat8.fromNat(a.size() + adj));
                if (adj == 1) buf.add(0x00);
                for (e in a.vals()) {
                    buf.add(e);
                };
            };
            let (#fr(r), #fr(s)) = sig;
            append(r);
            append(s);
            let va = Buffer.toVarArray(buf);
            va[1] := Nat8.fromNat(va.size()) - 2;
            Blob.fromArrayMut(va);
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
