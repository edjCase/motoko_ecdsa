import Curve "./Curve";
import Iter "mo:base/Iter";
import Signature "./Signature";

module {

    public class PublicKey(
        x_ : Nat,
        y_ : Nat,
        z_ : Nat,
        curveKind_ : Curve.CurveKind,
    ) {
        public let x = x_;
        public let y = y_;
        public let z = z_;
        public let curveKind = curveKind_;
        public let curve = Curve.Curve(curveKind);

        /// verify a tuple of pub, hashed, and lowerS sig
        public func verifyHashed(
            pub : PublicKey,
            hashed : Iter.Iter<Nat8>,
            signature : Signature.Signature,
        ) : Bool {
            if (not curve.isValid(pub)) return false;
            if (r == #fr(0)) return false;
            if (s == #fr(0)) return false;
            if (curve.Fr.toNat(s) >= curve.params.rHalf) return false;
            let z = getExponent(curve, hashed);
            let w = curve.Fr.inv(s);
            let u1 = curve.Fr.mul(z, w);
            let u2 = curve.Fr.mul(r, w);
            let R = curve.add(curve.mul_base(u1), curve.mul(pub, u2));
            switch (curve.fromJacobi(R)) {
                case (#zero) false;
                case (#affine(x, _)) curve.Fr.fromNat(curve.Fp.toNat(x)) == r;
            };
        };
        // verify a tuple of pub, msg, and sig
        public func verify(curve : Curve.Curve, pub : PublicKey, msg : Iter.Iter<Nat8>, sig : Signature) : Bool {
            verifyHashed(curve, pub, sha2(msg).vals(), sig);
        };

        /// return 0x04 + bigEndian(x) + bigEndian(y)
        public func serializeUncompressed(curve : Curve.Curve, (x, y) : Curve.Affine) : Blob {
            let prefix = 0x04 : Nat8;
            let n = 32;
            let x_bytes = Util.toBigEndianPad(n, curve.Fp.toNat(x));
            let y_bytes = Util.toBigEndianPad(n, curve.Fp.toNat(y));
            let ith = func(i : Nat) : Nat8 {
                if (i == 0) {
                    prefix;
                } else if (i <= n) {
                    x_bytes[i - 1];
                } else {
                    y_bytes[i - 1 - n];
                };
            };
            let ar = Array.tabulate<Nat8>(1 + n * 2, ith);
            Blob.fromArray(ar);
        };

        /// return 0x02 + bigEndian(x) if y is even
        /// return 0x03 + bigEndian(x) if y is odd
        public func serializePublicKeyCompressed(curve : Curve.Curve, (x, y) : Curve.Affine) : Blob {
            let prefix : Nat8 = if ((curve.Fp.toNat(y) % 2) == 0) 0x02 else 0x03;
            let n = 32;
            let x_bytes = Util.toBigEndianPad(n, curve.Fp.toNat(x));
            let ith = func(i : Nat) : Nat8 {
                if (i == 0) {
                    prefix;
                } else {
                    x_bytes[i - 1];
                };
            };
            let ar = Array.tabulate<Nat8>(1 + n, ith);
            Blob.fromArray(ar);
        };
    };

    /// Deserialize an uncompressed public key
    public func fromBytesUncompressed(curve : Curve.Curve, b : Blob) : ?PublicKey {
        if (b.size() != 65) return null;
        let a = Blob.toArray(b);
        if (a[0] != 0x04) return null;
        class range(a : [Nat8], begin : Nat, size : Nat) {
            var i = 0;
            public func next() : ?Nat8 {
                if (i == size) return null;
                let ret = ?a[begin + i];
                i += 1;
                ret;
            };
        };
        let n = 32;
        let x = Util.toNatAsBigEndian(range(a, 1, n));
        let y = Util.toNatAsBigEndian(range(a, 1 + n, n));
        if (x >= curve.params.p) return null;
        if (y >= curve.params.p) return null;
        let pub = (#fp(x), #fp(y));
        if (not curve.isValidAffine(pub)) return null;
        ?(#fp(x), #fp(y), #fp(1));
    };

    public func fromBytesCompressed(curve : Curve.Curve, b : Blob) : ?PublicKey {
        let n = 32;
        if (b.size() != n + 1) return null;
        let iter = b.vals();
        let even = switch (iter.next()) {
            case (?0x02) true;
            case (?0x03) false;
            case _ return null;
        };
        let x_ = Util.toNatAsBigEndian(iter);
        if (x_ >= curve.params.p) return null;
        let x = #fp(x_);
        return switch (curve.getYfromX(x, even)) {
            case (null) null;
            case (?y) ?(x, y, #fp(1));
        };
    };
};
