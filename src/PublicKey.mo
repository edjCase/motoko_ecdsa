import Curve "./Curve";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Sha256 "mo:sha2/Sha256";
import Signature "./Signature";
import Util "./Util";

module {

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
            let #fr(hash_z) = curve.getExponent(hashedMsg);
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

        /// return 0x04 + bigEndian(x) + bigEndian(y)
        public func toBytesUncompressed() : [Nat8] {
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

        /// return 0x02 + bigEndian(x) if y is even
        /// return 0x03 + bigEndian(x) if y is odd
        public func toBytesCompressed() : [Nat8] {
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
    };

    public func fromBytes(bytes : [Nat8], curve : Curve.Curve) : ?PublicKey {
        switch (bytes.size()) {
            case (65) fromBytesUncompressed(bytes, curve);
            case (33) fromBytesCompressed(bytes, curve);
            case (_) return null;
        };
    };

    private func fromBytesUncompressed(bytes : [Nat8], curve : Curve.Curve) : ?PublicKey {
        if (bytes[0] != 0x04) return null;
        class range(begin : Nat, size : Nat) {
            var i = 0;
            public func next() : ?Nat8 {
                if (i == size) return null;
                let ret = ?bytes[begin + i];
                i += 1;
                ret;
            };
        };
        let n = 32;
        let x = Util.toNatAsBigEndian(range(1, n));
        let y = Util.toNatAsBigEndian(range(1 + n, n));
        if (x >= curve.params.p) return null;
        if (y >= curve.params.p) return null;
        let pub = (#fp(x), #fp(y));
        if (not curve.isValidAffine(pub)) return null;
        ?PublicKey(x, y, curve);
    };

    private func fromBytesCompressed(bytes : [Nat8], curve : Curve.Curve) : ?PublicKey {
        let iter = bytes.vals();
        let even = switch (iter.next()) {
            case (?0x02) true;
            case (?0x03) false;
            case _ return null;
        };
        let x = Util.toNatAsBigEndian(iter);
        if (x >= curve.params.p) return null;
        let ?#fp(y) = curve.getYfromX(#fp(x), even) else return null;
        ?PublicKey(x, y, curve);
    };
};
