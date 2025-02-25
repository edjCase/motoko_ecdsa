import Curve "./Curve";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";
import Util "util";

module {

    public class Signature(r_ : Nat, s_ : Nat, curveKind : Curve.CurveKind) {
        public let curve = Curve.Curve(curveKind);
        public let (r, s) = if (curve.Fr.toNat(#fr(s_)) < curve.params.rHalf) {
            (r_, s_);
        } else (r_, curve.Fr.neg(s_));
    };

    /// convert a signature to lower S signature
    public func normalize(curve : Curve.Curve, signature : Signature) : Signature {};

    /// deserialize DER to signature
    public func fromDerBytes(b : Blob) : ?Signature {
        let a = Blob.toArray(b);
        if (a.size() <= 2 or a[0] != 0x30) return null;
        if (a.size() != Nat8.toNat(a[1]) + 2) return null;
        let read = func(a : [Nat8], begin : Nat) : ?(Nat, Nat) {
            if (a.size() < begin + 2) return null;
            if (a[begin] != 0x02) return null;
            let n = Nat8.toNat(a[begin + 1]);
            if (a.size() < begin + 1 + n) return null;
            let top = a[begin + 2];
            if (top >= 0x80) return null;
            if (top == 0 and n > 1 and (a[begin + 2 + 1] & 0x80) == 0) return null;
            var v = 0;
            var i = 0;
            while (i < n) {
                v := v * 256 + Nat8.toNat(a[begin + 2 + i]);
                i += 1;
            };
            ?(n + 2, v);
        };
        return switch (read(a, 2)) {
            case (null) null;
            case (?(read1, r)) {
                switch (read(a, 2 + read1)) {
                    case (null) null;
                    case (?(read2, s)) {
                        if (a.size() != 2 + read1 + read2) return null;
                        ?(#fr(r), #fr(s));
                    };
                };
            };
        };
    };

    public func fromRawBytes(signatureBlob : Blob) : ?Signature {
        let signatureBytes = Blob.toArray(signatureBlob);

        // JWT ECDSA signatures are 64 bytes - 32 bytes for r and 32 bytes for s
        if (signatureBytes.size() != 64) {
            return null;
        };

        // Extract r and s values
        let rBytes = Array.subArray(signatureBytes, 0, 32);
        let sBytes = Array.subArray(signatureBytes, 32, 32);

        let r = Util.toNatAsBigEndian(rBytes.vals());
        let s = Util.toNatAsBigEndian(sBytes.vals());

        // Return as Curve.FrElt values
        ?(#fr(r), #fr(s));
    };

};
