import Curve "./Curve";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Util "util";

module {
    public class Signature(r_ : Nat, s_ : Nat, curve_ : Curve.Curve) {
        public let curve = curve_;

        /// convert a signature to lower S signature
        // TODO do this automatically or on demand?
        public let (r, s) : (Nat, Nat) = if (curve.Fr.toNat(#fr(s_)) < curve.params.rHalf) {
            (r_, s_);
        } else {
            let #fr(s) = curve.Fr.neg(#fr(s_));
            (r_, s);
        };

        /// serialize to DER format
        /// https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html
        public func toBytesDer() : [Nat8] {
            let buf = Buffer.Buffer<Nat8>(80);
            buf.add(0x30); // top marker
            buf.add(0); // modify size later
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
            append(r);
            append(s);
            buf.put(1, Nat8.fromNat(buf.size() - 2)); // set size
            Buffer.toArray(buf);
        };
    };

    // TODO DER needs to evaluate curvekind
    // public func fromDerBytes(b : Blob) : ?Signature {
    //     let a = Blob.toArray(b);
    //     if (a.size() <= 2 or a[0] != 0x30) return null;
    //     if (a.size() != Nat8.toNat(a[1]) + 2) return null;
    //     let read = func(a : [Nat8], begin : Nat) : ?(Nat, Nat) {
    //         if (a.size() < begin + 2) return null;
    //         if (a[begin] != 0x02) return null;
    //         let n = Nat8.toNat(a[begin + 1]);
    //         if (a.size() < begin + 1 + n) return null;
    //         let top = a[begin + 2];
    //         if (top >= 0x80) return null;
    //         if (top == 0 and n > 1 and (a[begin + 2 + 1] & 0x80) == 0) return null;
    //         var v = 0;
    //         var i = 0;
    //         while (i < n) {
    //             v := v * 256 + Nat8.toNat(a[begin + 2 + i]);
    //             i += 1;
    //         };
    //         ?(n + 2, v);
    //     };
    //     return switch (read(a, 2)) {
    //         case (null) null;
    //         case (?(read1, r)) {
    //             switch (read(a, 2 + read1)) {
    //                 case (null) null;
    //                 case (?(read2, s)) {
    //                     if (a.size() != 2 + read1 + read2) return null;
    //                     ?Signature(r, s, curveKind);
    //                 };
    //             };
    //         };
    //     };
    // };

    public func fromRawBytes(signatureBlob : Blob, curve : Curve.Curve) : ?Signature {
        let signatureBytes = Blob.toArray(signatureBlob);

        if (signatureBytes.size() != 64) {
            return null;
        };

        // Extract r and s values
        let rBytes = Array.subArray(signatureBytes, 0, 32);
        let sBytes = Array.subArray(signatureBytes, 32, 32);

        let r = Util.toNatAsBigEndian(rBytes.vals());
        let s = Util.toNatAsBigEndian(sBytes.vals());

        ?Signature(r, s, curve);
    };

};
