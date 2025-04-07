import Curve "./Curve";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Util "Util";
import ASN1 "mo:asn1";
import Int "mo:new-base/Int";

module {
    public type SignatureEncoding = {
        #der;
        #raw;
    };

    public class Signature(r_ : Nat, s_ : Nat, curve_ : Curve.Curve) {
        public let curve = curve_;

        public let original_r = r_;
        public let original_s = s_;

        // Normalized values for cryptographic operations
        public let (r, s) : (Nat, Nat) = if (curve.Fr.toNat(#fr(s_)) < curve.params.rHalf) {
            (r_, s_);
        } else {
            let #fr(s) = curve.Fr.neg(#fr(s_));
            (r_, s);
        };

        public func equal(other : Signature) : Bool {
            return curve.equal(other.curve) and r == other.r and s == other.s;
        };

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
            append(original_r);
            append(original_s);
            buf.put(1, Nat8.fromNat(buf.size() - 2)); // set size
            Buffer.toArray(buf);
        };
    };

    public func fromBytes(bytes : [Nat8], curve : Curve.Curve, encoding : SignatureEncoding) : ?Signature {
        switch (encoding) {
            case (#raw) {
                if (bytes.size() != 64) {
                    return null;
                };

                // Extract r and s values
                let rBytes = Array.subArray(bytes, 0, 32);
                let sBytes = Array.subArray(bytes, 32, 32);

                let r = Util.toNatAsBigEndian(rBytes.vals());
                let s = Util.toNatAsBigEndian(sBytes.vals());

                ?Signature(r, s, curve);
            };
            case (#der) {
                switch (ASN1.decodeDER(bytes.vals())) {
                    case (#err(e)) return null;
                    case (#ok(#sequence(sequence))) {
                        if (sequence.size() != 2) return null;
                        let #integer(r) = sequence[0] else return null;
                        if (r < 0) return null;

                        let #integer(s) = sequence[1] else return null;
                        if (s < 0) return null;
                        return ?Signature(Int.abs(r), Int.abs(s), curve);
                    };
                    case (#ok(_)) return null; // Invalid DER format
                };
            };

        };

    };
};
