import Curve "./Curve";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Util "Util";
import ASN1 "mo:asn1";
import Int "mo:new-base/Int";
import Iter "mo:new-base/Iter";
import Result "mo:new-base/Result";
import IterTools "mo:itertools/Iter";

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

    public func fromBytes(bytes : Iter.Iter<Nat8>, curve : Curve.Curve, encoding : SignatureEncoding) : Result.Result<Signature, Text> {
        switch (encoding) {
            case (#raw) {
                // Extract r and s values
                let rBytes = IterTools.take(bytes, 32);
                let sBytes = IterTools.take(bytes, 32);

                let ?r = Util.toNatAsBigEndian(rBytes) else return #err("Invalid signature: failed to decode r from bytes");
                let ?s = Util.toNatAsBigEndian(sBytes) else return #err("Invalid signature: failed to decode s from bytes");

                #ok(Signature(r, s, curve));
            };
            case (#der) {
                switch (ASN1.decodeDER(bytes)) {
                    case (#err(e)) return #err("Invalid DER format: " # e);
                    case (#ok(#sequence(sequence))) {
                        if (sequence.size() != 2) return #err("Invalid DER format: expected 2 elements");
                        let #integer(r) = sequence[0] else return #err("Invalid DER format: expected integer for r");
                        if (r < 0) return #err("Invalid DER format: r is negative");

                        let #integer(s) = sequence[1] else return #err("Invalid DER format: expected integer for s");
                        if (s < 0) return #err("Invalid DER format: s is negative");
                        return #ok(Signature(Int.abs(r), Int.abs(s), curve));
                    };
                    case (#ok(_)) return #err("Invalid DER format: expected sequence");
                };
            };

        };

    };
};
