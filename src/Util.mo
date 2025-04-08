import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import NatX "mo:xtended-numbers/NatX";
import Iter "mo:new-base/Iter";

module {
  // [0x12, 0x34] : [Nat] => 0x1234
  public func toNatAsBigEndian(iter : Iter.Iter<Nat8>) : ?Nat = NatX.decodeNat(iter, #msb);
  /// 0x1234 => [0x12, 0x34], 0 => [0]
  public func toBigEndian(x : Nat) : [Nat8] {
    var buf = Buffer.Buffer<Nat8>(32);
    NatX.encodeNat(buf, x, #msb);
    Buffer.toArray(buf);
  };
  /// (5, 0x1234) => [0x00, 0x00, 0x00, 0x12, 0x34]
  public func toBigEndianPad(len : Nat, x : Nat) : [Nat8] {
    var buf = Buffer.Buffer<Nat8>(len);
    NatX.encodeNat(buf, x, #msb);
    while (buf.size() < len) {
      buf.insert(0, 0x00);
    };
    Buffer.toArray(buf);
  };
};
