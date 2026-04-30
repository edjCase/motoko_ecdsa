import Iter "mo:core@2/Iter";
import List "mo:core@2/List";
import Nat8 "mo:core@2/Nat8";

import Buffer "mo:buffer@0";
import NatX "mo:xtended-numbers@2/NatX";

module {
  // [0x12, 0x34] : [Nat] => 0x1234
  public func toNatAsBigEndian(iter : Iter.Iter<Nat8>) : ?Nat = NatX.fromNatBytes(iter, #msb);
  /// 0x1234 => [0x12, 0x34], 0 => [0]
  public func toBigEndian(x : Nat) : [Nat8] {
    var buf = List.empty<Nat8>();
    NatX.toNatBytesBuffer(Buffer.fromList(buf), x, #msb);
    buf.toArray();
  };
  /// (5, 0x1234) => [0x00, 0x00, 0x00, 0x12, 0x34]
  public func toBigEndianPad(len : Nat, x : Nat) : [Nat8] {
    var buf = List.empty<Nat8>();
    NatX.toNatBytesBuffer(Buffer.fromList(buf), x, #msb);
    if (buf.size() < len) {
      let paddedBuffer = List.repeat<Nat8>(0x00, len - buf.size());
      paddedBuffer.addAll(buf.values());
      return paddedBuffer.toArray();

    };
    buf.toArray();
  };
};
