import Nat8 "mo:core@1/Nat8";
import Buffer "mo:buffer@0";
import NatX "mo:xtended-numbers@2/NatX";
import Iter "mo:core@1/Iter";
import List "mo:core@1/List";

module {
  // [0x12, 0x34] : [Nat] => 0x1234
  public func toNatAsBigEndian(iter : Iter.Iter<Nat8>) : ?Nat = NatX.fromNatBytes(iter, #msb);
  /// 0x1234 => [0x12, 0x34], 0 => [0]
  public func toBigEndian(x : Nat) : [Nat8] {
    var buf = List.empty<Nat8>();
    NatX.toNatBytesBuffer(Buffer.fromList(buf), x, #msb);
    List.toArray(buf);
  };
  /// (5, 0x1234) => [0x00, 0x00, 0x00, 0x12, 0x34]
  public func toBigEndianPad(len : Nat, x : Nat) : [Nat8] {
    var buf = List.empty<Nat8>();
    NatX.toNatBytesBuffer(Buffer.fromList(buf), x, #msb);
    if (List.size(buf) < len) {
      let paddedBuffer = List.repeat<Nat8>(0x00, len - List.size(buf));
      List.addAll(paddedBuffer, List.values(buf));
      return List.toArray(paddedBuffer);

    };
    List.toArray(buf);
  };
};
