/// Internal byte-conversion helpers used across the codebase.
///
/// ```motoko name=import
/// import Util "mo:ecdsa/Util";
/// ```

import Iter "mo:core@2/Iter";
import List "mo:core@2/List";
import Nat8 "mo:core@2/Nat8";

import Buffer "mo:buffer@0";
import NatX "mo:xtended-numbers@2/NatX";

module {
  /// Reads a big-endian unsigned integer from `iter`. Returns `null` if
  /// the iterator is empty.
  // [0x12, 0x34] : [Nat] => 0x1234
  public func toNatAsBigEndian(iter : Iter.Iter<Nat8>) : ?Nat = NatX.fromNatBytes(iter, #msb);
  /// Encodes `x` as the shortest big-endian byte sequence (a single `0`
  /// byte when `x == 0`).
  /// 0x1234 => [0x12, 0x34], 0 => [0]
  public func toBigEndian(x : Nat) : [Nat8] {
    let buf = List.empty<Nat8>();
    NatX.toNatBytesBuffer(Buffer.fromList(buf), x, #msb);
    buf.toArray();
  };
  /// Encodes `x` as a big-endian byte sequence of exactly `len` bytes,
  /// left-padding with zeros if needed. Truncation is not handled; the
  /// caller must ensure `x` fits in `len` bytes.
  /// (5, 0x1234) => [0x00, 0x00, 0x00, 0x12, 0x34]
  public func toBigEndianPad(len : Nat, x : Nat) : [Nat8] {
    let buf = List.empty<Nat8>();
    NatX.toNatBytesBuffer(Buffer.fromList(buf), x, #msb);
    if (buf.size() < len) {
      let paddedBuffer = List.repeat<Nat8>(0x00, len - buf.size());
      paddedBuffer.addAll(buf.values());
      return paddedBuffer.toArray();

    };
    buf.toArray();
  };
};
