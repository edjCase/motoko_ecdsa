import Iter "mo:base/Iter";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Sha256 "mo:sha2/Sha256";
import Curve "./Curve";
import Util "util";
import Prelude "mo:base/Prelude";
import Result "mo:base/Result";
import PublicKey "PublicKey";

module {

  public type CurveKind = Curve.CurveKind;

  public type PublicKey = PublicKey.PublicKey;
  public func PublicKey(
    x : Nat,
    y : Nat,
    z : Nat,
    curveKind : CurveKind,
  ) : PublicKey = PublicKey.PublicKey(x, y, z, curveKind);

};
