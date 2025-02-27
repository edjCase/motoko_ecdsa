import Curve "./Curve";
import PublicKeyModule "PublicKey";

module {

  public type CurveKind = Curve.CurveKind;

  public type PublicKey = PublicKeyModule.PublicKey;
  public func PublicKey(
    x : Nat,
    y : Nat,
    curve : Curve.Curve,
  ) : PublicKey = PublicKeyModule.PublicKey(x, y, curve);

};
