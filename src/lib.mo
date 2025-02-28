import Curve "./Curve";
import PublicKeyModule "PublicKey";
import PrivateKeyModule "PrivateKey";
import SignatureModule "Signature";

module {

  public type CurveKind = Curve.CurveKind;

  public type PublicKey = PublicKeyModule.PublicKey;
  public func PublicKey(
    x : Nat,
    y : Nat,
    curve : Curve.Curve,
  ) : PublicKey = PublicKeyModule.PublicKey(x, y, curve);

  public type PrivateKey = PrivateKeyModule.PrivateKey;
  public func PrivateKey(
    d : Nat,
    curve : Curve.Curve,
  ) : PrivateKey = PrivateKeyModule.PrivateKey(d, curve);

  public type Signature = SignatureModule.Signature;
  public func Signature(
    r : Nat,
    s : Nat,
    curve : Curve.Curve,
  ) : Signature = SignatureModule.Signature(r, s, curve);
};
