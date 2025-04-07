import Curve "./Curve";
import PublicKeyModule "PublicKey";
import PrivateKeyModule "PrivateKey";
import SignatureModule "Signature";
import Iter "mo:base/Iter";

module {

  public type CurveKind = Curve.CurveKind;

  public type PublicKey = PublicKeyModule.PublicKey;
  public func PublicKey(
    x : Nat,
    y : Nat,
    curve : Curve.Curve,
  ) : PublicKey = PublicKeyModule.PublicKey(x, y, curve);

  public func publicKeyFromBytes(
    bytes : Iter.Iter<Nat8>,
    encoding : PublicKeyModule.KeyEncoding,
  ) : ?PublicKey = PublicKeyModule.fromBytes(bytes, encoding);

  public type PrivateKey = PrivateKeyModule.PrivateKey;
  public func PrivateKey(
    d : Nat,
    curve : Curve.Curve,
  ) : PrivateKey = PrivateKeyModule.PrivateKey(d, curve);

  public func privateKeyFromBytes(
    bytes : Iter.Iter<Nat8>,
    encoding : PrivateKeyModule.KeyEncoding,
  ) : ?PrivateKey = PrivateKeyModule.fromBytes(bytes, encoding);

  public func generatePrivateKey(
    entropy : Iter.Iter<Nat8>,
    curve : Curve.Curve,
  ) : ?PrivateKey = PrivateKeyModule.generate(entropy, curve);

  public type Signature = SignatureModule.Signature;
  public func Signature(
    r : Nat,
    s : Nat,
    curve : Curve.Curve,
  ) : Signature = SignatureModule.Signature(r, s, curve);

  public func signatureFromBytes(
    bytes : Iter.Iter<Nat8>,
    curve : Curve.Curve,
    encoding : SignatureModule.SignatureEncoding,
  ) : ?Signature = SignatureModule.fromBytes(bytes, curve, encoding);
};
