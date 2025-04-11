import CurveModule "./Curve";
import PublicKeyModule "PublicKey";
import PrivateKeyModule "PrivateKey";
import SignatureModule "Signature";
import Iter "mo:base/Iter";
import Result "mo:new-base/Result";

module {

  public type CurveKind = CurveModule.CurveKind;

  public type Curve = CurveModule.Curve;
  public func Curve(kind : CurveKind) : Curve = CurveModule.Curve(kind);
  public func secp256k1Curve() : Curve = CurveModule.secp256k1();
  public func prime256v1Curve() : Curve = CurveModule.prime256v1();

  public type PublicKey = PublicKeyModule.PublicKey;
  public func PublicKey(
    x : Nat,
    y : Nat,
    curve : CurveModule.Curve,
  ) : PublicKey = PublicKeyModule.PublicKey(x, y, curve);

  public func publicKeyFromBytes(
    bytes : Iter.Iter<Nat8>,
    encoding : PublicKeyModule.InputByteEncoding,
  ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromBytes(bytes, encoding);

  public func publicKeyFromText(
    text : Text,
    encoding : PublicKeyModule.InputTextFormat,
  ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromText(text, encoding);

  public type PrivateKey = PrivateKeyModule.PrivateKey;
  public func PrivateKey(
    d : Nat,
    curve : CurveModule.Curve,
  ) : PrivateKey = PrivateKeyModule.PrivateKey(d, curve);

  public func privateKeyFromBytes(
    bytes : Iter.Iter<Nat8>,
    encoding : PrivateKeyModule.InputByteEncoding,
  ) : Result.Result<PrivateKey, Text> = PrivateKeyModule.fromBytes(bytes, encoding);

  public func privateKeyFromText(
    text : Text,
    encoding : PrivateKeyModule.InputTextFormat,
  ) : Result.Result<PrivateKey, Text> = PrivateKeyModule.fromText(text, encoding);

  public func generatePrivateKey(
    entropy : Iter.Iter<Nat8>,
    curve : CurveModule.Curve,
  ) : Result.Result<PrivateKey, Text> = PrivateKeyModule.generate(entropy, curve);

  public type Signature = SignatureModule.Signature;
  public func Signature(
    r : Nat,
    s : Nat,
    curve : CurveModule.Curve,
  ) : Signature = SignatureModule.Signature(r, s, curve);

  public func signatureFromBytes(
    bytes : Iter.Iter<Nat8>,
    curve : CurveModule.Curve,
    encoding : SignatureModule.InputByteEncoding,
  ) : Result.Result<Signature, Text> = SignatureModule.fromBytes(bytes, curve, encoding);

  public func signatureFromText(
    text : Text,
    curve : CurveModule.Curve,
    encoding : SignatureModule.InputTextFormat,
  ) : Result.Result<Signature, Text> = SignatureModule.fromText(text, curve, encoding);
};
