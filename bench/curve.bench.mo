import Array "mo:core@2/Array";

import Bench "mo:bench-helper";

import Curve "../src/Curve";
import ECDSA "../src";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "ECDSA curve point operations";
      description = "Low-level Jacobi point arithmetic across both supported curves.";
      rows = [
        "mul_arbitrary",
        "mul_generator",
        "add",
        "double",
      ];
      cols = ["secp256k1", "prime256v1"];
    };

    // ---- shared inputs ----
    let curves : [Curve.Curve] = [ECDSA.secp256k1Curve(), ECDSA.prime256v1Curve()];
    let testPrivateKeyValue = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;
    let testScalarNat = 0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0;

    type Setup = {
      curve : Curve.Curve;
      point : Curve.Jacobi;
      gen : Curve.Jacobi;
      scalar : Curve.FrElt;
    };

    let setups : [Setup] = Array.tabulate<Setup>(
      curves.size(),
      func(ci) {
        let curve = curves[ci];
        let priv = ECDSA.PrivateKey(testPrivateKeyValue, curve);
        let pub = priv.getPublicKey();
        {
          curve;
          point = curve.toJacobi(#affine(curve.Fp.fromNat(pub.x), curve.Fp.fromNat(pub.y)));
          gen = curve.G_;
          scalar = curve.Fr.fromNat(testScalarNat);
        };
      },
    );

    let perCurve = func(op : Setup -> ()) : [() -> ()] {
      Array.tabulate<() -> ()>(
        setups.size(),
        func(ci) {
          let s = setups[ci];
          func() = op(s);
        },
      );
    };

    let routines : [[() -> ()]] = [
      perCurve(func(s) = ignore s.curve.mul(s.point, s.scalar)),
      perCurve(func(s) = ignore s.curve.mul_base(s.scalar)),
      perCurve(func(s) = ignore s.curve.add(s.point, s.gen)),
      perCurve(func(s) = ignore s.curve.dbl(s.point)),
    ];

    Bench.V1(schema, func(ri, ci) = routines[ri][ci]());
  };
};
