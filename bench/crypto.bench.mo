import Array "mo:core@2/Array";
import Runtime "mo:core@2/Runtime";

import Bench "mo:bench-helper";

import ECDSA "../src";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "ECDSA crypto operations";
      description = "Key generation, signing and verification across both supported curves.";
      rows = [
        "keyGeneration",
        "sign",
        "verify",
      ];
      cols = ["secp256k1", "prime256v1"];
    };

    // ---- shared inputs (built once) ----
    let curves = [ECDSA.secp256k1Curve(), ECDSA.prime256v1Curve()];

    let messageData : Blob = "\68\65\6c\6c\6f"; // "hello"
    let entropy : Blob = "\aa\bb\cc\dd\ee\ff\00\11\22\33\44\55\66\77\88\99\aa\bb\cc\dd\ee\ff\00\11\22\33\44\55\66\77\88\99";
    let randomData : Blob = "\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be";

    let testPrivateKeyValue = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;

    // Per-curve precomputed key/signature pairs.
    let keys = Array.tabulate<{ priv : ECDSA.PrivateKey; pub : ECDSA.PublicKey; sig : ECDSA.Signature }>(
      curves.size(),
      func(ci) {
        let priv = ECDSA.PrivateKey(testPrivateKeyValue, curves[ci]);
        let pub = priv.getPublicKey();
        let sig = switch (priv.sign(messageData.vals(), randomData.vals())) {
          case (#ok s) s;
          case (#err e) Runtime.trap("setup: sign failed: " # e);
        };
        { priv; pub; sig };
      },
    );

    // routines[rowIndex][colIndex]
    let routines : [[() -> ()]] = [
      // keyGeneration
      Array.tabulate<() -> ()>(
        curves.size(),
        func(ci) = func() {
          ignore ECDSA.generatePrivateKey(entropy.vals(), curves[ci]);
        },
      ),
      // sign
      Array.tabulate<() -> ()>(
        curves.size(),
        func(ci) {
          let priv = keys[ci].priv;
          func() = ignore priv.sign(messageData.vals(), randomData.vals());
        },
      ),
      // verify
      Array.tabulate<() -> ()>(
        curves.size(),
        func(ci) {
          let pub = keys[ci].pub;
          let sig = keys[ci].sig;
          func() = ignore pub.verify(messageData.vals(), sig);
        },
      ),
    ];

    Bench.V1(schema, func(ri, ci) = routines[ri][ci]());
  };
};
