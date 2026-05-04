import Runtime "mo:core@2/Runtime";

import Bench "mo:bench-helper";

import ECDSA "../src";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "ECDSA serialization";
      description = "Encoding and decoding of public keys, private keys and signatures (secp256k1).";
      rows = [
        "publicKey_compressed",
        "publicKey_uncompressed",
        "privateKey_raw",
        "signature_der",
        "publicKey_hex",
        "privateKey_hex",
        "signature_hex",
      ];
      cols = ["encode", "decode"];
    };

    // ---- shared inputs ----
    let curve = ECDSA.secp256k1Curve();
    let messageData : Blob = "\68\65\6c\6c\6f"; // "hello"
    let randomData : Blob = "\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be";
    let testPrivateKeyValue = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;

    let priv = ECDSA.PrivateKey(testPrivateKeyValue, curve);
    let pub = priv.getPublicKey();
    let sig = switch (priv.sign(messageData.vals(), randomData.vals())) {
      case (#ok s) s;
      case (#err e) Runtime.trap("setup: sign failed: " # e);
    };

    // Pre-encoded forms used by the decode column.
    let pubCompressed = pub.toBytes(#compressed);
    let pubUncompressed = pub.toBytes(#uncompressed);
    let privRaw = priv.toBytes(#raw);
    let sigDer = sig.toBytes(#der);

    let pubHexFormat = #hex({
      byteEncoding = #compressed;
      format = { isUpper = false; prefix = #none };
    });
    let pubHexInputFormat = #hex({
      byteEncoding = #raw({ curve });
      format = { prefix = #none };
    });
    let privHexFormat = #hex({
      byteEncoding = #raw;
      format = { isUpper = false; prefix = #none };
    });
    let privHexInputFormat = #hex({
      byteEncoding = #raw({ curve });
      format = { prefix = #none };
    });
    let sigHexFormat = #hex({
      byteEncoding = #der;
      format = { isUpper = false; prefix = #none };
    });
    let sigHexInputFormat = #hex({
      byteEncoding = #der;
      format = { prefix = #none };
    });

    let pubHex = pub.toText(pubHexFormat);
    let privHex = priv.toText(privHexFormat);
    let sigHex = sig.toText(sigHexFormat);

    // routines[rowIndex][colIndex], cols = [encode, decode]
    let routines : [[() -> ()]] = [
      // publicKey_compressed
      [
        func() = ignore pub.toBytes(#compressed),
        func() = ignore ECDSA.publicKeyFromBytes(pubCompressed.vals(), #raw({ curve })),
      ],
      // publicKey_uncompressed
      [
        func() = ignore pub.toBytes(#uncompressed),
        func() = ignore ECDSA.publicKeyFromBytes(pubUncompressed.vals(), #raw({ curve })),
      ],
      // privateKey_raw
      [
        func() = ignore priv.toBytes(#raw),
        func() = ignore ECDSA.privateKeyFromBytes(privRaw.vals(), #raw({ curve })),
      ],
      // signature_der
      [
        func() = ignore sig.toBytes(#der),
        func() = ignore ECDSA.signatureFromBytes(sigDer.vals(), curve, #der),
      ],
      // publicKey_hex
      [
        func() = ignore pub.toText(pubHexFormat),
        func() = ignore ECDSA.publicKeyFromText(pubHex, pubHexInputFormat),
      ],
      // privateKey_hex
      [
        func() = ignore priv.toText(privHexFormat),
        func() = ignore ECDSA.privateKeyFromText(privHex, privHexInputFormat),
      ],
      // signature_hex
      [
        func() = ignore sig.toText(sigHexFormat),
        func() = ignore ECDSA.signatureFromText(sigHex, curve, sigHexInputFormat),
      ],
    ];

    Bench.V1(schema, func(ri, ci) = routines[ri][ci]());
  };
};
