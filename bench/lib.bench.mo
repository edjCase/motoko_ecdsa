import Bench "mo:bench";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Runtime "mo:new-base/Runtime";
import ECDSA "../src";

module {

  public func init() : Bench.Bench {
    // Test data for benchmarking
    let messageData : Blob = "\68\65\6c\6c\6f"; // "hello"
    let randomData : Blob = "\ff\fe\fd\fc\fb\fa\f9\f8\f7\f6\f5\f4\f3\f2\f1\f0\ef\ee\ed\ec\eb\ea\e9\e8\e7\e6\e5\e4\e3\e2\e1\e0"; // 32 bytes of randomness

    // Pre-generated test keys and signatures for consistent benchmarking
    let secp256k1Curve = ECDSA.secp256k1Curve();
    let prime256v1Curve = ECDSA.prime256v1Curve();

    // Pre-generated private key (deterministic for benchmarking)
    let testPrivateKeyValue = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;

    // Pre-generated keys for both curves
    let secp256k1PrivateKey = ECDSA.PrivateKey(testPrivateKeyValue, secp256k1Curve);
    let secp256k1PublicKey = secp256k1PrivateKey.getPublicKey();

    let prime256v1PrivateKey = ECDSA.PrivateKey(testPrivateKeyValue, prime256v1Curve);
    let prime256v1PublicKey = prime256v1PrivateKey.getPublicKey();

    // Pre-generated signatures for verification benchmarking
    let secp256k1Signature = switch (secp256k1PrivateKey.sign(messageData.vals(), randomData.vals())) {
      case (#ok(sig)) sig;
      case (#err(e)) Debug.trap("Failed to create test signature: " # e);
    };

    let prime256v1Signature = switch (prime256v1PrivateKey.sign(messageData.vals(), randomData.vals())) {
      case (#ok(sig)) sig;
      case (#err(e)) Debug.trap("Failed to create test signature: " # e);
    };

    // Serialized key data for parsing benchmarks
    let secp256k1PublicKeyHex = secp256k1PublicKey.toText(#hex({ byteEncoding = #compressed; format = { isUpper = false; prefix = #none } }));

    let secp256k1PrivateKeyHex = secp256k1PrivateKey.toText(#hex({ byteEncoding = #raw; format = { isUpper = false; prefix = #none } }));

    let secp256k1SignatureDer = secp256k1Signature.toText(#hex({ byteEncoding = #der; format = { isUpper = false; prefix = #none } }));

    // Predefined entropy blobs for key generation benchmarks
    let entropy1 : Blob = "\aa\bb\cc\dd\ee\ff\00\11\22\33\44\55\66\77\88\99\aa\bb\cc\dd\ee\ff\00\11\22\33\44\55\66\77\88\99";
    let entropy2 : Blob = "\11\22\33\44\55\66\77\88\99\aa\bb\cc\dd\ee\ff\00\11\22\33\44\55\66\77\88\99\aa\bb\cc\dd\ee\ff\00";
    let entropy3 : Blob = "\ab\cd\ef\01\23\45\67\89\ab\cd\ef\01\23\45\67\89\ab\cd\ef\01\23\45\67\89\ab\cd\ef\01\23\45\67\89";
    let entropy4 : Blob = "\98\76\54\32\10\fe\dc\ba\98\76\54\32\10\fe\dc\ba\98\76\54\32\10\fe\dc\ba\98\76\54\32\10\fe\dc\ba";
    let entropies = [entropy1, entropy2, entropy3, entropy4];

    // Predefined random data for signing benchmarks
    let random1 : Blob = "\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be\de\ad\be\ef\ca\fe\ba\be";
    let random2 : Blob = "\12\34\56\78\9a\bc\de\f0\12\34\56\78\9a\bc\de\f0\12\34\56\78\9a\bc\de\f0\12\34\56\78\9a\bc\de\f0";
    let random3 : Blob = "\fe\dc\ba\98\76\54\32\10\fe\dc\ba\98\76\54\32\10\fe\dc\ba\98\76\54\32\10\fe\dc\ba\98\76\54\32\10";
    let random4 : Blob = "\a1\b2\c3\d4\e5\f6\07\18\29\3a\4b\5c\6d\7e\8f\90\a1\b2\c3\d4\e5\f6\07\18\29\3a\4b\5c\6d\7e\8f\90";
    let randoms = [random1, random2, random3, random4];
    let bench = Bench.Bench();

    bench.name("ECDSA Cryptographic Operations Benchmarks");
    bench.description("Benchmark key generation, signing, verification, and serialization operations for ECDSA");

    bench.rows([
      "keyGeneration_secp256k1",
      "keyGeneration_prime256v1",
      "signing_secp256k1",
      "signing_prime256v1",
      "verification_secp256k1",
      "verification_prime256v1",
      "publicKeyToBytes_compressed",
      "publicKeyToBytes_uncompressed",
      "publicKeyFromBytes_compressed",
      "publicKeyFromBytes_uncompressed",
      "privateKeyToBytes_raw",
      "privateKeyFromBytes_raw",
      "signatureToBytes_der",
      "signatureFromBytes_der",
      "publicKeyToText_hex",
      "publicKeyFromText_hex",
      "privateKeyToText_hex",
      "privateKeyFromText_hex",
      "signatureToText_hex",
      "signatureFromText_hex",
    ]);

    bench.cols(["1", "10", "100"]);

    bench.runner(
      func(row, col) {
        let ?n = Nat.fromText(col) else Debug.trap("Cols must only contain numbers: " # col);

        // Define the operation to perform based on the row
        let operation = switch (row) {
          case ("keyGeneration_secp256k1") func(i : Nat) : Result.Result<Any, Text> {
            let entropy = entropies[i % entropies.size()];
            ECDSA.generatePrivateKey(entropy.vals(), secp256k1Curve);
          };
          case ("keyGeneration_prime256v1") func(i : Nat) : Result.Result<Any, Text> {
            let entropy = entropies[i % entropies.size()];
            ECDSA.generatePrivateKey(entropy.vals(), prime256v1Curve);
          };
          case ("signing_secp256k1") func(i : Nat) : Result.Result<Any, Text> {
            let randomBytes = randoms[i % randoms.size()];
            secp256k1PrivateKey.sign(messageData.vals(), randomBytes.vals());
          };
          case ("signing_prime256v1") func(i : Nat) : Result.Result<Any, Text> {
            let randomBytes = randoms[i % randoms.size()];
            prime256v1PrivateKey.sign(messageData.vals(), randomBytes.vals());
          };
          case ("verification_secp256k1") func(_ : Nat) : Result.Result<Any, Text> {
            let isValid = secp256k1PublicKey.verify(messageData.vals(), secp256k1Signature);
            if (isValid) #ok else #err("Verification failed");
          };
          case ("verification_prime256v1") func(_ : Nat) : Result.Result<Any, Text> {
            let isValid = prime256v1PublicKey.verify(messageData.vals(), prime256v1Signature);
            if (isValid) #ok else #err("Verification failed");
          };
          case ("publicKeyToBytes_compressed") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1PublicKey.toBytes(#compressed);
            #ok;
          };
          case ("publicKeyToBytes_uncompressed") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1PublicKey.toBytes(#uncompressed);
            #ok;
          };
          case ("publicKeyFromBytes_compressed") {
            let compressedBytes = secp256k1PublicKey.toBytes(#compressed);
            func(_ : Nat) : Result.Result<Any, Text> {
              ECDSA.publicKeyFromBytes(compressedBytes.vals(), #raw({ curve = secp256k1Curve }));
            };
          };
          case ("publicKeyFromBytes_uncompressed") {
            let uncompressedBytes = secp256k1PublicKey.toBytes(#uncompressed);
            func(_ : Nat) : Result.Result<Any, Text> {
              ECDSA.publicKeyFromBytes(uncompressedBytes.vals(), #raw({ curve = secp256k1Curve }));
            };
          };
          case ("privateKeyToBytes_raw") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1PrivateKey.toBytes(#raw);
            #ok;
          };
          case ("privateKeyFromBytes_raw") {
            let rawBytes = secp256k1PrivateKey.toBytes(#raw);
            func(_ : Nat) : Result.Result<Any, Text> {
              ECDSA.privateKeyFromBytes(rawBytes.vals(), #raw({ curve = secp256k1Curve }));
            };
          };
          case ("signatureToBytes_der") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1Signature.toBytes(#der);
            #ok;
          };
          case ("signatureFromBytes_der") {
            let derBytes = secp256k1Signature.toBytes(#der);
            func(_ : Nat) : Result.Result<Any, Text> {
              ECDSA.signatureFromBytes(derBytes.vals(), secp256k1Curve, #der);
            };
          };
          case ("publicKeyToText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1PublicKey.toText(#hex({ byteEncoding = #compressed; format = { isUpper = false; prefix = #none } }));
            #ok;
          };
          case ("publicKeyFromText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ECDSA.publicKeyFromText(secp256k1PublicKeyHex, #hex({ byteEncoding = #raw({ curve = secp256k1Curve }); format = { prefix = #none } }));
          };
          case ("privateKeyToText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1PrivateKey.toText(#hex({ byteEncoding = #raw; format = { isUpper = false; prefix = #none } }));
            #ok;
          };
          case ("privateKeyFromText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ECDSA.privateKeyFromText(secp256k1PrivateKeyHex, #hex({ byteEncoding = #raw({ curve = secp256k1Curve }); format = { prefix = #none } }));
          };
          case ("signatureToText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ignore secp256k1Signature.toText(#hex({ byteEncoding = #der; format = { isUpper = false; prefix = #none } }));
            #ok;
          };
          case ("signatureFromText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ECDSA.signatureFromText(secp256k1SignatureDer, secp256k1Curve, #hex({ byteEncoding = #der; format = { prefix = #none } }));
          };
          case (_) Runtime.trap("Unknown row: " # row);
        };

        // Single shared loop with result checking
        for (i in Iter.range(1, n)) {
          switch (operation(i)) {
            case (#ok(_)) ();
            case (#err(e)) Debug.trap(e);
          };
        };
      }
    );

    bench;
  };

};
