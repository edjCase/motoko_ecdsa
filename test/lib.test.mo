import M "../src";
import Field "../src/Field";
import Curve "../src/Curve";
import Binary "../src/Binary";
import Util "../src/Util";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Blob "mo:base/Blob";
import Iter "mo:base/Iter";
import Nat8 "mo:base/Nat8";
import P "mo:base/Prelude";
import Debug "mo:base/Debug";
import { test; suite } "mo:test";
import Sha256 "mo:sha2/Sha256";
import Array "mo:new-base/Array";
import Result "mo:new-base/Result";
import PrivateKey "../src/PrivateKey";
import PublicKey "../src/PublicKey";
import Signature "../src/Signature";
import ASN1 "mo:asn1";
import IterTools "mo:itertools/Iter";

func sha2(bytes : Iter.Iter<Nat8>) : Blob {
  Sha256.fromIter(#sha256, bytes);
};

let curveKinds : [Curve.CurveKind] = [
  #secp256k1,
  #prime256v1,
];
for (curveKind in curveKinds.vals()) {
  let curve = Curve.Curve(curveKind);

  let (okP1, okP2, okP3, okP4) = switch (curveKind) {
    case (#secp256k1) (
      // Base point G
      (
        #fp(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),
        #fp(0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
        #fp(1),
      ),
      // 2G
      (
        #fp(0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),
        #fp(0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a),
        #fp(1),
      ),
      // 3G
      (
        #fp(0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),
        #fp(0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672),
        #fp(1),
      ),
      // 4G
      (
        #fp(0xe493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),
        #fp(0x51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922),
        #fp(1),
      ),
    );
    case (#prime256v1) (
      // Base point G for NIST P-256 (prime256v1)
      (
        #fp(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296),
        #fp(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
        #fp(1),
      ),
      // 2G
      (
        #fp(0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978),
        #fp(0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1),
        #fp(1),
      ),
      // 3G
      (
        #fp(0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c),
        #fp(0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032),
        #fp(1),
      ),
      // 4G - CORRECT NIST value
      (
        #fp(0xe2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852),
        #fp(0xe0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6),
        #fp(1),
      ),
    );
  };

  suite(
    "Curve: " # debug_show (curveKind),
    func() {
      let C = Curve.Curve(curveKind);
      let p = C.params.p;

      func consumeIter(iter : Iter.Iter<Nat>, expect : [Nat]) {
        assert (iter.next() == ?expect[0]);
        assert (iter.next() == ?expect[1]);
      };

      test(
        "iterTest",
        func() {
          let a = [1, 2, 3, 4, 5];
          let b = a.vals();
          let c = b;
          let d = a.vals();
          consumeIter(b, [1, 2]);
          consumeIter(c, [3, 4]);
          consumeIter(d, [1, 2]);
        },
      );

      func optionFunc(v : Nat) : ?Nat {
        if (v == 0) return null;
        ?v;
      };

      test(
        "toReverseBinTest",
        func() {
          let tbl = [
            (0, [] : [Bool]),
            (1, [true]),
            (2, [false, true]),
          ];
          for (i in tbl.keys()) {
            let (v, a) = tbl[i];
            let b = Binary.fromNatReversed(v);
            assert (b == a);
          };
          switch (optionFunc(5)) {
            case (null) { assert (false) };
            case (?v) { assert (v == 5) };
          };
        },
      );

      test(
        "toBigEndianTest",
        func() {
          let tbl = [
            ([0] : [Nat8], 0x0),
            ([0x12] : [Nat8], 0x12),
            ([0x12, 0x34] : [Nat8], 0x1234),
            ([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0] : [Nat8], 0x123456789abcdef0),
            ([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12] : [Nat8], 0x123456789abcdef012),
          ];
          for (i in tbl.keys()) {
            let (b, v) = tbl[i];
            assert (Util.toBigEndian(v) == b);
          };
        },
      );

      test(
        "toBigEndianPadTest",
        func() {
          let tbl = [
            ([0x0] : [Nat8], 0x0),
            ([0x12] : [Nat8], 0x12),
            ([0x12, 0x34] : [Nat8], 0x1234),
            ([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0] : [Nat8], 0x123456789abcdef0),
            ([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12] : [Nat8], 0x123456789abcdef012),
          ];
          for (i in tbl.keys()) {
            let (b, v) = tbl[i];
            assert (Util.toNatAsBigEndian(b.vals()) == ?v);
            assert (Util.toBigEndianPad(b.size(), v) == b);
          };
          assert (Util.toBigEndianPad(1, 0) == ([0x00] : [Nat8]));
          assert (Util.toBigEndianPad(5, 0x1234) == ([0x00, 0x00, 0x00, 0x12, 0x34] : [Nat8]));
        },
      );

      test(
        "dbl_prime256v1",
        func() {

          let curve = C;

          // Test doubling
          let P2 = curve.dbl(okP1);

          // Verify equality
          assert (curve.isEqual(P2, okP2));

          // Test if points are on curve
          assert (curve.isValid(okP1));
          assert (curve.isValid(P2));
          assert (curve.isValid(okP2));
        },
      );
      test(
        "add_test",
        func() {

          let curve = C;

          // Test points we know are correct from previous tests
          let P = curve.G_; // Base point
          let P2 = okP2;

          let sum = curve.add(P, P);
          let (sumX, sumY, sumZ) = curve.normalize(sum);

          // This tests both add and dbl since add(P,P) should redirect to dbl(P)
          assert (sumX == P2.0);
          assert (sumY == P2.1);
          assert (sumZ == P2.2);

          // Now test P + 2P = 3P
          let P3 = okP3;

          let sum2 = curve.add(P, P2);
          let (sum2X, sum2Y, sum2Z) = curve.normalize(sum2);

          // Let's also print intermediate values from the add function
          let isPzOne = P.2 == #fp(1);
          let r = if (isPzOne) #fp(1) else curve.Fp.sqr(P.2);
          let S1 = curve.Fp.sqr(P2.2);
          let U1 = curve.Fp.mul(P.0, S1);
          var H = if (isPzOne) P2.0 else curve.Fp.mul(P2.0, r);
          H := curve.Fp.sub(H, U1);

          assert (sum2X == P3.0);
          assert (sum2Y == P3.1);
          assert (sum2Z == P3.2);
        },
      );

      test(
        "mul_negative_test",
        func() {
          let curve = C;
          let G = curve.G_; // Base point

          // Define simple scalar values
          let one = curve.Fr.fromNat(1);
          let two = curve.Fr.fromNat(2);
          let minus_one = curve.Fr.neg(one);

          // Test that (-1)G = -(1G)
          let P_neg = curve.mul(G, minus_one);
          let P = curve.mul(G, one);
          let neg_P = curve.neg(P);

          // Compare coordinates after normalization
          let normalized_P_neg = curve.normalize(P_neg);
          let normalized_neg_P = curve.normalize(neg_P);

          let (x1, y1, z1) = normalized_P_neg;
          let (x2, y2, z2) = normalized_neg_P;

          assert (z1 == #fp(1));
          assert (z2 == #fp(1));
          assert (x1 == x2);
          assert (y1 == y2);

          // Check negation of scalar in field
          // For a prime field, we should have n + (-n) ≡ 0 (mod order)
          let sum = curve.Fr.add(two, curve.Fr.neg(two));
          assert (curve.Fr.toNat(sum) == 0);
        },
      );

      test(
        "mul_test",
        func() {
          let curve = C;
          let G = curve.G_; // Base point

          // Define scalar values
          let one = curve.Fr.fromNat(1);
          let two = curve.Fr.add(one, one);
          let three = curve.Fr.add(two, one);
          let six = curve.Fr.add(three, three);

          // Compute points
          let P2 = curve.mul(G, two); // 2G
          let P6 = curve.mul(G, six); // 6G

          // Assert: 2G * 3 = 6G
          let P2_times_3 = curve.mul(P2, three);
          let normalized_P2_times_3 = curve.normalize(P2_times_3);
          let normalized_P6 = curve.normalize(P6);

          // Compare normalized coordinates
          let (x1, y1, z1) = normalized_P2_times_3;
          let (x2, y2, z2) = normalized_P6;
          assert (z1 == #fp(1));
          assert (z2 == #fp(1));
          assert (x1 == x2);
          assert (y1 == y2);

          // Compute negative scalars
          let minus_two = curve.Fr.neg(two);
          let minus_three = curve.Fr.neg(three);

          // Assert: -(-2) = 2
          let double_neg_two = curve.Fr.neg(minus_two);
          assert (curve.Fr.toNat(double_neg_two) == curve.Fr.toNat(two));

          // Assert: (-3) * (-2) = (-2) * (-3)
          let product1 = curve.Fr.mul(minus_three, minus_two);
          let product2 = curve.Fr.mul(minus_two, minus_three);
          assert (curve.Fr.toNat(product1) == curve.Fr.toNat(product2));

          // Assert: (-3) * (-2) = 6
          assert (curve.Fr.toNat(product1) == curve.Fr.toNat(six));

          // Additional point multiplication check
          let P_minus_two = curve.mul(G, minus_two); // -2G

          // (-2G) * (-3) should equal 6G
          let result = curve.mul(P_minus_two, minus_three);
          let normalized_result = curve.normalize(result);
          let (xr, yr, zr) = normalized_result;
          let (x6, y6, z6) = normalized_P6;

          assert (zr == #fp(1));
          assert (z6 == #fp(1));
          assert (xr == x6);
          assert (yr == y6);
        },
      );

      test(
        "arithTest",
        func() {
          let m1 = 5 * 2 ** 128;
          let m2 = 6 * 2 ** 128;
          var x1 = C.Fp.fromNat(m1);
          var x2 = C.Fp.fromNat(m2);
          assert (C.Fp.add(x1, x2) == C.Fp.fromNat(m1 + m2));
          assert (C.Fp.sub(x1, x2) == C.Fp.fromNat(m1 + p - m2 : Nat));
          assert (C.Fp.sub(x2, x1) == C.Fp.fromNat(m2 - m1 : Nat));
          assert (C.Fp.neg(#fp(0)) == #fp(0));
          assert (C.Fp.neg(x1) == C.Fp.fromNat(p - m1 : Nat));
          assert (C.Fp.mul(x1, x2) == C.Fp.fromNat(m1 * m2));

          var i = 0;
          x2 := #fp(1);
          while (i < 30) {
            assert (x2 == C.Fp.pow(x1, i));
            x2 := C.Fp.mul(x2, x1);
            i += 1;
          };
        },
      );

      test(
        "invTest",
        func() {
          let inv123 = Field.inv_(123, 65537);
          assert (inv123 == 14919);
          let x2 = C.Fp.inv(#fp(123));
          var i = 1;
          while (i < 20) {
            let x1 = #fp(i);
            assert (C.Fp.mul(x1, C.Fp.inv(x1)) == #fp(1));
            assert (C.Fp.mul(C.Fp.div(x2, x1), x1) == x2);
            i += 1;
          };
        },
      );

      test(
        "sqrRootTest",
        func() {
          var i = 0;
          while (i < 30) {
            //    Debug.print("i=" # M.toHex(i));
            switch (C.fpSqrRoot(#fp(i))) {
              case (null) {};
              case (?sq) {
                //        Debug.print("sq=" # M.toHex(sq));
                assert (C.Fp.sqr(sq) == #fp(i));
              };
            };
            i += 1;
          };
        },
      );

      test(
        "ec1Test",
        func() {
          let Z = C.zeroJ;
          assert (C.isZero(Z));
          assert (C.isZero(C.neg(Z)));
          assert (C.isZero(C.add(Z, Z)));

          let P = C.G_;
          assert (not C.isZero(P));
          let Q = C.neg(P);
          assert (not C.isZero(Q));
          assert (C.isZero(C.add(P, Q)));
        },
      );
      test(
        "ec2Test",
        func() {
          let P = C.G_;

          // Test base point correctness
          assert (C.isValid(P));
          assert (C.isEqual(P, okP1));

          // Test doubling and addition
          let P2 = C.dbl(P);
          assert (C.isEqual(P2, okP2));
          assert (C.isEqual(C.add(P, P), okP2));

          let P3 = C.add(P2, P);
          assert (C.isEqual(P3, okP3));

          let P4 = C.add(P3, P);
          assert (C.isEqual(P4, okP4));

          let P5 = C.add(P4, P);

          // Test scalar multiplication
          assert (C.isZero(C.add(P, C.neg(P))));
          assert (C.isEqual(C.dbl(P), P2));
          assert (C.isEqual(C.mul(P, #fr(1)), P));
          assert (C.isEqual(C.mul(P, #fr(2)), P2));
          assert (C.isEqual(C.mul(P, #fr(3)), P3));

          // Debug the multiplication for 4G specifically
          let mul4G = C.mul(P, #fr(4));
          assert (C.isEqual(mul4G, P4));

          assert (C.isEqual(C.mul(P, #fr(4)), P4));
          assert (C.isEqual(C.mul(P, #fr(5)), P5));

          // Continue with other assertions
          let Q = C.mul(P, C.Fr.fromNat(C.params.r - 1));
          assert (C.isEqual(Q, C.neg(P)));
          assert (C.isZero(C.add(Q, P)));
          assert (C.isZero(C.mul(P, C.Fr.fromNat(C.params.r))));
        },
      );

      test(
        "ecdsaTest",
        func() {
          let hello : [Nat8] = [0x68, 0x65, 0x6c, 0x6c, 0x6f];
          // sha256('hello')
          let hashed : [Nat8] = [0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24];
          assert (Blob.toArray(sha2(hello.vals())) == hashed);

          let secBytes : [Nat8] = [0x83, 0xec, 0xb3, 0x98, 0x4a, 0x4f, 0x9f, 0xf0, 0x3e, 0x84, 0xd5, 0xf9, 0xc0, 0xd7, 0xf8, 0x88, 0xa8, 0x18, 0x33, 0x64, 0x30, 0x47, 0xac, 0xc5, 0x8e, 0xb6, 0x43, 0x1e, 0x01, 0xd9, 0xba, 0xc8];
          let expectedSecKey = 0x83ecb3984a4f9ff03e84d5f9c0d7f888a81833643047acc58eb6431e01d9bac8;
          let randBytes : [Nat8] = [0x8a, 0xfa, 0x4a, 0x16, 0x2b, 0x7b, 0xad, 0x6c, 0x92, 0xff, 0x14, 0xf3, 0xa8, 0xbf, 0x4d, 0xb0, 0xf3, 0xc3, 0x9e, 0x90, 0xc0, 0x6f, 0x93, 0x78, 0x61, 0xf8, 0x23, 0xd2, 0x99, 0x5c, 0x74, 0xf0];
          do {
            // Define test vectors for each curve
            let expectedPK = switch (curveKind) {
              case (#secp256k1) PublicKey.PublicKey(0x653bd02ba1367e5d4cd695b6f857d1cd90d4d8d42bc155d85377b7d2d0ed2e71, 0x04e8f5da403ab78decec1f19e2396739ea544e2b14159beb5091b30b418b813a, curve);
              case (#prime256v1) PublicKey.PublicKey(0x5eef7fbe25dab17a4f30c0e6e6501b40ad0e53a9a3193695b0b10099e8af59ea, 0x7d7aab6919a4346c45a54d89861a043bae3c5d3a6fba5ce32241d20396f7e430, curve);
            };

            let #ok(privateKey) = PrivateKey.generate(secBytes.vals(), C) else P.unreachable();

            assert (privateKey.d == expectedSecKey);

            let publicKey = privateKey.getPublicKey();
            assert (publicKey.equal(expectedPK));

            let #ok(sig) = privateKey.signHashed(hashed.vals(), randBytes.vals()) else P.unreachable();
            let #ok(sig2) = privateKey.sign(hello.vals(), randBytes.vals()) else P.unreachable();
            assert (sig.equal(sig2));

            assert (publicKey.verify(hello.vals(), sig));
            assert (publicKey.verifyHashed(hashed.vals(), sig));
            let #fp(y2) = C.Fp.add(#fp(publicKey.y), #fp(1));
            let publicKey2 = PublicKey.PublicKey(publicKey.x, y2, curve);
            assert (not publicKey2.verifyHashed(hashed.vals(), sig));
          };
        },
      );

      test(
        "ecdsaTest2",
        func() {
          // sha256('hello')
          let hashed : [Nat8] = [0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24];

          let secretKeyVal = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;

          // Test vectors from Python:ecdsa for both curves
          let (expectedPubKey, expectedSig) = switch (curveKind) {
            case (#secp256k1) (
              PublicKey.PublicKey(
                0x0a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3d,
                0xa53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d,
                curve,
              ),
              Signature.Signature(
                0x50839a97404c24ec39455b996e4888477fd61bcf0ffb960c7ffa3bef10450191,
                0x9671b8315bb5c1611d422d49cbbe7e80c6b463215bfad1c16ca73172155bf31a,
                curve,
              ),
            );
            case (#prime256v1) (
              PublicKey.PublicKey(
                0x56dbd53724b2831eca1bb64d95985fd889edfc93abdbf2c30682658dd7d5f4c8,
                0xc18a9684c45484e9d84d47aba1ff13893af81fd76fdca0914364265a5bf7ec33,
                curve,
              ),
              Signature.Signature(
                0xc92ce5eccc1b9e659e5e27f6d3fe874c9f0a76c9286248c70166cb0991a941fa,
                0x8714550e18c194fd1d4a2a22a1c3077b64c7acbceb7d111a25d08dfd14c98a3,
                curve,
              ),
            );
          };

          let privateKey = PrivateKey.PrivateKey(secretKeyVal, curve);
          let publicKey = privateKey.getPublicKey();

          // Verify public key
          assert (publicKey.equal(expectedPubKey));

          // Verify signature
          assert (publicKey.verifyHashed(hashed.vals(), expectedSig));
        },
      );

      test(
        "serializeTest",
        func() {
          let (expectedBytes, publicKey) : ([Nat8], PublicKey.PublicKey) = switch (curveKind) {
            case (#secp256k1) (
              [0x04, 0xa, 0x9, 0xff, 0x14, 0x2d, 0x94, 0xbc, 0x3f, 0x56, 0xc5, 0xc8, 0x1b, 0x75, 0xea, 0x3b, 0x6, 0xb0, 0x82, 0xc5, 0x26, 0x3f, 0xbb, 0x5b, 0xd8, 0x8c, 0x61, 0x9f, 0xc6, 0x39, 0x3d, 0xda, 0x3d, 0xa5, 0x3e, 0xe, 0x93, 0x8, 0x92, 0xcd, 0xb7, 0x79, 0x9e, 0xea, 0x8f, 0xd4, 0x5b, 0x9f, 0xff, 0x37, 0x7d, 0x83, 0x8f, 0x41, 0x6, 0x45, 0x42, 0x89, 0xae, 0x8a, 0x8, 0xb, 0x11, 0x1f, 0x8d],
              PublicKey.PublicKey(0x0a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3d, 0xa53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d, curve),
            );
            case (#prime256v1) (
              [0x04, 0xE4, 0x66, 0x8E, 0x55, 0x48, 0xEE, 0x5A, 0x7E, 0x7D, 0x6B, 0xC0, 0x69, 0xEF, 0xDE, 0xBD, 0xE0, 0x3E, 0x4A, 0x0A, 0x52, 0xFB, 0xEE, 0x28, 0xAB, 0x01, 0x16, 0x4D, 0x03, 0x3C, 0x4B, 0x63, 0x65, 0x38, 0x1D, 0x87, 0x04, 0x6D, 0x4F, 0x8F, 0xB4, 0xE7, 0xCC, 0xF3, 0xFD, 0x34, 0x3A, 0xFA, 0x3E, 0xDA, 0xE4, 0x9B, 0x16, 0x1B, 0x02, 0x40, 0xFC, 0x3E, 0x8A, 0x33, 0x37, 0xA5, 0xFE, 0x8E, 0x39],
              PublicKey.PublicKey(0xe4668e5548ee5a7e7d6bc069efdebde03e4a0a52fbee28ab01164d033c4b6365, 0x381d87046d4f8fb4e7ccf3fd343afa3edae49b161b0240fc3e8a3337a5fe8e39, curve),
            );
          };

          let check = func(actualPubKey : Result.Result<M.PublicKey, Text>, expectedPubKey : M.PublicKey) {
            switch (actualPubKey) {
              case (#err(e)) Debug.trap("Unable to parse public key bytes: " # e);
              case (#ok(actualPubKey)) {
                if (not actualPubKey.equal(expectedPubKey)) {
                  Debug.trap("Public key mismatch");
                };
              };
            };
          };
          do {
            let uncompressedBytes = publicKey.toBytes(#uncompressed);
            assert (uncompressedBytes == expectedBytes);
            check(PublicKey.fromBytes(uncompressedBytes.vals(), #raw({ curve })), publicKey);
          };
          do {
            let compressedBytes = publicKey.toBytes(#compressed);
            check(PublicKey.fromBytes(compressedBytes.vals(), #raw({ curve })), publicKey);
            let #fp(yNeg) = C.Fp.neg(#fp(publicKey.y));
            let publicKeyNeg = PublicKey.PublicKey(publicKey.x, yNeg, curve);
            let compressedBytesNeg = publicKeyNeg.toBytes(#compressed);
            check(PublicKey.fromBytes(compressedBytesNeg.vals(), #raw({ curve })), publicKeyNeg);
          };
        },
      );

      test(
        "derTest",
        func() {
          let sig = Signature.Signature(0xed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f, 0x7a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed, curve);
          let expected : [Nat8] = switch (curveKind) {
            case (#secp256k1) [0x30, 0x45, 0x02, 0x21, 0x00, 0xed, 0x81, 0xff, 0x19, 0x2e, 0x75, 0xa3, 0xfd, 0x23, 0x04, 0x00, 0x4d, 0xca, 0xdb, 0x74, 0x6f, 0xa5, 0xe2, 0x4c, 0x50, 0x31, 0xcc, 0xfc, 0xf2, 0x13, 0x20, 0xb0, 0x27, 0x74, 0x57, 0xc9, 0x8f, 0x02, 0x20, 0x7a, 0x98, 0x6d, 0x95, 0x5c, 0x6e, 0x0c, 0xb3, 0x5d, 0x44, 0x6a, 0x89, 0xd3, 0xf5, 0x61, 0x00, 0xf4, 0xd7, 0xf6, 0x78, 0x01, 0xc3, 0x19, 0x67, 0x74, 0x3a, 0x9c, 0x8e, 0x10, 0x61, 0x5b, 0xed];
            case (#prime256v1) [0x30, 0x45, 0x2, 0x21, 0x0, 0xed, 0x81, 0xff, 0x19, 0x2e, 0x75, 0xa3, 0xfd, 0x23, 0x4, 0x0, 0x4d, 0xca, 0xdb, 0x74, 0x6f, 0xa5, 0xe2, 0x4c, 0x50, 0x31, 0xcc, 0xfc, 0xf2, 0x13, 0x20, 0xb0, 0x27, 0x74, 0x57, 0xc9, 0x8f, 0x2, 0x20, 0x7a, 0x98, 0x6d, 0x95, 0x5c, 0x6e, 0xc, 0xb3, 0x5d, 0x44, 0x6a, 0x89, 0xd3, 0xf5, 0x61, 0x0, 0xf4, 0xd7, 0xf6, 0x78, 0x1, 0xc3, 0x19, 0x67, 0x74, 0x3a, 0x9c, 0x8e, 0x10, 0x61, 0x5b, 0xed];
          };
          let derBytes = sig.toBytes(#der);

          assert (derBytes == expected);
          let #ok(actualSig) = Signature.fromBytes(derBytes.vals(), curve, #der) else Debug.trap("Unable to parse signature der bytes");

          assert (actualSig.equal(sig));
        },
      );

      test(
        "jacobiTest",
        func() {
          // Use the precomputed 2G point from earlier test values
          let dblP = switch (curveKind) {
            case (#secp256k1) (
              #fp(0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),
              #fp(0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a),
            );
            case (#prime256v1) (
              #fp(0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978),
              #fp(0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1),
            );
          };

          let Pa = #affine(C.params.g);
          let Pj = C.toJacobi(Pa);
          assert (Pa == C.fromJacobi(Pj));
          var Qj = C.neg(Pj);
          assert (C.isZero(C.add(Pj, Qj)));
          Qj := C.dbl(Pj);

          // Instead of directly comparing, use C.isEqual to compare Jacobi coordinates
          var Qa = C.toJacobi(#affine(dblP));
          assert (C.isEqual(Qj, Qa));

          // Continue with the rest of the test...
          var i = 0;
          while (i < 10) {
            Qa := C.add(Qa, C.toJacobi(Pa));
            let R = C.add(Pj, Qj);
            Qj := C.add(Qj, Pj);
            assert (C.isEqual(Qj, R));
            assert (C.isEqual(Qj, Qa));
            i += 1;
          };

          Qj := C.mul(Pj, C.Fr.fromNat(C.params.r - 1));
          assert (C.isEqual(Qj, C.neg(Pj)));
          assert (C.isZero(C.add(Qj, Pj)));
          assert (C.isZero(C.mul(Pj, C.Fr.fromNat(C.params.r))));
        },
      );

      test(
        "nafTest",
        func() {
          let tbl : [(Int, [Int])] = [
            (0, []),
            (1, [1]),
            (2, [0, 1]),
            (3, [3]),
            (4, [0, 0, 1]),
            (5, [5]),
            (6, [0, 3]),
            (7, [7]),
            (8, [0, 0, 0, 1]),
            (9, [9]),
            (10, [0, 5]),
            (11, [11]),
            (12, [0, 0, 3]),
            (30, [0, 15]),
            (31, [-1, 0, 0, 0, 0, 1]),
            (32, [0, 0, 0, 0, 0, 1]),
            (33, [1, 0, 0, 0, 0, 1]),
            (60, [0, 0, 15]),
            (61, [-3, 0, 0, 0, 0, 0, 1]),
            (62, [0, -1, 0, 0, 0, 0, 1]),
            (63, [-1, 0, 0, 0, 0, 0, 1]),
            (125, [-3, 0, 0, 0, 0, 0, 0, 1]),
            (126, [0, -1, 0, 0, 0, 0, 0, 1]),
            (127, [-1, 0, 0, 0, 0, 0, 0, 1]),
            (128, [0, 0, 0, 0, 0, 0, 0, 1]),
            (129, [1, 0, 0, 0, 0, 0, 0, 1]),
            (65535, [-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            (131070, [0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            (262140, [0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            (5592405, [-11, 0, 0, 0, 0, 11, 0, 0, 0, 0, -11, 0, 0, 0, 0, 11, 0, 0, 0, 0, 5]),
            (16777200, [0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            (2130771712, [0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1]),
            (-1, [-1]),
            (-2, [0, -1]),
            (-3, [-3]),
            (-4, [0, 0, -1]),
            (-5, [-5]),
            (-6, [0, -3]),
            (-7, [-7]),
            (-8, [0, 0, 0, -1]),
            (-9, [-9]),
          ];
          for ((k, v) in tbl.vals()) {
            let naf = Binary.toNafWidth(k, 5);
            assert (naf == v);
          };
        },
      );

      test(
        "okEdgeTest",
        func() {
          let (tbl, vTbl) : ([[Nat8]], [Int]) = switch (curveKind) {
            case (#secp256k1) (
              [
                [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
                [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
                [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x7f],
                [0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x08, 0x02, 0x01, 0x00, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x26, 0x02, 0x01, 0x00, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00],
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x7f],
                [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
                [0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x00],
                [0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x01],
                [0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x7f],
                [0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x08, 0x02, 0x01, 0x7f, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x26, 0x02, 0x01, 0x7f, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
                [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x00],
                [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01],
                [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x7f],
                [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x09, 0x02, 0x02, 0x00, 0x80, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x27, 0x02, 0x02, 0x00, 0x80, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
                [0x30, 0x07, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x01, 0x00],
                [0x30, 0x07, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x01, 0x01],
                [0x30, 0x07, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x01, 0x7f],
                [0x30, 0x08, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x08, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x09, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x27, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
                [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x00],
                [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x01],
                [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x7f],
                [0x30, 0x09, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x09, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x28, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
                [0x30, 0x26, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x01, 0x00],
                [0x30, 0x26, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x01, 0x01],
                [0x30, 0x26, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x01, 0x7f],
                [0x30, 0x27, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x02, 0x00, 0x80],
                [0x30, 0x27, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x02, 0x7f, 0xff],
                [0x30, 0x28, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x03, 0x00, 0x80, 0x00],
                [0x30, 0x46, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40],
              ],
              [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, -1],
            );
            case (#prime256v1) (
              [
                [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00], // r=0, s=0
                [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01], // r=0, s=1
                [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x7f], // r=0, s=127
                [0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x80], // r=0, s=128
                [0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x7f, 0xff], // r=0, s=32767
                [0x30, 0x08, 0x02, 0x01, 0x00, 0x02, 0x03, 0x00, 0x80, 0x00], // r=0, s=32768
                [0x30, 0x26, 0x02, 0x01, 0x00, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=0, s=-1
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00], // r=1, s=0
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // r=1, s=1
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x7f], // r=1, s=127
                [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80], // r=1, s=128
                [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x7f, 0xff], // r=1, s=32767
                [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0x80, 0x00], // r=1, s=32768
                [0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=1, s=-1
                [0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x00], // r=127, s=0
                [0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x01], // r=127, s=1
                [0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x7f], // r=127, s=127
                [0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, 0x80], // r=127, s=128
                [0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x7f, 0xff], // r=127, s=32767
                [0x30, 0x08, 0x02, 0x01, 0x7f, 0x02, 0x03, 0x00, 0x80, 0x00], // r=127, s=32768
                [0x30, 0x26, 0x02, 0x01, 0x7f, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=127, s=-1
                [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x00], // r=128, s=0
                [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01], // r=128, s=1
                [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x7f], // r=128, s=127
                [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x80], // r=128, s=128
                [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x7f, 0xff], // r=128, s=32767
                [0x30, 0x09, 0x02, 0x02, 0x00, 0x80, 0x02, 0x03, 0x00, 0x80, 0x00], // r=128, s=32768
                [0x30, 0x27, 0x02, 0x02, 0x00, 0x80, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=128, s=-1
                [0x30, 0x07, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x01, 0x00], // r=32767, s=0
                [0x30, 0x07, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x01, 0x01], // r=32767, s=1
                [0x30, 0x07, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x01, 0x7f], // r=32767, s=127
                [0x30, 0x08, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x02, 0x00, 0x80], // r=32767, s=128
                [0x30, 0x08, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x02, 0x7f, 0xff], // r=32767, s=32767
                [0x30, 0x09, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x03, 0x00, 0x80, 0x00], // r=32767, s=32768
                [0x30, 0x27, 0x02, 0x02, 0x7f, 0xff, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=32767, s=-1
                [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x00], // r=32768, s=0
                [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x01], // r=32768, s=1
                [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x01, 0x7f], // r=32768, s=127
                [0x30, 0x09, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x02, 0x00, 0x80], // r=32768, s=128
                [0x30, 0x09, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x02, 0x7f, 0xff], // r=32768, s=32767
                [0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x03, 0x00, 0x80, 0x00], // r=32768, s=32768
                [0x30, 0x28, 0x02, 0x03, 0x00, 0x80, 0x00, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=32768, s=-1
                [0x30, 0x26, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x01, 0x00], // r=-1, s=0
                [0x30, 0x26, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x01, 0x01], // r=-1, s=1
                [0x30, 0x26, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x01, 0x7f], // r=-1, s=127
                [0x30, 0x27, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x02, 0x00, 0x80], // r=-1, s=128
                [0x30, 0x27, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x02, 0x7f, 0xff], // r=-1, s=32767
                [0x30, 0x28, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x03, 0x00, 0x80, 0x00], // r=-1, s=32768
                [0x30, 0x46, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50], // r=-1, s=-1
              ],
              [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, -1],
            );
          };
          let toNat = func(v : Int) : Curve.FrElt {
            let a = #fr(Int.abs(v));
            if (v >= 0) a else C.Fr.neg(a);
          };
          let n = vTbl.size();
          var i = 0;
          while (i < n) {
            let r = toNat(vTbl[i]);
            var j = 0;
            while (j < n) {
              let s = toNat(vTbl[j]);
              let der = tbl[i * n + j];
              switch (Signature.fromBytes(der.vals(), curve, #der)) {
                case (#err(e)) Debug.trap("Failed to parse DER Signature: " # e);
                case (#ok(sig)) {
                  // Calculate expected r and s after normalization
                  let expectedR = r;
                  let #fr(rHalf) = curve.Fr.fromNat(curve.params.rHalf);
                  let #fr(s_value) = s;

                  // If s > curve.params.rHalf, expect the normalized value
                  let expectedS = if (s_value > rHalf) {
                    curve.Fr.neg(s);
                  } else {
                    s;
                  };

                  if (#fr(sig.r) != expectedR or #fr(sig.s) != expectedS) {
                    Debug.trap(
                      "Signature mismatch after normalization for i=" #
                      debug_show (i) # ",j=" # debug_show (j) # ": \nExpected\n" #
                      "r - " # debug_show (expectedR) # "\ns - " # debug_show (expectedS) #
                      "\nActual\n" # "r - " # debug_show (#fr(sig.r)) #
                      "\ns - " # debug_show (#fr(sig.s))
                    );
                  };
                  // Check if serialized DER matches the original
                  let actualDer = sig.toBytes(#der);
                  if (actualDer != der) {
                    Debug.trap(
                      "DER serialization mismatch for i=" # debug_show (i) #
                      ",j=" # debug_show (j) # ": \nExpected DER\n" #
                      debug_show (der) # "\nActual DER\n" # debug_show (actualDer)
                    );
                  };
                };
              };
              j += 1;
            };
            i += 1;
          };
        },
      );

      test(
        "ngEdgeTest",
        func() {
          let badTbl : [[Nat8]] = [
            [0x31 /* bad header */, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            [0x30, 0x07 /* bad length */, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            [0x30],
            [0x30, 0x80 /* too long*/],
            [0x30, 0x06, 0x01 /* bad marker */, 0x01, 0x00, 0x02, 0x01, 0x00],
            [0x30, 0x06, 0x02],
            [0x30, 0x06, 0x02, 0x00],
            [0x30, 0x06, 0x02, 0x11 /* too large */, 0x00, 0x02, 0x01, 0x00],
            [0x30, 0x06, 0x02, 0x01, 0x80 /*negative*/, 0x02, 0x01, 0x00],
          ];
          for (b in badTbl.vals()) {
            switch (Signature.fromBytes(b.vals(), curve, #der)) {
              case (#err(_)) ();
              case (#ok(_)) Debug.trap("Failed to reject bad DER Signature: " # debug_show (b));
            };
          };
          do {
            let correct : [Nat8] = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
            let n = correct.size();
            var i = 0;
            while (i < n) {
              let b = IterTools.take(correct.vals(), i);

              switch (Signature.fromBytes(b, curve, #der)) {
                case (#err(_)) ();
                case (#ok(_)) Debug.trap("Failed to reject bad DER Signature: " # debug_show (i));
              };
              i += 1;
            };
          };
        },
      );
    },
  );

  test(
    "privateKeySerializeTest",
    func() {
      let asn1AlgorithmIdentifier = func(curveKind : Curve.CurveKind) : ASN1.ASN1Value {
        let (curveOid, curveParams) : (ASN1.ASN1Value, ASN1.ASN1Value) = switch (curveKind) {
          case (#secp256k1) (#objectIdentifier([1, 3, 132, 0, 10]), #null_);
          case (#prime256v1) (#objectIdentifier([1, 2, 840, 10045, 3, 1, 7]), #null_);
        };
        #sequence([
          curveOid,
          curveParams,
        ]);
      };

      let privateKeyVal = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;

      let privateKey = PrivateKey.PrivateKey(privateKeyVal, curve);
      let publicKey = privateKey.getPublicKey();

      // Test serialization to raw format (32 bytes)
      let rawBytes = Util.toBigEndianPad(32, privateKeyVal);

      // Test parsing from raw format
      let #ok(parsedFromRaw) = PrivateKey.fromBytes(rawBytes.vals(), #raw({ curve })) else Debug.trap("Failed to parse raw bytes");
      assert (parsedFromRaw.curve.kind == curve.kind);
      assert (parsedFromRaw.d == privateKeyVal);
      assert (parsedFromRaw.getPublicKey().equal(publicKey));

      // Test serialization to DER format
      let asn1 : ASN1.ASN1Value = #sequence([
        #integer(1),
        asn1AlgorithmIdentifier(curveKind),
        #octetString(rawBytes),
        #null_,
      ]);
      let derBytes = ASN1.encodeDER(asn1);

      // Test parsing from DER format
      let #ok(parsedFromDer) = PrivateKey.fromBytes(derBytes.vals(), #der) else Debug.trap("Failed to parse DER bytes");
      assert (parsedFromDer.d == privateKeyVal);
      assert (parsedFromDer.getPublicKey().equal(publicKey));
    },
  );

  test(
    "privateKeyEdgeCasesTest",
    func() {
      // Test parsing invalid keys
      let assertIsErr = func(key : Result.Result<PrivateKey.PrivateKey, Text>, label_ : Text) {
        switch (key) {
          case (#err(_)) ();
          case (#ok(_)) {
            // If the key is not null, it should be a valid private key
            Debug.trap("Expected #err key for '" # label_ # "', but got a valid key");
          };
        };
      };

      // Empty bytes
      let emptyBytes : [Nat8] = [];
      assertIsErr(PrivateKey.fromBytes(emptyBytes.vals(), #raw({ curve })), "empty raw");
      assertIsErr(PrivateKey.fromBytes(emptyBytes.vals(), #der), "empty der");

      // Invalid DER structure
      let invalidDer : [Nat8] = [0x30, 0x03, 0x02, 0x01, 0x01]; // Too short
      assertIsErr(PrivateKey.fromBytes(invalidDer.vals(), #der), "invalid der");

      // Zero value (invalid for EC private key)
      let zeroKeyRaw = Array.tabulate<Nat8>(32, func(_) = 0);
      assertIsErr(PrivateKey.fromBytes(zeroKeyRaw.vals(), #raw({ curve })), "zero raw");

      // Value >= curve order (invalid for EC private key)
      let tooLargeValue = curve.params.r;
      let tooLargeKeyRaw = Util.toBigEndianPad(32, tooLargeValue);
      assertIsErr(PrivateKey.fromBytes(tooLargeKeyRaw.vals(), #raw({ curve })), "too large raw");
    },
  );

  test(
    "publicKeyFromBytes",
    func() {
      let (x, y, key) : (Nat, Nat, Blob) = switch (curveKind) {
        case (#secp256k1) (
          38_429_425_455_415_631_134_142_539_000_605_002_670_886_210_329_907_085_845_074_048_940_350_736_307_511,
          575_828_099_184_175_788_894_911_350_722_390_938_371_747_048_717_700_577_109_830_429_869_990_220_126,
          "\30\56\30\10\06\07\2a\86\48\ce\3d\02\01\06\05\2b\81\04\00\0a\03\42\00\04\54\f6\48\b4\aa\86\75\98\ec\a3\36\59\85\5a\2e\99\bf\35\22\b9\38\a3\dd\3c\d3\08\e4\5c\42\da\15\37\01\45\e8\3b\45\b7\26\ad\23\f5\ba\f6\9f\68\46\0e\27\d2\e7\66\cc\7e\d2\fd\6e\ca\90\ae\33\d8\11\5e",
        );
        case (#prime256v1) (
          8_246_848_202_158_231_730_716_563_389_865_169_855_763_682_067_620_766_047_489_138_422_753_650_078_002,
          4_581_609_636_742_156_842_656_836_398_542_464_111_512_942_411_741_276_644_977_917_616_723_361_211_554,
          "\30\59\30\13\06\07\2a\86\48\ce\3d\02\01\06\08\2a\86\48\ce\3d\03\01\07\03\42\00\04\12\3b\8c\f8\c0\97\44\89\7e\dc\31\52\2d\7c\ad\e9\49\37\b8\43\01\ae\b2\a8\1c\50\58\ed\cf\88\f1\32\0a\21\19\62\72\4f\a3\c4\c1\e4\16\af\1c\3f\9d\78\46\77\53\3d\b9\68\dd\0d\a4\76\28\d0\0f\0b\24\a2",
        );
      };
      switch (PublicKey.fromBytes(key.vals(), #der)) {
        case (#err(e)) Debug.trap("Failed to parse public key: " # debug_show (e));
        case (#ok(publicKey)) {
          assert (publicKey.curve.kind == curveKind);
          if (publicKey.x != x or publicKey.y != y) {
            Debug.trap("Public key mismatch:\nExpected\nx=" # debug_show (x) # "\ny=" # debug_show (y) # "\nActual\nx=" # debug_show (publicKey.x) # "\ny=" # debug_show (publicKey.y));
          };
        };
      };
    },
  );

  test(
    "publicKeyToText",
    func() {
      type TestCase = {
        x : Nat;
        y : Nat;
        outputs : [{
          format : PublicKey.OutputTextFormat;
          inputFormat : ?PublicKey.InputTextFormat;
          expectedText : Text;
        }];
      };
      let testCases : [TestCase] = switch (curveKind) {
        case (#secp256k1) [{
          x = 38_429_425_455_415_631_134_142_539_000_605_002_670_886_210_329_907_085_845_074_048_940_350_736_307_511;
          y = 575_828_099_184_175_788_894_911_350_722_390_938_371_747_048_717_700_577_109_830_429_869_990_220_126;
          outputs = [
            {
              format = #hex({
                format = {
                  isUpper = false;
                  prefix = #single("0x");
                };
                byteEncoding = #der;
              });
              inputFormat = ?#hex({
                format = {
                  prefix = #single("0x");
                };
                byteEncoding = #der;
              });
              expectedText = "0x3056301006072a8648ce3d020106052b8104000a0342000454f648b4aa867598eca33659855a2e99bf3522b938a3dd3cd308e45c42da15370145e83b45b726ad23f5baf69f68460e27d2e766cc7ed2fd6eca90ae33d8115e";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #none;
                };
                byteEncoding = #compressed;
              });
              inputFormat = ?#hex({
                format = {
                  prefix = #none;
                };
                byteEncoding = #raw({ curve });
              });
              expectedText = "0254F648B4AA867598ECA33659855A2E99BF3522B938A3DD3CD308E45C42DA1537";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #perByte("\\x");
                };
                byteEncoding = #uncompressed;
              });
              inputFormat = ?#hex({
                format = {
                  prefix = #perByte("\\x");
                };
                byteEncoding = #raw({ curve });
              });
              expectedText = "\\x04\\x54\\xF6\\x48\\xB4\\xAA\\x86\\x75\\x98\\xEC\\xA3\\x36\\x59\\x85\\x5A\\x2E\\x99\\xBF\\x35\\x22\\xB9\\x38\\xA3\\xDD\\x3C\\xD3\\x08\\xE4\\x5C\\x42\\xDA\\x15\\x37\\x01\\x45\\xE8\\x3B\\x45\\xB7\\x26\\xAD\\x23\\xF5\\xBA\\xF6\\x9F\\x68\\x46\\x0E\\x27\\xD2\\xE7\\x66\\xCC\\x7E\\xD2\\xFD\\x6E\\xCA\\x90\\xAE\\x33\\xD8\\x11\\x5E";
            },
            {
              format = #base64({
                isUriSafe = false;
                byteEncoding = #der;
              });
              inputFormat = ?#base64({
                byteEncoding = #der;
              });
              expectedText = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEVPZItKqGdZjsozZZhVoumb81Irk4o9080wjkXELaFTcBReg7RbcmrSP1uvafaEYOJ9LnZsx+0v1uypCuM9gRXg==";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #der;
              });
              inputFormat = ?#base64({
                byteEncoding = #der;
              });
              expectedText = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEVPZItKqGdZjsozZZhVoumb81Irk4o9080wjkXELaFTcBReg7RbcmrSP1uvafaEYOJ9LnZsx-0v1uypCuM9gRXg";
            },
            {
              format = #pem;
              inputFormat = ?#pem;
              expectedText = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEVPZItKqGdZjsozZZhVoumb81Irk4o908\n0wjkXELaFTcBReg7RbcmrSP1uvafaEYOJ9LnZsx+0v1uypCuM9gRXg==\n-----END PUBLIC KEY-----";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #uncompressed;
              });
              inputFormat = ?#base64({
                byteEncoding = #raw({ curve });
              });
              expectedText = "BFT2SLSqhnWY7KM2WYVaLpm_NSK5OKPdPNMI5FxC2hU3AUXoO0W3Jq0j9br2n2hGDifS52bMftL9bsqQrjPYEV4";
            },
            {
              format = #jwk;
              inputFormat = null;
              expectedText = "{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"x\":\"VPZItKqGdZjsozZZhVoumb81Irk4o9080wjkXELaFTc\",\"y\":\"AUXoO0W3Jq0j9br2n2hGDifS52bMftL9bsqQrjPYEV4\"}";
            },
          ];
        }];
        case (#prime256v1) [{
          x = 8_246_848_202_158_231_730_716_563_389_865_169_855_763_682_067_620_766_047_489_138_422_753_650_078_002;
          y = 4_581_609_636_742_156_842_656_836_398_542_464_111_512_942_411_741_276_644_977_917_616_723_361_211_554;
          outputs = [
            {
              format = #hex({
                format = {
                  isUpper = false;
                  prefix = #single("0x");
                };
                byteEncoding = #der;
              });
              inputFormat = ?#hex({
                format = {
                  prefix = #single("0x");
                };
                byteEncoding = #der;
              });
              expectedText = "0x3059301306072a8648ce3d020106082a8648ce3d03010703420004123b8cf8c09744897edc31522d7cade94937b84301aeb2a81c5058edcf88f1320a211962724fa3c4c1e416af1c3f9d784677533db968dd0da47628d00f0b24a2";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #none;
                };
                byteEncoding = #compressed;
              });
              inputFormat = ?#hex({
                format = {
                  prefix = #none;
                };
                byteEncoding = #raw({ curve });
              });
              expectedText = "02123B8CF8C09744897EDC31522D7CADE94937B84301AEB2A81C5058EDCF88F132";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #perByte("\\x");
                };
                byteEncoding = #uncompressed;
              });
              inputFormat = ?#hex({
                format = {
                  prefix = #perByte("\\x");
                };
                byteEncoding = #raw({ curve });
              });
              expectedText = "\\x04\\x12\\x3B\\x8C\\xF8\\xC0\\x97\\x44\\x89\\x7E\\xDC\\x31\\x52\\x2D\\x7C\\xAD\\xE9\\x49\\x37\\xB8\\x43\\x01\\xAE\\xB2\\xA8\\x1C\\x50\\x58\\xED\\xCF\\x88\\xF1\\x32\\x0A\\x21\\x19\\x62\\x72\\x4F\\xA3\\xC4\\xC1\\xE4\\x16\\xAF\\x1C\\x3F\\x9D\\x78\\x46\\x77\\x53\\x3D\\xB9\\x68\\xDD\\x0D\\xA4\\x76\\x28\\xD0\\x0F\\x0B\\x24\\xA2";
            },
            {
              format = #base64({
                isUriSafe = false;
                byteEncoding = #der;
              });
              inputFormat = ?#base64({
                byteEncoding = #der;
              });
              expectedText = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEjuM+MCXRIl+3DFSLXyt6Uk3uEMBrrKoHFBY7c+I8TIKIRlick+jxMHkFq8cP514RndTPblo3Q2kdijQDwskog==";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #der;
              });
              inputFormat = ?#base64({
                byteEncoding = #der;
              });
              expectedText = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEjuM-MCXRIl-3DFSLXyt6Uk3uEMBrrKoHFBY7c-I8TIKIRlick-jxMHkFq8cP514RndTPblo3Q2kdijQDwskog";
            },
            {
              format = #pem;
              inputFormat = ?#pem;
              expectedText = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEjuM+MCXRIl+3DFSLXyt6Uk3uEMB\nrrKoHFBY7c+I8TIKIRlick+jxMHkFq8cP514RndTPblo3Q2kdijQDwskog==\n-----END PUBLIC KEY-----";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #uncompressed;
              });
              inputFormat = ?#base64({
                byteEncoding = #raw({ curve });
              });
              expectedText = "BBI7jPjAl0SJftwxUi18relJN7hDAa6yqBxQWO3PiPEyCiEZYnJPo8TB5BavHD-deEZ3Uz25aN0NpHYo0A8LJKI";
            },
            {
              format = #jwk;
              inputFormat = null;
              expectedText = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"EjuM-MCXRIl-3DFSLXyt6Uk3uEMBrrKoHFBY7c-I8TI\",\"y\":\"CiEZYnJPo8TB5BavHD-deEZ3Uz25aN0NpHYo0A8LJKI\"}";
            },
          ];
        }];
      };
      for ({ x; y; outputs } in testCases.vals()) {
        let key = PublicKey.PublicKey(x, y, curve);
        for ({ format; inputFormat; expectedText } in outputs.vals()) {
          let actualText = key.toText(format);
          if (actualText != expectedText) {
            Debug.trap("Public key text mismatch:\nExpected\n" # expectedText # "\nActual\n" # actualText);
          };
          switch (inputFormat) {
            case (null) ();
            case (?inputFormat) {
              switch (PublicKey.fromText(actualText, inputFormat)) {
                case (#err(e)) Debug.trap("Failed to parse public key from text: " # debug_show (e) # "\nText: " # actualText);
                case (#ok(parsedKey)) {
                  assert (parsedKey.curve.kind == curve.kind);
                  if (parsedKey.x != x or parsedKey.y != y) {
                    Debug.trap("Parsed public key mismatch:\nExpected\nx=" # debug_show (x) # "\ny=" # debug_show (y) # "\nActual\nx=" # debug_show (parsedKey.x) # "\ny=" # debug_show (parsedKey.y));
                  };
                };
              };
            };
          };
        };
      };
    },
  );

  test(
    "privateKeyToText",
    func() {
      type TestCase = {
        d : Nat;
        outputs : [{
          format : PrivateKey.OutputTextFormat;
          expectedText : Text;
        }];
      };
      let testCases : [TestCase] = switch (curveKind) {
        case (#secp256k1) [{
          d = 0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2;
          outputs = [
            {
              format = #hex({
                format = {
                  isUpper = false;
                  prefix = #single("0x");
                };
                byteEncoding = #der;
              });
              expectedText = "0x308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420b1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da20500034200040a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3da53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #none;
                };
                byteEncoding = #raw;
              });
              expectedText = "B1AA6282B14E5FFBF6D12F783612F804E6A20D1A9734FFBB6C9923C670EE8DA2";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #perByte("\\x");
                };
                byteEncoding = #raw;
              });
              expectedText = "\\xB1\\xAA\\x62\\x82\\xB1\\x4E\\x5F\\xFB\\xF6\\xD1\\x2F\\x78\\x36\\x12\\xF8\\x04\\xE6\\xA2\\x0D\\x1A\\x97\\x34\\xFF\\xBB\\x6C\\x99\\x23\\xC6\\x70\\xEE\\x8D\\xA2";
            },
            {
              format = #base64({
                isUriSafe = false;
                byteEncoding = #der;
              });
              expectedText = "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgsapigrFOX/v20S94NhL4BOaiDRqXNP+7bJkjxnDujaIFAANCAAQKCf8ULZS8P1bFyBt16jsGsILFJj+7W9iMYZ/GOT3aPaU+DpMIks23eZ7qj9Rbn/83fYOPQQZFQomuiggLER+N";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #der;
              });
              expectedText = "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgsapigrFOX_v20S94NhL4BOaiDRqXNP-7bJkjxnDujaIFAANCAAQKCf8ULZS8P1bFyBt16jsGsILFJj-7W9iMYZ_GOT3aPaU-DpMIks23eZ7qj9Rbn_83fYOPQQZFQomuiggLER-N";
            },
            {
              format = #pem;
              expectedText = "-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgsapigrFOX/v20S94NhL4\nBOaiDRqXNP+7bJkjxnDujaIFAANCAAQKCf8ULZS8P1bFyBt16jsGsILFJj+7W9iM\nYZ/GOT3aPaU+DpMIks23eZ7qj9Rbn/83fYOPQQZFQomuiggLER+N\n-----END PRIVATE KEY-----";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #raw;
              });
              expectedText = "sapigrFOX_v20S94NhL4BOaiDRqXNP-7bJkjxnDujaI";
            },
          ];
        }];
        case (#prime256v1) []; // Doesn't differ from secp256k1
      };
      for ({ d; outputs } in testCases.vals()) {
        let key = PrivateKey.PrivateKey(d, curve);
        for ({ format; expectedText } in outputs.vals()) {
          let actualText = key.toText(format);
          if (actualText != expectedText) {
            Debug.trap("Public key text mismatch:\nExpected\n" # expectedText # "\nActual\n" # actualText);
          };
        };
      };

    },
  );

  test(
    "signatureToText",
    func() {
      type TestCase = {
        r : Nat;
        s : Nat;
        outputs : [{
          format : Signature.OutputTextFormat;
          expectedText : Text;
        }];
      };
      let testCases : [TestCase] = switch (curveKind) {
        case (#secp256k1) [{
          r = 0xa1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789;
          s = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba;
          outputs = [
            {
              format = #hex({
                format = {
                  isUpper = false;
                  prefix = #single("0x");
                };
                byteEncoding = #der;
              });
              expectedText = "0x3046022100a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef01234567890221009876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #none;
                };
                byteEncoding = #raw;
              });
              expectedText = "A1B2C3D4E5F67890ABCDEF0123456789ABCDEF0123456789ABCDEF01234567899876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA";
            },
            {
              format = #hex({
                format = {
                  isUpper = true;
                  prefix = #perByte("\\x");
                };
                byteEncoding = #raw;
              });
              expectedText = "\\xA1\\xB2\\xC3\\xD4\\xE5\\xF6\\x78\\x90\\xAB\\xCD\\xEF\\x01\\x23\\x45\\x67\\x89\\xAB\\xCD\\xEF\\x01\\x23\\x45\\x67\\x89\\xAB\\xCD\\xEF\\x01\\x23\\x45\\x67\\x89\\x98\\x76\\x54\\x32\\x10\\xFE\\xDC\\xBA\\x98\\x76\\x54\\x32\\x10\\xFE\\xDC\\xBA\\x98\\x76\\x54\\x32\\x10\\xFE\\xDC\\xBA\\x98\\x76\\x54\\x32\\x10\\xFE\\xDC\\xBA";
            },
            {
              format = #base64({
                isUriSafe = false;
                byteEncoding = #der;
              });
              expectedText = "MEYCIQChssPU5fZ4kKvN7wEjRWeJq83vASNFZ4mrze8BI0VniQIhAJh2VDIQ/ty6mHZUMhD+3LqYdlQyEP7cuph2VDIQ/ty6";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #der;
              });
              expectedText = "MEYCIQChssPU5fZ4kKvN7wEjRWeJq83vASNFZ4mrze8BI0VniQIhAJh2VDIQ_ty6mHZUMhD-3LqYdlQyEP7cuph2VDIQ_ty6";
            },
            {
              format = #base64({
                isUriSafe = true;
                byteEncoding = #raw;
              });
              expectedText = "obLD1OX2eJCrze8BI0VniavN7wEjRWeJq83vASNFZ4mYdlQyEP7cuph2VDIQ_ty6mHZUMhD-3LqYdlQyEP7cug";
            },
          ];
        }];
        case (#prime256v1) []; // Doesn't differ from secp256k1
      };

      for ({ r; s; outputs } in testCases.vals()) {
        let signature = Signature.Signature(r, s, curve);
        for ({ format; expectedText } in outputs.vals()) {
          let actualText = signature.toText(format);
          if (actualText != expectedText) {
            Debug.trap("Signature text mismatch:\nExpected\n" # expectedText # "\nActual\n" # actualText);
          };
        };
      };
    },
  );
};
