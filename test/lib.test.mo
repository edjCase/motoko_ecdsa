import M "../src";
import Field "../src/field";
import Curve "../src/curve";
import Binary "../src/binary";
import Util "../src/util";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Blob "mo:base/Blob";
import Iter "mo:base/Iter";
import Nat8 "mo:base/Nat8";
import P "mo:base/Prelude";
import Debug "mo:base/Debug";
import Array "mo:base/Array";
import { test; suite } "mo:test";

let curveKinds : [Curve.CurveKind] = [
  #secp256k1,
  #prime256v1,
];
for (curveKind in curveKinds.vals()) {

  let (okP1, okP2, okP3, okP4, okP5) = switch (curveKind) {
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
      // 5G
      (
        #fp(0x2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4),
        #fp(0xd8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6),
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
      // 5G - CORRECT NIST value
      (
        #fp(0x51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed),
        #fp(0xe0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4),
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
            ([] : [Nat8], 0x0),
            ([0x12] : [Nat8], 0x12),
            ([0x12, 0x34] : [Nat8], 0x1234),
            ([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0] : [Nat8], 0x123456789abcdef0),
            ([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12] : [Nat8], 0x123456789abcdef012),
          ];
          for (i in tbl.keys()) {
            let (b, v) = tbl[i];
            assert (Util.toNatAsBigEndian(b.vals()) == v);
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

      func gcdTest(f : (Int, Int) -> (Int, Int, Int)) {
        let (gcd1, gcd2, gcd3) = f(100, 37);
        assert (gcd1 == 1);
        assert (gcd2 == 10);
        assert (gcd3 == -27);
        let (a, b, c) = f(0, 37);
        assert (a == 37);
        assert (b == 0);
        assert (c == 1);
      };

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
          assert (Blob.toArray(M.sha2(hello.vals())) == hashed);

          do {
            let secBytes : [Nat8] = [0x83, 0xec, 0xb3, 0x98, 0x4a, 0x4f, 0x9f, 0xf0, 0x3e, 0x84, 0xd5, 0xf9, 0xc0, 0xd7, 0xf8, 0x88, 0xa8, 0x18, 0x33, 0x64, 0x30, 0x47, 0xac, 0xc5, 0x8e, 0xb6, 0x43, 0x1e, 0x01, 0xd9, 0xba, 0xc8];
            let sec = switch (M.getSecretKey(C, secBytes.vals())) {
              case (null) P.unreachable();
              case (?v) v;
            };
            assert (sec == #non_zero(#fr(0x83ecb3984a4f9ff03e84d5f9c0d7f888a81833643047acc58eb6431e01d9bac8)));
            let pub = M.getPublicKey(C, sec);
            assert (C.isEqual(pub, (#fp(0x653bd02ba1367e5d4cd695b6f857d1cd90d4d8d42bc155d85377b7d2d0ed2e71), #fp(0x04e8f5da403ab78decec1f19e2396739ea544e2b14159beb5091b30b418b813a), #fp(1))));

            let rand : [Nat8] = [0x8a, 0xfa, 0x4a, 0x16, 0x2b, 0x7b, 0xad, 0x6c, 0x92, 0xff, 0x14, 0xf3, 0xa8, 0xbf, 0x4d, 0xb0, 0xf3, 0xc3, 0x9e, 0x90, 0xc0, 0x6f, 0x93, 0x78, 0x61, 0xf8, 0x23, 0xd2, 0x99, 0x5c, 0x74, 0xf0];
            let sig = switch (M.signHashed(C, sec, hashed.vals(), rand.vals())) {
              case (null) P.unreachable();
              case (?v) v;
            };
            assert (M.verifyHashed(C, pub, hashed.vals(), sig));
            assert (not M.verifyHashed(C, (pub.0, C.Fp.add(pub.1, #fp(1)), #fp(1)), hashed.vals(), sig));
            assert (not M.verifyHashed(C, pub, ([0x1, 0x2] : [Nat8]).vals(), sig));
            assert (M.sign(C, sec, hello.vals(), rand.vals()) == ?sig);
            assert (M.verifyHashed(C, pub, hashed.vals(), sig));

            let sig2 = M.normalizeSignature(C, (#fr(0xa598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5), #fr(0xde5d79a2ba44e311d04fdca263639283965780bce9169822be9cc81756e95a24)));
            assert (M.verify(C, pub, hello.vals(), sig2));
          };

          // generated values by Python:ecdsa
          do {
            let sec = #non_zero(#fr(0xb1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2));
            let pub = M.getPublicKey(C, sec);
            assert (C.isEqual(pub, (#fp(0x0a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3d), #fp(0xa53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d), #fp(1))));
            let sig = M.normalizeSignature(C, (#fr(0x50839a97404c24ec39455b996e4888477fd61bcf0ffb960c7ffa3bef10450191), #fr(0x9671b8315bb5c1611d422d49cbbe7e80c6b463215bfad1c16ca73172155bf31a)));
            assert (M.verifyHashed(C, pub, hashed.vals(), sig));
          };
        },
      );

      test(
        "serializeTest",
        func() {
          let expected = Blob.fromArray([0x04, 0xa, 0x9, 0xff, 0x14, 0x2d, 0x94, 0xbc, 0x3f, 0x56, 0xc5, 0xc8, 0x1b, 0x75, 0xea, 0x3b, 0x6, 0xb0, 0x82, 0xc5, 0x26, 0x3f, 0xbb, 0x5b, 0xd8, 0x8c, 0x61, 0x9f, 0xc6, 0x39, 0x3d, 0xda, 0x3d, 0xa5, 0x3e, 0xe, 0x93, 0x8, 0x92, 0xcd, 0xb7, 0x79, 0x9e, 0xea, 0x8f, 0xd4, 0x5b, 0x9f, 0xff, 0x37, 0x7d, 0x83, 0x8f, 0x41, 0x6, 0x45, 0x42, 0x89, 0xae, 0x8a, 0x8, 0xb, 0x11, 0x1f, 0x8d]);
          let pub = (#fp(0x0a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3d), #fp(0xa53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d));
          let pubJ : Curve.Jacobi = C.toJacobi(#affine(pub));

          let check = func(ret : ?M.PublicKey, expected : M.PublicKey) {
            switch (ret) {
              case (null) { assert (false) };
              case (?pub) {
                assert (C.isEqual(pub, expected));
              };
            };
          };
          do {
            let v = M.serializePublicKeyUncompressed(C, pub);
            assert (v == expected);
            check(M.deserializePublicKeyUncompressed(C, v), pubJ);
          };
          do {
            let v = M.serializePublicKeyCompressed(C, pub);
            check(M.deserializePublicKeyCompressed(C, v), pubJ);
            let pubNeg = (pub.0, C.Fp.neg(pub.1));
            let v2 = M.serializePublicKeyCompressed(C, pubNeg);
            check(M.deserializePublicKeyCompressed(C, v2), C.toJacobi(#affine(pubNeg)));
          };
        },
      );

      test(
        "derTest",
        func() {
          let sig = (#fr(0xed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f), #fr(0x7a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed));
          let expected : [Nat8] = [0x30, 0x45, 0x02, 0x21, 0x00, 0xed, 0x81, 0xff, 0x19, 0x2e, 0x75, 0xa3, 0xfd, 0x23, 0x04, 0x00, 0x4d, 0xca, 0xdb, 0x74, 0x6f, 0xa5, 0xe2, 0x4c, 0x50, 0x31, 0xcc, 0xfc, 0xf2, 0x13, 0x20, 0xb0, 0x27, 0x74, 0x57, 0xc9, 0x8f, 0x02, 0x20, 0x7a, 0x98, 0x6d, 0x95, 0x5c, 0x6e, 0x0c, 0xb3, 0x5d, 0x44, 0x6a, 0x89, 0xd3, 0xf5, 0x61, 0x00, 0xf4, 0xd7, 0xf6, 0x78, 0x01, 0xc3, 0x19, 0x67, 0x74, 0x3a, 0x9c, 0x8e, 0x10, 0x61, 0x5b, 0xed];
          let der = M.serializeSignatureDer(sig);
          //  Dump.dump(expected.vals());
          //  Dump.dump(Blob.toArray(der).vals());
          assert (Blob.toArray(der) == expected);
          assert (M.deserializeSignatureDer(C, der) == ?sig);
        },
      );

      test(
        "jacobiTest",
        func() {
          let dblP = (#fp(0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5), #fp(0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a));
          let Pa = #affine(C.params.g);
          let Pj = C.toJacobi(Pa);
          assert (Pa == C.fromJacobi(Pj));
          var Qj = C.neg(Pj);
          assert (C.isZero(C.add(Pj, Qj)));
          Qj := C.dbl(Pj);
          var Qa : Curve.Point = #affine(dblP);
          assert (#affine(dblP) == C.fromJacobi(Qj));
          assert (C.isEqual(Qj, C.toJacobi(Qa)));
          var i = 0;
          while (i < 10) {
            Qa := C.fromJacobi(C.add(C.toJacobi(Qa), C.toJacobi(Pa)));
            let R = C.add(Pj, Qj);
            Qj := C.add(Qj, Pj);
            assert (Qa == C.fromJacobi(Qj));
            assert (C.isEqual(Qj, R));
            assert (C.isEqual(Qj, C.toJacobi(Qa)));
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
          let tbl : [[Nat8]] = [
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
          ];
          let vTbl = [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, -1];
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
              let der = Blob.fromArray(tbl[i * n + j]);
              switch (M.deserializeSignatureDer(C, der)) {
                case (null) { assert (false) };
                case (?sig) {
                  assert (sig.0 == r);
                  assert (sig.1 == s);
                  assert (M.serializeSignatureDer(sig) == der);
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
            // (r, s) where s = char(Zn)
            [0x30, 0x26, 0x02, 0x01, 0x00, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41],
            [0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00 /* redundant zero */],
          ];
          for (b in badTbl.vals()) {
            assert (M.deserializeSignatureDer(C, Blob.fromArray(b)) == null);
          };
          do {
            let correct : [Nat8] = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
            let n = correct.size();
            var i = 0;
            while (i < n) {
              let b = Blob.fromArray(Util.subArray(correct, 0, i));
              assert (M.deserializeSignatureDer(C, b) == null);
              i += 1;
            };
          };
        },
      );
    },
  );
};
