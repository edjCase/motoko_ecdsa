/// Modular arithmetic on `Nat` values for an arbitrary modulus `n`.
/// Used as the engine behind both `Curve.Fp` and `Curve.Fr`.
///
/// All `*_` functions take an explicit modulus; the `Field` class
/// captures one modulus and exposes the same operations as methods.
/// Inputs are assumed to already be reduced modulo `n`; values larger
/// than `n` produce undefined-but-deterministic results.
///
/// ```motoko name=import
/// import Field "mo:ecdsa/Field";
/// ```

import Int "mo:core@2/Int";

import Binary "./Binary";
import IntExt "./IntExt";

module {
  /// Modular inverse of `x` mod `n`. Traps via `assert` when `x` and `n`
  /// are not coprime (e.g. `x == 0` or `gcd(x, n) > 1`).
  public func inv_(x : Nat, n : Nat) : Nat {
    let (gcd, rev, _) = IntExt.extGcd(x, n);
    assert (gcd == 1);
    let v = if (rev < 0) rev + n else rev;
    assert (0 <= v and v < n);
    Int.abs(v);
  };
  /// Modular addition `(x + y) mod n`.
  public func add_(x : Nat, y : Nat, n : Nat) : Nat {
    let z = x + y;
    if (z < n) z else z - n;
  };
  /// Modular multiplication `(x * y) mod n`.
  public func mul_(x : Nat, y : Nat, n : Nat) : Nat = (x * y) % n;
  /// Modular subtraction `(x - y) mod n`.
  public func sub_(x : Nat, y : Nat, n : Nat) : Nat = if (x >= y) x - y else x + n - y;
  /// Modular division `(x / y) mod n`. Same trap conditions as `inv_`.
  public func div_(x : Nat, y : Nat, n : Nat) : Nat = (x * inv_(y, n)) % n;
  /// Modular negation `(-x) mod n`.
  public func neg_(x : Nat, n : Nat) : Nat = if (x == 0) 0 else n - x;
  /// Modular exponentiation `x^y mod n` via square-and-multiply.
  public func pow_(x : Nat, y : Nat, n : Nat) : Nat {
    if (y == 0) return 1;
    let bs = Binary.fromNatReversed(y);
    let len = bs.size();
    var ret = 1;
    var i = 0;
    while (i < len) {
      let b = bs[len - 1 - i];
      ret := mul_(ret, ret, n);
      if (b) ret := mul_(ret, x, n);
      i += 1;
    };
    ret;
  };
  /// Modular squaring `x^2 mod n`.
  public func sqr_(x : Nat, n : Nat) : Nat = mul_(x, x, n);

  /// Captures a modulus `n` and exposes the modular operations above as
  /// instance methods, removing the per-call `n` argument.
  public class Field(n : Nat) {
    /// Modular addition `(x + y) mod n`.
    public func add(x : Nat, y : Nat) : Nat = add_(x, y, n);
    /// Modular multiplication `(x * y) mod n`.
    public func mul(x : Nat, y : Nat) : Nat = mul_(x, y, n);
    /// Modular subtraction `(x - y) mod n`.
    public func sub(x : Nat, y : Nat) : Nat = sub_(x, y, n);
    /// Modular division `(x / y) mod n`. Traps when `y` is not invertible
    /// modulo `n`.
    public func div(x : Nat, y : Nat) : Nat = div_(x, y, n);
    /// Modular exponentiation `x^y mod n`.
    public func pow(x : Nat, y : Nat) : Nat = pow_(x, y, n);
    /// Modular negation `(-x) mod n`.
    public func neg(x : Nat) : Nat = neg_(x, n);
    /// Modular inverse of `x` mod `n`. Traps when `x` and `n` are not
    /// coprime.
    public func inv(x : Nat) : Nat = inv_(x, n);
    /// Modular squaring `x^2 mod n`.
    public func sqr(x : Nat) : Nat = sqr_(x, n);
  };
};
