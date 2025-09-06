import List "mo:core@1/List";

module {
  // 13 = 0b1101 => [true,false,true,true]
  public func fromNatReversed(x : Nat) : [Bool] {
    var buf = List.empty<Bool>();
    var t = x;
    while (t > 0) {
      List.add(buf, (t % 2) == 1);
      t /= 2;
    };
    List.toArray(buf);
  };
  // getNAF
  public func toNafWidth(x_ : Int, _w : Int) : [Int] {
    var naf = List.empty<Int>();
    let w = 5;
    let signedMaxW : Int = 2 ** (w - 1);
    let maxW = signedMaxW * 2;
    let negative = x_ < 0;
    var x = if (x_ < 0) -x_ else x_;
    var zeroNum = 0;
    while (x > 0) {
      while ((x % 2) == 0) {
        x /= 2;
        zeroNum += 1;
      };
      do {
        var i = 0;
        while (i < zeroNum) {
          List.add(naf, 0);
          i += 1;
        };
      };
      var v = x % maxW;
      x /= maxW;
      if (v >= signedMaxW) {
        x += 1;
        v -= maxW;
      };
      List.add(naf, v);
      zeroNum := w - 1;
    };
    if (negative) {
      var i = 0;
      while (i < List.size(naf)) {
        List.put(naf, i, -List.at(naf, i));
        i += 1;
      };
    };
    List.toArray(naf);
  };
};
