// File: src/utils/MathUtils.js

export const MathUtils = {
  // Modulo yang valid untuk angka negatif
  mod: (n, m) => ((n % m) + m) % m,

  // Pencarian FPB (Greatest Common Divisor)
  gcd: function (a, b) {
    return b === 0 ? a : this.gcd(b, a % b);
  },

  // Pencarian Invers Modulo: (a * x) % m == 1
  modInverse: function (a, m) {
    let aMod = this.mod(a, m);
    for (let x = 1; x < m; x++) {
      if (this.mod(aMod * x, m) === 1) return x;
    }
    return -1;
  },
};
