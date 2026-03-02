// File: src/ciphers/CipherClasses.js
import { MathUtils } from "../utils/MathUtils.js";

/**
 * Base Class (Induk) untuk semua algoritma
 */
class BaseCipher {
  encrypt(text) {
    throw new Error("Method encrypt() harus diimplementasikan");
  }
  decrypt(text) {
    throw new Error("Method decrypt() harus diimplementasikan");
  }
}

export class VigenereCipher extends BaseCipher {
  constructor(key) {
    super();
    if (!key) throw new Error("Kunci Vigenere tidak boleh kosong.");
    this.key = key;
  }

  _process(text, isDecrypt) {
    let result = "";
    for (let i = 0, j = 0; i < text.length; i++) {
      let p = text.charCodeAt(i) - 65;
      let k = this.key.charCodeAt(j % this.key.length) - 65;
      let c = isDecrypt ? MathUtils.mod(p - k, 26) : MathUtils.mod(p + k, 26);
      result += String.fromCharCode(c + 65);
      j++;
    }
    return result;
  }

  encrypt(text) {
    return this._process(text, false);
  }
  decrypt(text) {
    return this._process(text, true);
  }
}

export class AffineCipher extends BaseCipher {
  constructor(a, b) {
    super();
    if (isNaN(a) || isNaN(b))
      throw new Error("Kunci 'a' dan 'b' harus berupa angka.");
    if (MathUtils.gcd(a, 26) !== 1)
      throw new Error("Kunci 'a' tidak valid! Harus koprima dengan 26.");
    this.a = a;
    this.b = b;
    this.aInv = MathUtils.modInverse(a, 26);
  }

  encrypt(text) {
    let result = "";
    for (let i = 0; i < text.length; i++) {
      let p = text.charCodeAt(i) - 65;
      let c = MathUtils.mod(this.a * p + this.b, 26);
      result += String.fromCharCode(c + 65);
    }
    return result;
  }

  decrypt(text) {
    let result = "";
    for (let i = 0; i < text.length; i++) {
      let p = text.charCodeAt(i) - 65;
      let c = MathUtils.mod(this.aInv * (p - this.b), 26);
      result += String.fromCharCode(c + 65);
    }
    return result;
  }
}

export class PlayfairCipher extends BaseCipher {
  constructor(key) {
    super();
    if (!key) throw new Error("Keyword Playfair tidak boleh kosong.");
    this.matrix = this._buildMatrix(key);
  }

  _buildMatrix(key) {
    key = key.replace(/J/g, "I");
    let matrix = [];
    let used = new Set();
    for (let char of key) {
      if (!used.has(char)) {
        matrix.push(char);
        used.add(char);
      }
    }
    for (let i = 0; i < 26; i++) {
      let char = String.fromCharCode(i + 65);
      if (char === "J") continue;
      if (!used.has(char)) {
        matrix.push(char);
        used.add(char);
      }
    }
    return matrix;
  }

  _getPos(char) {
    let index = this.matrix.indexOf(char === "J" ? "I" : char);
    return { r: Math.floor(index / 5), c: index % 5 };
  }

  _process(text, isDecrypt) {
    let pairs = [];
    text = text.replace(/J/g, "I");
    if (!isDecrypt) {
      for (let i = 0; i < text.length; i++) {
        let c1 = text[i],
          c2 = text[i + 1];
        if (!c2) {
          pairs.push([c1, "X"]);
          break;
        }
        if (c1 === c2) {
          pairs.push([c1, "X"]);
        } else {
          pairs.push([c1, c2]);
          i++;
        }
      }
    } else {
      if (text.length % 2 !== 0)
        throw new Error("Ciphertext Playfair (jumlah huruf ganjil).");
      for (let i = 0; i < text.length; i += 2)
        pairs.push([text[i], text[i + 1]]);
    }

    let result = "";
    let shift = isDecrypt ? -1 : 1;
    for (let [a, b] of pairs) {
      let posA = this._getPos(a),
        posB = this._getPos(b);
      if (posA.r === posB.r) {
        result += this.matrix[posA.r * 5 + MathUtils.mod(posA.c + shift, 5)];
        result += this.matrix[posB.r * 5 + MathUtils.mod(posB.c + shift, 5)];
      } else if (posA.c === posB.c) {
        result += this.matrix[MathUtils.mod(posA.r + shift, 5) * 5 + posA.c];
        result += this.matrix[MathUtils.mod(posB.r + shift, 5) * 5 + posB.c];
      } else {
        result += this.matrix[posA.r * 5 + posB.c];
        result += this.matrix[posB.r * 5 + posA.c];
      }
    }
    return result;
  }

  encrypt(text) {
    return this._process(text, false);
  }
  decrypt(text) {
    return this._process(text, true);
  }
}

export class HillCipher extends BaseCipher {
  constructor(k11, k12, k21, k22) {
    super();
    if ([k11, k12, k21, k22].some(isNaN))
      throw new Error("Semua sel matriks kunci harus diisi.");

    let det = k11 * k22 - k12 * k21;
    let detMod = MathUtils.mod(det, 26);
    this.invDet = MathUtils.modInverse(detMod, 26);

    if (this.invDet === -1)
      throw new Error(`Matriks tidak memiliki invers (Det: ${det}).`);

    this.encMatrix = [
      MathUtils.mod(k11, 26),
      MathUtils.mod(k12, 26),
      MathUtils.mod(k21, 26),
      MathUtils.mod(k22, 26),
    ];
    this.decMatrix = [
      MathUtils.mod(k22 * this.invDet, 26),
      MathUtils.mod(-k12 * this.invDet, 26),
      MathUtils.mod(-k21 * this.invDet, 26),
      MathUtils.mod(k11 * this.invDet, 26),
    ];
  }

  _process(text, matrix) {
    let result = "";
    for (let i = 0; i < text.length; i += 2) {
      let p1 = text.charCodeAt(i) - 65;
      let p2 = text.charCodeAt(i + 1) - 65;
      let c1 = MathUtils.mod(matrix[0] * p1 + matrix[1] * p2, 26);
      let c2 = MathUtils.mod(matrix[2] * p1 + matrix[3] * p2, 26);
      result += String.fromCharCode(c1 + 65) + String.fromCharCode(c2 + 65);
    }
    return result;
  }

  encrypt(text) {
    if (text.length % 2 !== 0) text += "X";
    return this._process(text, this.encMatrix);
  }

  decrypt(text) {
    if (text.length % 2 !== 0)
      throw new Error("Ciphertext Hill tidak valid (ganjil).");
    return this._process(text, this.decMatrix);
  }
}

export class EnigmaCipher extends BaseCipher {
  constructor(config) {
    super();
    if (!config.posL || !config.posM || !config.posR)
      throw new Error("Posisi rotor awal tidak valid.");
    this.config = config;
    this.ROTOR_WIRING = {
      I: "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
      II: "AJDKSIRUXBLHWTMCQGZNPYFVOE",
      III: "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    };
    this.ROTOR_NOTCH = { I: 16, II: 4, III: 21 };
    this.REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT";
  }

  _passRotor(charIndex, type, pos, isReverse) {
    let wire = this.ROTOR_WIRING[type];
    let contactIn = MathUtils.mod(charIndex + pos, 26);
    if (!isReverse) {
      let wiredChar = wire.charCodeAt(contactIn) - 65;
      return MathUtils.mod(wiredChar - pos, 26);
    } else {
      let wiredChar = wire.indexOf(String.fromCharCode(contactIn + 65));
      return MathUtils.mod(wiredChar - pos, 26);
    }
  }

  _process(text) {
    let posL = this.config.posL.charCodeAt(0) - 65;
    let posM = this.config.posM.charCodeAt(0) - 65;
    let posR = this.config.posR.charCodeAt(0) - 65;
    let result = "";

    for (let i = 0; i < text.length; i++) {
      let charIndex = text.charCodeAt(i) - 65;

      // Stepping
      let atNotchM = posM === this.ROTOR_NOTCH[this.config.typeM];
      let atNotchR = posR === this.ROTOR_NOTCH[this.config.typeR];

      posR = MathUtils.mod(posR + 1, 26);
      if (atNotchR || atNotchM) {
        posM = MathUtils.mod(posM + 1, 26);
        if (atNotchM) posL = MathUtils.mod(posL + 1, 26);
      }

      // Maju -> Reflektor -> Mundur
      charIndex = this._passRotor(charIndex, this.config.typeR, posR, false);
      charIndex = this._passRotor(charIndex, this.config.typeM, posM, false);
      charIndex = this._passRotor(charIndex, this.config.typeL, posL, false);
      charIndex = this.REFLECTOR_B.charCodeAt(charIndex) - 65;
      charIndex = this._passRotor(charIndex, this.config.typeL, posL, true);
      charIndex = this._passRotor(charIndex, this.config.typeM, posM, true);
      charIndex = this._passRotor(charIndex, this.config.typeR, posR, true);

      result += String.fromCharCode(charIndex + 65);
    }
    return result;
  }

  // Enigma bersifat resiprokal (Enkripsi dan Dekripsi menggunakan jalur yang sama)
  encrypt(text) {
    return this._process(text);
  }
  decrypt(text) {
    return this._process(text);
  }
}
