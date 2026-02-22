// ==========================================
// MODUL 1: FUNGSI MATEMATIKA (MathUtils)
// ==========================================
const MathUtils = {
  // Modulo yang valid untuk angka negatif
  mod: function (n, m) {
    return ((n % m) + m) % m;
  },

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
    return -1; // -1 berarti tidak ada invers
  },
};

// ==========================================
// MODUL 2: ALGORITMA CIPHER (Ciphers)
// Mengisolasi logika enkripsi dari komponen UI
// ==========================================
const Ciphers = {
  // --- A. Vigenere Cipher ---
  vigenere: function (text, isDecrypt, key) {
    if (!key)
      throw new Error(
        "Kunci Vigenere tidak boleh kosong dan harus berisi alfabet.",
      );
    let result = "";
    for (let i = 0, j = 0; i < text.length; i++) {
      let p = text.charCodeAt(i) - 65;
      let k = key.charCodeAt(j % key.length) - 65;
      let c = isDecrypt ? MathUtils.mod(p - k, 26) : MathUtils.mod(p + k, 26);
      result += String.fromCharCode(c + 65);
      j++;
    }
    return result;
  },

  // --- B. Affine Cipher ---
  affine: function (text, isDecrypt, a, b) {
    if (isNaN(a) || isNaN(b))
      throw new Error("Kunci 'a' dan 'b' harus berupa angka.");
    if (MathUtils.gcd(a, 26) !== 1)
      throw new Error(
        "Kunci 'a' tidak valid! Harus bernilai koprima dengan 26.",
      );

    let aInv = MathUtils.modInverse(a, 26);
    let result = "";

    for (let i = 0; i < text.length; i++) {
      let p = text.charCodeAt(i) - 65;
      let c = isDecrypt
        ? MathUtils.mod(aInv * (p - b), 26)
        : MathUtils.mod(a * p + b, 26);
      result += String.fromCharCode(c + 65);
    }
    return result;
  },

  // --- C. Playfair Cipher ---
  playfair: function (text, isDecrypt, key) {
    if (!key) throw new Error("Keyword Playfair tidak boleh kosong.");

    // 1. Matriks 5x5
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

    function getPos(char) {
      let index = matrix.indexOf(char === "J" ? "I" : char);
      return { r: Math.floor(index / 5), c: index % 5 };
    }

    // 2. Padding/Pairs Preparation
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

    // 3. Eksekusi Geser/Tukar
    let result = "";
    for (let [a, b] of pairs) {
      let posA = getPos(a),
        posB = getPos(b);
      let shift = isDecrypt ? -1 : 1;

      if (posA.r === posB.r) {
        result += matrix[posA.r * 5 + MathUtils.mod(posA.c + shift, 5)];
        result += matrix[posB.r * 5 + MathUtils.mod(posB.c + shift, 5)];
      } else if (posA.c === posB.c) {
        result += matrix[MathUtils.mod(posA.r + shift, 5) * 5 + posA.c];
        result += matrix[MathUtils.mod(posB.r + shift, 5) * 5 + posB.c];
      } else {
        result += matrix[posA.r * 5 + posB.c];
        result += matrix[posB.r * 5 + posA.c];
      }
    }
    return result;
  },

  // --- D. Hill Cipher ---
  hill: function (text, isDecrypt, matrixInput) {
    if (matrixInput.some(isNaN))
      throw new Error("Semua sel matriks kunci Hill harus diisi angka.");

    let [k11, k12, k21, k22] = matrixInput;
    let det = k11 * k22 - k12 * k21;
    let detMod = MathUtils.mod(det, 26);
    let invDet = MathUtils.modInverse(detMod, 26);

    if (invDet === -1)
      throw new Error(
        `Matriks tidak valid! Determinan (${det}) tidak memiliki invers.`,
      );

    let matrix = [];
    if (isDecrypt) {
      matrix = [
        MathUtils.mod(k22 * invDet, 26),
        MathUtils.mod(-k12 * invDet, 26),
        MathUtils.mod(-k21 * invDet, 26),
        MathUtils.mod(k11 * invDet, 26),
      ];
    } else {
      matrix = [
        MathUtils.mod(k11, 26),
        MathUtils.mod(k12, 26),
        MathUtils.mod(k21, 26),
        MathUtils.mod(k22, 26),
      ];
    }

    if (text.length % 2 !== 0 && !isDecrypt) text += "X";
    if (text.length % 2 !== 0 && isDecrypt)
      throw new Error("Ciphertext Hill tidak valid (ganjil).");

    let result = "";
    for (let i = 0; i < text.length; i += 2) {
      let p1 = text.charCodeAt(i) - 65;
      let p2 = text.charCodeAt(i + 1) - 65;

      let c1 = MathUtils.mod(matrix[0] * p1 + matrix[1] * p2, 26);
      let c2 = MathUtils.mod(matrix[2] * p1 + matrix[3] * p2, 26);

      result += String.fromCharCode(c1 + 65) + String.fromCharCode(c2 + 65);
    }
    return result;
  },

  // --- E. Enigma Cipher (M3) ---
  enigma: function (text, isDecrypt, config) {
    const ROTOR_WIRING = {
      I: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", // Notch: Q (16)
      II: "AJDKSIRUXBLHWTMCQGZNPYFVOE", // Notch: E (4)
      III: "BDFHJLCPRTXVZNYEIWGAKMUSQO", // Notch: V (21)
    };
    const ROTOR_NOTCH = { I: 16, II: 4, III: 21 };
    const REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

    if (!config.posL || !config.posM || !config.posR)
      throw new Error("Posisi rotor awal tidak valid.");

    let posL = config.posL.charCodeAt(0) - 65;
    let posM = config.posM.charCodeAt(0) - 65;
    let posR = config.posR.charCodeAt(0) - 65;

    function passRotor(charIndex, type, pos, isReverse) {
      let wire = ROTOR_WIRING[type];
      let contactIn = MathUtils.mod(charIndex + pos, 26);
      let contactOut;

      if (!isReverse) {
        let wiredChar = wire.charCodeAt(contactIn) - 65;
        contactOut = MathUtils.mod(wiredChar - pos, 26);
      } else {
        let wiredChar = wire.indexOf(String.fromCharCode(contactIn + 65));
        contactOut = MathUtils.mod(wiredChar - pos, 26);
      }
      return contactOut;
    }

    let result = "";
    for (let i = 0; i < text.length; i++) {
      let charIndex = text.charCodeAt(i) - 65;

      // 1. Mekanisme Putaran Notch
      let atNotchM = posM === ROTOR_NOTCH[config.typeM];
      let atNotchR = posR === ROTOR_NOTCH[config.typeR];

      posR = MathUtils.mod(posR + 1, 26);
      if (atNotchR || atNotchM) {
        posM = MathUtils.mod(posM + 1, 26);
        if (atNotchM) posL = MathUtils.mod(posL + 1, 26);
      }

      // 2. Sirkuit Maju
      charIndex = passRotor(charIndex, config.typeR, posR, false);
      charIndex = passRotor(charIndex, config.typeM, posM, false);
      charIndex = passRotor(charIndex, config.typeL, posL, false);

      // 3. Reflektor
      charIndex = REFLECTOR_B.charCodeAt(charIndex) - 65;

      // 4. Sirkuit Mundur
      charIndex = passRotor(charIndex, config.typeL, posL, true);
      charIndex = passRotor(charIndex, config.typeM, posM, true);
      charIndex = passRotor(charIndex, config.typeR, posR, true);

      result += String.fromCharCode(charIndex + 65);
    }
    return result;
  },
};

// ==========================================
// MODUL 3: KONTROL ANTARMUKA (UI Controller)
// Mengelola Interaksi User dan DOM
// ==========================================
const AppUI = {
  init: function () {
    // Pasang Event Listeners
    document
      .getElementById("cipher-select")
      .addEventListener("change", this.handleCipherChange.bind(this));
    document
      .getElementById("btn-encrypt")
      .addEventListener("click", () => this.process(false));
    document
      .getElementById("btn-decrypt")
      .addEventListener("click", () => this.process(true));
  },

  handleCipherChange: function (e) {
    document
      .querySelectorAll(".key-panel")
      .forEach((panel) => panel.classList.add("hidden"));
    document
      .getElementById(`settings-${e.target.value}`)
      .classList.remove("hidden");
    this.hideError();
  },

  showError: function (message) {
    document.getElementById("error-msg").innerText = message;
    document.getElementById("error-alert").classList.remove("hidden");
  },

  hideError: function () {
    document.getElementById("error-alert").classList.add("hidden");
  },

  cleanText: function (text) {
    return text.toUpperCase().replace(/[^A-Z]/g, "");
  },

  process: function (isDecrypt) {
    this.hideError();
    const cipherType = document.getElementById("cipher-select").value;
    const inputText = this.cleanText(
      document.getElementById("input-text").value,
    );
    const outputBox = document.getElementById("output-text");

    if (!inputText) {
      this.showError(
        "Teks input tidak boleh kosong dan harus mengandung huruf alfabet.",
      );
      return;
    }

    try {
      let result = "";
      switch (cipherType) {
        case "vigenere":
          const vKey = this.cleanText(
            document.getElementById("vigenere-key").value,
          );
          result = Ciphers.vigenere(inputText, isDecrypt, vKey);
          break;

        case "affine":
          const a = parseInt(document.getElementById("affine-a").value);
          const b = parseInt(document.getElementById("affine-b").value);
          result = Ciphers.affine(inputText, isDecrypt, a, b);
          break;

        case "playfair":
          const pKey = this.cleanText(
            document.getElementById("playfair-key").value,
          );
          result = Ciphers.playfair(inputText, isDecrypt, pKey);
          break;

        case "hill":
          const k11 = parseInt(document.getElementById("hill-00").value);
          const k12 = parseInt(document.getElementById("hill-01").value);
          const k21 = parseInt(document.getElementById("hill-10").value);
          const k22 = parseInt(document.getElementById("hill-11").value);
          result = Ciphers.hill(inputText, isDecrypt, [k11, k12, k21, k22]);
          break;

        case "enigma":
          const enigmaConfig = {
            typeL: document.getElementById("enigma-rotor-l").value,
            typeM: document.getElementById("enigma-rotor-m").value,
            typeR: document.getElementById("enigma-rotor-r").value,
            posL: this.cleanText(document.getElementById("enigma-pos-l").value),
            posM: this.cleanText(document.getElementById("enigma-pos-m").value),
            posR: this.cleanText(document.getElementById("enigma-pos-r").value),
          };
          result = Ciphers.enigma(inputText, isDecrypt, enigmaConfig);
          break;
      }
      outputBox.value = result;
    } catch (error) {
      this.showError(error.message);
      outputBox.value = "";
    }
  },
};

// Jalankan UI ketika HTML selesai dimuat
document.addEventListener("DOMContentLoaded", () => AppUI.init());
