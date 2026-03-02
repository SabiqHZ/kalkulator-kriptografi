// File: src/app.js
import {
  VigenereCipher,
  AffineCipher,
  PlayfairCipher,
  HillCipher,
  EnigmaCipher,
} from "./ciphers/CipherClasses.js";

class AppUI {
  constructor() {
    this.initEventListeners();
  }

  initEventListeners() {
    document
      .getElementById("cipher-select")
      .addEventListener("change", (e) => this.handleCipherChange(e));
    document
      .getElementById("btn-encrypt")
      .addEventListener("click", () => this.executeCipher(false));
    document
      .getElementById("btn-decrypt")
      .addEventListener("click", () => this.executeCipher(true));
  }

  handleCipherChange(e) {
    document
      .querySelectorAll(".key-panel")
      .forEach((panel) => panel.classList.add("hidden"));
    document
      .getElementById(`settings-${e.target.value}`)
      .classList.remove("hidden");
    this.hideError();
  }

  showError(message) {
    document.getElementById("error-msg").innerText = message;
    document.getElementById("error-alert").classList.remove("hidden");
  }

  hideError() {
    document.getElementById("error-alert").classList.add("hidden");
  }

  cleanText(text) {
    return text.toUpperCase().replace(/[^A-Z]/g, "");
  }

  // Pabrik Pembuat Instance (Factory Pattern)
  createCipherInstance(cipherType) {
    switch (cipherType) {
      case "vigenere":
        return new VigenereCipher(
          this.cleanText(document.getElementById("vigenere-key").value),
        );

      case "affine":
        const a = parseInt(document.getElementById("affine-a").value);
        const b = parseInt(document.getElementById("affine-b").value);
        return new AffineCipher(a, b);

      case "playfair":
        return new PlayfairCipher(
          this.cleanText(document.getElementById("playfair-key").value),
        );

      case "hill":
        const k11 = parseInt(document.getElementById("hill-00").value);
        const k12 = parseInt(document.getElementById("hill-01").value);
        const k21 = parseInt(document.getElementById("hill-10").value);
        const k22 = parseInt(document.getElementById("hill-11").value);
        return new HillCipher(k11, k12, k21, k22);

      case "enigma":
        const config = {
          typeL: document.getElementById("enigma-rotor-l").value,
          typeM: document.getElementById("enigma-rotor-m").value,
          typeR: document.getElementById("enigma-rotor-r").value,
          posL: this.cleanText(document.getElementById("enigma-pos-l").value),
          posM: this.cleanText(document.getElementById("enigma-pos-m").value),
          posR: this.cleanText(document.getElementById("enigma-pos-r").value),
        };
        return new EnigmaCipher(config);

      default:
        throw new Error("Tipe Cipher tidak dikenal.");
    }
  }

  executeCipher(isDecrypt) {
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
      // 1. Buat Objek (Instance) dari Kelas Cipher yang dipilih
      const cipher = this.createCipherInstance(cipherType);

      // 2. Eksekusi proses menggunakan metode dari kelas tersebut (Polymorphism)
      const result = isDecrypt
        ? cipher.decrypt(inputText)
        : cipher.encrypt(inputText);

      // 3. Tampilkan hasil
      outputBox.value = result;
    } catch (error) {
      this.showError(error.message);
      outputBox.value = "";
    }
  }
}

// Inisialisasi Aplikasi setelah DOM siap
document.addEventListener("DOMContentLoaded", () => {
  new AppUI();
});
