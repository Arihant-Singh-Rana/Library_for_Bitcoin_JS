const {
  encodeVarint,
  hash256,
  intToLittleEndian,
  littleEndianToInt,
  readVarint,
  SIGHASH_ALL,
} = require("./helper");
const { PrivateKey } = require("./ecc");
const { Script } = require("./script");
const axios = require("axios");
const fs = require("fs");

class TxFetcher {
  static cache = {};

  static getUrl(testnet = false) {
    return testnet
      ? "https://blockstream.info/testnet/api"
      : "https://blockstream.info/api";
  }

  static async fetch(txId, testnet = false, fresh = false) {
    if (fresh || !(txId in this.cache)) {
      const url = `${this.getUrl(testnet)}/tx/${txId}/hex`;
      const response = await axios.get(url);
      let raw;
      try {
        raw = Buffer.from(response.data.trim(), "hex");
      } catch (e) {
        throw new Error(`unexpected response: ${response.data}`);
      }

      if (raw[4] === 0) {
        raw = Buffer.concat([raw.slice(0, 4), raw.slice(6)]);
        const tx = Tx.parse(raw, testnet);
        tx.locktime = littleEndianToInt(raw.slice(-4));
      } else {
        const tx = Tx.parse(raw, testnet);
      }

      if (tx.id() !== txId) {
        throw new Error(`not the same id: ${tx.id()} vs ${txId}`);
      }

      this.cache[txId] = tx;
    }
    this.cache[txId].testnet = testnet;
    return this.cache[txId];
  }

  static loadCache(filename) {
    const diskCache = JSON.parse(fs.readFileSync(filename, "utf-8"));
    for (const [k, rawHex] of Object.entries(diskCache)) {
      let raw = Buffer.from(rawHex, "hex");
      if (raw[4] === 0) {
        raw = Buffer.concat([raw.slice(0, 4), raw.slice(6)]);
        const tx = Tx.parse(raw);
        tx.locktime = littleEndianToInt(raw.slice(-4));
      } else {
        const tx = Tx.parse(raw);
      }
      this.cache[k] = tx;
    }
  }

  static dumpCache(filename) {
    const toDump = {};
    for (const [k, tx] of Object.entries(this.cache)) {
      toDump[k] = tx.serialize().toString("hex");
    }
    fs.writeFileSync(filename, JSON.stringify(toDump, null, 4));
  }
}

class Tx {
  constructor(version, txIns, txOuts, locktime, testnet = false) {
    this.version = version;
    this.txIns = txIns;
    this.txOuts = txOuts;
    this.locktime = locktime;
    this.testnet = testnet;
  }

  toString() {
    let txIns = "";
    for (const txIn of this.txIns) {
      txIns += txIn.toString() + "\n";
    }
    let txOuts = "";
    for (const txOut of this.txOuts) {
      txOuts += txOut.toString() + "\n";
    }
    return `tx: ${this.id()}\nversion: ${
      this.version
    }\ntxIns:\n${txIns}txOuts:\n${txOuts}locktime: ${this.locktime}`;
  }

  id() {
    return this.hash().toString("hex");
  }

  hash() {
    return hash256(this.serialize()).reverse();
  }

  static parse(buffer, testnet = false) {
    const version = littleEndianToInt(buffer.slice(0, 4));
    const { value: numInputs, remainingBuffer: inputsBuffer } = readVarint(
      buffer.slice(4)
    );
    const inputs = [];
    let buf = inputsBuffer;

    for (let i = 0; i < numInputs; i++) {
      const txIn = TxIn.parse(buf);
      inputs.push(txIn.txIn);
      buf = txIn.remainingBuffer;
    }

    const { value: numOutputs, remainingBuffer: outputsBuffer } =
      readVarint(buf);
    const outputs = [];
    buf = outputsBuffer;

    for (let i = 0; i < numOutputs; i++) {
      const txOut = TxOut.parse(buf);
      outputs.push(txOut.txOut);
      buf = txOut.remainingBuffer;
    }

    const locktime = littleEndianToInt(buf.slice(0, 4));
    return new Tx(version, inputs, outputs, locktime, testnet);
  }

  serialize() {
    let result = intToLittleEndian(this.version, 4);
    result = Buffer.concat([result, encodeVarint(this.txIns.length)]);
    for (const txIn of this.txIns) {
      result = Buffer.concat([result, txIn.serialize()]);
    }
    result = Buffer.concat([result, encodeVarint(this.txOuts.length)]);
    for (const txOut of this.txOuts) {
      result = Buffer.concat([result, txOut.serialize()]);
    }
    result = Buffer.concat([result, intToLittleEndian(this.locktime, 4)]);
    return result;
  }

  fee() {
    let inputSum = 0;
    let outputSum = 0;
    for (const txIn of this.txIns) {
      inputSum += txIn.value(this.testnet);
    }
    for (const txOut of this.txOuts) {
      outputSum += txOut.amount;
    }
    return inputSum - outputSum;
  }

  sigHash(inputIndex) {
    let s = intToLittleEndian(this.version, 4);
    s = Buffer.concat([s, encodeVarint(this.txIns.length)]);

    this.txIns.forEach((txIn, i) => {
      if (i === inputIndex) {
        const scriptPubKey = txIn.scriptPubkey(this.testnet);
        s = Buffer.concat([
          s,
          new TxIn(
            txIn.prevTx,
            txIn.prevIndex,
            scriptPubKey,
            txIn.sequence
          ).serialize(),
        ]);
      } else {
        s = Buffer.concat([
          s,
          new TxIn(
            txIn.prevTx,
            txIn.prevIndex,
            undefined,
            txIn.sequence
          ).serialize(),
        ]);
      }
    });

    s = Buffer.concat([s, encodeVarint(this.txOuts.length)]);
    for (const txOut of this.txOuts) {
      s = Buffer.concat([s, txOut.serialize()]);
    }

    s = Buffer.concat([s, intToLittleEndian(this.locktime, 4)]);
    s = Buffer.concat([s, intToLittleEndian(SIGHASH_ALL, 4)]);
    const h256 = hash256(s);
    return BigInt(`0x${h256.toString("hex")}`);
  }

  verifyInput(inputIndex) {
    const txIn = this.txIns[inputIndex];
    const scriptPubkey = txIn.scriptPubkey(this.testnet);
    const z = this.sigHash(inputIndex);
    const combined = txIn.scriptSig + scriptPubkey;
    return combined.evaluate(z);
  }

  verify() {
    if (this.fee() < 0) {
      return false;
    }
    for (let i = 0; i < this.txIns.length; i++) {
      if (!this.verifyInput(i)) {
        return false;
      }
    }
    return true;
  }

  signInput(inputIndex, privateKey) {
    const z = this.sigHash(inputIndex);
    const der = privateKey.sign(z).toDer();
    const sig = Buffer.concat([der, Buffer.from([SIGHASH_ALL])]);
    const sec = privateKey.point.sec();
    const scriptSig = new Script([sig, sec]);
    this.txIns[inputIndex].scriptSig = scriptSig;
    return this.verifyInput(inputIndex);
  }
}

class TxIn {
  constructor(
    prevTx,
    prevIndex,
    scriptSig = new Script(),
    sequence = 0xffffffff
  ) {
    this.prevTx = prevTx;
    this.prevIndex = prevIndex;
    this.scriptSig = scriptSig;
    this.sequence = sequence;
  }

  toString() {
    return `${this.prevTx.toString("hex")}:${this.prevIndex}`;
  }

  static parse(buffer) {
    const prevTx = buffer.slice(0, 32).reverse();
    const prevIndex = littleEndianToInt(buffer.slice(32, 36));
    const scriptSig = Script.parse(buffer.slice(36));
    const sequence = littleEndianToInt(buffer.slice(buffer.length - 4));
    return {
      txIn: new TxIn(prevTx, prevIndex, scriptSig, sequence),
      remainingBuffer: buffer.slice(36 + scriptSig.size() + 4),
    };
  }

  serialize() {
    let result = this.prevTx.reverse();
    result = Buffer.concat([result, intToLittleEndian(this.prevIndex, 4)]);
    result = Buffer.concat([result, this.scriptSig.serialize()]);
    result = Buffer.concat([result, intToLittleEndian(this.sequence, 4)]);
    return result;
  }

  async fetchTx(testnet = false) {
    return await TxFetcher.fetch(this.prevTx.toString("hex"), testnet);
  }

  async value(testnet = false) {
    const tx = await this.fetchTx(testnet);
    return tx.txOuts[this.prevIndex].amount;
  }

  async scriptPubkey(testnet = false) {
    const tx = await this.fetchTx(testnet);
    return tx.txOuts[this.prevIndex].scriptPubkey;
  }
}

class TxOut {
  constructor(amount, scriptPubkey) {
    this.amount = amount;
    this.scriptPubkey = scriptPubkey;
  }

  toString() {
    return `${this.amount}:${this.scriptPubkey}`;
  }

  static parse(buffer) {
    const amount = littleEndianToInt(buffer.slice(0, 8));
    const scriptPubkey = Script.parse(buffer.slice(8));
    return {
      txOut: new TxOut(amount, scriptPubkey),
      remainingBuffer: buffer.slice(8 + scriptPubkey.size()),
    };
  }

  serialize() {
    let result = intToLittleEndian(this.amount, 8);
    result = Buffer.concat([result, this.scriptPubkey.serialize()]);
    return result;
  }
}

module.exports = { Tx, TxIn, TxOut, TxFetcher };
