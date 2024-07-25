const crypto = require("crypto");

const SIGHASH_ALL = 1;
const SIGHASH_NONE = 2;
const SIGHASH_SINGLE = 3;
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function hash160(s) {
  return crypto
    .createHash("ripemd160")
    .update(crypto.createHash("sha256").update(s).digest())
    .digest();
}

function hash256(s) {
  return crypto
    .createHash("sha256")
    .update(crypto.createHash("sha256").update(s).digest())
    .digest();
}

function encodeBase58(buffer) {
  let num = BigInt("0x" + buffer.toString("hex"));
  let result = "";

  while (num > 0) {
    let mod = num % 58n;
    result = BASE58_ALPHABET[Number(mod)] + result;
    num = num / 58n;
  }

  // Handle leading zeroes
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    result = "1" + result;
  }

  return result;
}
function encodeBase58Checksum(buffer) {
  const checksum = hash256(buffer).slice(0, 4);
  return encodeBase58(Buffer.concat([buffer, checksum]));
}

function decodeBase58(s) {
  let num = BigInt(0);
  for (let i = 0; i < s.length; i++) {
    num = num * 58n + BigInt(BASE58_ALPHABET.indexOf(s[i]));
  }

  let combined = Buffer.from(num.toString(16).padStart(50, "0"), "hex");
  let checksum = combined.slice(-4);
  let payload = combined.slice(0, -4);

  if (!checksum.equals(hash256(payload).slice(0, 4))) {
    throw new Error(
      `Bad address checksum: ${checksum.toString("hex")} != ${hash256(payload)
        .slice(0, 4)
        .toString("hex")}`
    );
  }

  return payload;
}
function littleEndianToInt(buffer) {
  // Create a new Buffer from a slice to avoid deprecation
  return parseInt(buffer.slice().reverse().toString("hex"), 16);
}

function intToLittleEndian(num, length) {
  const hex = num.toString(16).padStart(length * 2, "0");
  const buffer = Buffer.from(hex, "hex");
  // Reverse for little-endian format
  return Buffer.from(buffer).reverse();
}

function readVarint(s) {
  let i = s.readUInt8(0);
  s = s.slice(1);
  if (i === 0xfd) {
    return {
      value: littleEndianToInt(s.slice(0, 2)),
      remainingBuffer: s.slice(2),
    };
  } else if (i === 0xfe) {
    return {
      value: littleEndianToInt(s.slice(0, 4)),
      remainingBuffer: s.slice(4),
    };
  } else if (i === 0xff) {
    return {
      value: littleEndianToInt(s.slice(0, 8)),
      remainingBuffer: s.slice(8),
    };
  } else {
    return { value: i, remainingBuffer: s };
  }
}

function encodeVarint(i) {
  if (i < 0xfd) {
    return Buffer.from([i]);
  } else if (i < 0x10000) {
    return Buffer.concat([Buffer.from([0xfd]), intToLittleEndian(i, 2)]);
  } else if (i < 0x100000000) {
    return Buffer.concat([Buffer.from([0xfe]), intToLittleEndian(i, 4)]);
  } else if (i < 0x10000000000000000) {
    return Buffer.concat([Buffer.from([0xff]), intToLittleEndian(i, 8)]);
  } else {
    throw new Error("integer too large: " + i);
  }
}

module.exports = {
  SIGHASH_ALL,
  SIGHASH_NONE,
  SIGHASH_SINGLE,
  BASE58_ALPHABET,
  hash160,
  hash256,
  encodeBase58,
  encodeBase58Checksum,
  decodeBase58,
  littleEndianToInt,
  intToLittleEndian,
  readVarint,
  encodeVarint,
};
