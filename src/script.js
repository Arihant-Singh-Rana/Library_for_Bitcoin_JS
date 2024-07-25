const { Buffer } = require("buffer");
const { getLogger } = require("log4js");
const {
  encodeVarint,
  intToLittleEndian,
  littleEndianToInt,
  readVarint,
} = require("./helper");
const {
  opEqual,
  opHash160,
  opVerify,
  OP_CODE_FUNCTIONS,
  OP_CODE_NAMES,
} = require("./op");

function p2pkhScript(h160) {
  // P2PKH ScriptPubKey format: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
  return Buffer.concat([
    Buffer.from([0x76]), // OP_DUP
    Buffer.from([0xa9]), // OP_HASH160
    h160, // 20-byte hash
    Buffer.from([0x88]), // OP_EQUALVERIFY
    Buffer.from([0xac]), // OP_CHECKSIG
  ]);
}

// Function to create a P2SH ScriptPubKey
function p2shScript(h160) {
  // P2SH ScriptPubKey format: OP_HASH160 <20-byte hash> OP_EQUAL
  return Buffer.concat([
    Buffer.from([0xa9]), // OP_HASH160
    h160, // 20-byte hash
    Buffer.from([0x87]), // OP_EQUAL
  ]);
}

const LOGGER = getLogger(__filename);

class Script {
  constructor(cmds = []) {
    this.cmds = cmds;
  }

  toString() {
    return this.cmds
      .map((cmd) => {
        if (typeof cmd === "number") {
          return OP_CODE_NAMES[cmd] ? OP_CODE_NAMES[cmd] : `OP_[${cmd}]`;
        } else {
          return cmd.toString("hex");
        }
      })
      .join(" ");
  }

  concat(other) {
    return new Script(this.cmds.concat(other.cmds));
  }

  static parse(buffer) {
    const length = readVarint(buffer);
    const cmds = [];
    let count = 0;

    while (count < length) {
      const current = buffer.readUInt8(0);
      buffer = buffer.slice(1);
      count += 1;

      if (current >= 1 && current <= 75) {
        const n = current;
        cmds.push(buffer.slice(0, n));
        buffer = buffer.slice(n);
        count += n;
      } else if (current === 76) {
        const dataLength = littleEndianToInt(buffer.slice(0, 1));
        buffer = buffer.slice(1);
        cmds.push(buffer.slice(0, dataLength));
        buffer = buffer.slice(dataLength);
        count += dataLength + 1;
      } else if (current === 77) {
        const dataLength = littleEndianToInt(buffer.slice(0, 2));
        buffer = buffer.slice(2);
        cmds.push(buffer.slice(0, dataLength));
        buffer = buffer.slice(dataLength);
        count += dataLength + 2;
      } else {
        cmds.push(current);
      }
    }

    if (count !== length) {
      throw new SyntaxError("Parsing script failed");
    }

    return new Script(cmds);
  }

  rawSerialize() {
    let result = Buffer.alloc(0);

    for (const cmd of this.cmds) {
      if (typeof cmd === "number") {
        result = Buffer.concat([result, intToLittleEndian(cmd, 1)]);
      } else {
        const length = cmd.length;
        if (length < 75) {
          result = Buffer.concat([result, intToLittleEndian(length, 1)]);
        } else if (length >= 75 && length < 0x100) {
          result = Buffer.concat([
            result,
            intToLittleEndian(76, 1),
            intToLittleEndian(length, 1),
          ]);
        } else if (length >= 0x100 && length <= 520) {
          result = Buffer.concat([
            result,
            intToLittleEndian(77, 1),
            intToLittleEndian(length, 2),
          ]);
        } else {
          throw new ValueError("Too long a cmd");
        }
        result = Buffer.concat([result, cmd]);
      }
    }

    return result;
  }

  serialize() {
    const raw = this.rawSerialize();
    const total = raw.length;
    return Buffer.concat([encodeVarint(total), raw]);
  }

  evaluate(z) {
    const cmds = [...this.cmds];
    const stack = [];
    const altstack = [];

    while (cmds.length > 0) {
      const cmd = cmds.shift();

      if (typeof cmd === "number") {
        const operation = OP_CODE_FUNCTIONS[cmd];
        if (cmd === 99 || cmd === 100) {
          // OP_IF/OP_NOTIF
          if (!operation(stack, cmds)) {
            LOGGER.info(`bad op: ${OP_CODE_NAMES[cmd]}`);
            return false;
          }
        } else if (cmd === 107 || cmd === 108) {
          // OP_TOALTSTACK/OP_FROMALTSTACK
          if (!operation(stack, altstack)) {
            LOGGER.info(`bad op: ${OP_CODE_NAMES[cmd]}`);
            return false;
          }
        } else if ([172, 173, 174, 175].includes(cmd)) {
          // OP_CHECKSIG and similar
          if (!operation(stack, z)) {
            LOGGER.info(`bad op: ${OP_CODE_NAMES[cmd]}`);
            return false;
          }
        } else {
          if (!operation(stack)) {
            LOGGER.info(`bad op: ${OP_CODE_NAMES[cmd]}`);
            return false;
          }
        }
      } else {
        stack.push(cmd);
        if (
          cmds.length === 3 &&
          cmds[0] === 0xa9 &&
          Buffer.isBuffer(cmds[1]) &&
          cmds[1].length === 20 &&
          cmds[2] === 0x87
        ) {
          cmds.shift(); // OP_HASH160
          const h160 = cmds.shift();
          cmds.shift(); // OP_EQUAL
          if (!opHash160(stack)) {
            return false;
          }
          stack.push(h160);
          if (!opEqual(stack)) {
            return false;
          }
          if (!opVerify(stack)) {
            LOGGER.info("bad p2sh h160");
            return false;
          }
          const redeemScript = Buffer.concat([encodeVarint(cmd.length), cmd]);
          const stream = Buffer.from(redeemScript);
          cmds.push(...Script.parse(stream).cmds);
        }
      }
    }

    if (stack.length === 0 || stack.pop().equals(Buffer.alloc(0))) {
      return false;
    }
    return true;
  }

  isP2PKHScriptPubKey() {
    return (
      this.cmds.length === 5 &&
      this.cmds[0] === 0x76 &&
      this.cmds[1] === 0xa9 &&
      Buffer.isBuffer(this.cmds[2]) &&
      this.cmds[2].length === 20 &&
      this.cmds[3] === 0x88 &&
      this.cmds[4] === 0xac
    );
  }

  isP2SHScriptPubKey() {
    return (
      this.cmds.length === 3 &&
      this.cmds[0] === 0xa9 &&
      Buffer.isBuffer(this.cmds[1]) &&
      this.cmds[1].length === 20 &&
      this.cmds[2] === 0x87
    );
  }
}
module.exports = { p2pkhScript, p2shScript };
