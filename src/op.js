const crypto = require("crypto");
const { S256Point, Signature } = require("./ecc");
const { hash160, hash256 } = require("./helper");

function encodeNum(num) {
  if (num === 0) {
    return Buffer.from([]);
  }
  let absNum = Math.abs(num);
  const negative = num < 0;
  const result = [];
  while (absNum) {
    result.push(absNum & 0xff);
    absNum >>= 8;
  }
  if (result[result.length - 1] & 0x80) {
    if (negative) {
      result.push(0x80);
    } else {
      result.push(0);
    }
  } else if (negative) {
    result[result.length - 1] |= 0x80;
  }
  return Buffer.from(result);
}

function decodeNum(element) {
  if (element.length === 0) {
    return 0;
  }
  const bigEndian = Buffer.from(element).reverse();
  const negative = bigEndian[0] & 0x80;
  let result = bigEndian[0] & 0x7f;
  for (const byte of bigEndian.slice(1)) {
    result <<= 8;
    result += byte;
  }
  return negative ? -result : result;
}

function op_0(stack) {
  stack.push(encodeNum(0));
  return true;
}

function op_1negate(stack) {
  stack.push(encodeNum(-1));
  return true;
}

function op_1(stack) {
  stack.push(encodeNum(1));
  return true;
}

function op_2(stack) {
  stack.push(encodeNum(2));
  return true;
}

function op_3(stack) {
  stack.push(encodeNum(3));
  return true;
}

function op_4(stack) {
  stack.push(encodeNum(4));
  return true;
}

function op_5(stack) {
  stack.push(encodeNum(5));
  return true;
}

function op_6(stack) {
  stack.push(encodeNum(6));
  return true;
}

function op_7(stack) {
  stack.push(encodeNum(7));
  return true;
}

function op_8(stack) {
  stack.push(encodeNum(8));
  return true;
}

function op_9(stack) {
  stack.push(encodeNum(9));
  return true;
}

function op_10(stack) {
  stack.push(encodeNum(10));
  return true;
}

function op_11(stack) {
  stack.push(encodeNum(11));
  return true;
}

function op_12(stack) {
  stack.push(encodeNum(12));
  return true;
}

function op_13(stack) {
  stack.push(encodeNum(13));
  return true;
}

function op_14(stack) {
  stack.push(encodeNum(14));
  return true;
}

function op_15(stack) {
  stack.push(encodeNum(15));
  return true;
}

function op_16(stack) {
  stack.push(encodeNum(16));
  return true;
}


function op_nop(stack) {
  return true;
}

function op_if(stack, items) {
  if (stack.length < 1) {
    return false;
  }
  const trueItems = [];
  const falseItems = [];
  let currentArray = trueItems;
  let found = false;
  let numEndifsNeeded = 1;
  while (items.length > 0) {
    const item = items.shift();
    if (item === 99 || item === 100) {
      numEndifsNeeded++;
      currentArray.push(item);
    } else if (numEndifsNeeded === 1 && item === 103) {
      currentArray = falseItems;
    } else if (item === 104) {
      if (numEndifsNeeded === 1) {
        found = true;
        break;
      } else {
        numEndifsNeeded--;
        currentArray.push(item);
      }
    } else {
      currentArray.push(item);
    }
  }
  if (!found) {
    return false;
  }
  const element = stack.pop();
  if (decodeNum(element) === 0) {
    items.unshift(...falseItems);
  } else {
    items.unshift(...trueItems);
  }
  return true;
}

function op_notif(stack, items) {
  if (stack.length < 1) {
    return false;
  }
  const trueItems = [];
  const falseItems = [];
  let currentArray = trueItems;
  let found = false;
  let numEndifsNeeded = 1;
  while (items.length > 0) {
    const item = items.shift();
    if (item === 99 || item === 100) {
      numEndifsNeeded++;
      currentArray.push(item);
    } else if (numEndifsNeeded === 1 && item === 103) {
      currentArray = falseItems;
    } else if (item === 104) {
      if (numEndifsNeeded === 1) {
        found = true;
        break;
      } else {
        numEndifsNeeded--;
        currentArray.push(item);
      }
    } else {
      currentArray.push(item);
    }
  }
  if (!found) {
    return false;
  }
  const element = stack.pop();
  if (decodeNum(element) === 0) {
    items.unshift(...trueItems);
  } else {
    items.unshift(...falseItems);
  }
  return true;
}

function op_verify(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = stack.pop();
  return decodeNum(element) !== 0;
}

function op_return(stack) {
  return false;
}

function op_toaltstack(stack, altstack) {
  if (stack.length < 1) {
    return false;
  }
  altstack.push(stack.pop());
  return true;
}

function op_fromaltstack(stack, altstack) {
  if (altstack.length < 1) {
    return false;
  }
  stack.push(altstack.pop());
  return true;
}

function op_2drop(stack) {
  if (stack.length < 2) {
    return false;
  }
  stack.pop();
  stack.pop();
  return true;
}

function op_2dup(stack) {
  if (stack.length < 2) {
    return false;
  }
  stack.push(stack[stack.length - 2]);
  stack.push(stack[stack.length - 2]);
  return true;
}
function op_3dup(stack) {
  if (stack.length < 3) {
    return false;
  }
  stack.push(...stack.slice(-3));
  return true;
}

function op_2over(stack) {
  if (stack.length < 4) {
    return false;
  }
  stack.push(...stack.slice(-4, -2));
  return true;
}

function op_2rot(stack) {
  if (stack.length < 6) {
    return false;
  }
  stack.push(...stack.slice(-6, -4));
  return true;
}

function op_2swap(stack) {
  if (stack.length < 4) {
    return false;
  }
  const topTwo = stack.slice(-2);
  stack.splice(-4, 2, ...topTwo);
  return true;
}
function op_ifdup(stack) {
  if (stack.length < 1) {
    return false;
  }
  if (decodeNum(stack[stack.length - 1]) !== 0) {
    stack.push(stack[stack.length - 1]);
  }
  return true;
}

function op_depth(stack) {
  stack.push(encodeNum(stack.length));
  return true;
}

function op_drop(stack) {
  if (stack.length < 1) {
    return false;
  }
  stack.pop();
  return true;
}

function op_dup(stack) {
  if (stack.length < 1) {
    return false;
  }
  stack.push(stack[stack.length - 1]);
  return true;
}

function op_nip(stack) {
  if (stack.length < 2) {
    return false;
  }
  stack.splice(-2, 1);
  return true;
}

function op_over(stack) {
  if (stack.length < 2) {
    return false;
  }
  stack.push(stack[stack.length - 2]);
  return true;
}

function op_pick(stack) {
  if (stack.length < 1) {
    return false;
  }
  const n = decodeNum(stack.pop());
  if (stack.length < n + 1) {
    return false;
  }
  stack.push(stack[stack.length - n - 1]);
  return true;
}

function op_roll(stack) {
  if (stack.length < 1) {
    return false;
  }
  const n = decodeNum(stack.pop());
  if (stack.length < n + 1) {
    return false;
  }
  if (n === 0) {
    return true;
  }
  stack.push(stack.splice(-n - 1, 1)[0]);
  return true;
}

function op_rot(stack) {
  if (stack.length < 3) {
    return false;
  }
  stack.push(stack.splice(-3, 1)[0]);
  return true;
}

function op_swap(stack) {
  if (stack.length < 2) {
    return false;
  }
  stack.push(stack.splice(-2, 1)[0]);
  return true;
}

function op_tuck(stack) {
  if (stack.length < 2) {
    return false;
  }
  stack.splice(-2, 0, stack[stack.length - 1]);
  return true;
}

function op_size(stack) {
  if (stack.length < 1) {
    return false;
  }
  stack.push(encodeNum(stack[stack.length - 1].length));
  return true;
}

function op_equal(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = stack.pop();
  const element2 = stack.pop();
  if (Buffer.compare(element1, element2) === 0) {
    stack.push(encodeNum(1));
  } else {
    stack.push(encodeNum(0));
  }
  return true;
}

function op_equalverify(stack) {
  return op_equal(stack) && op_verify(stack);
}

function op_1add(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = decodeNum(stack.pop());
  stack.push(encodeNum(element + 1));
  return true;
}

function op_1sub(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = decodeNum(stack.pop());
  stack.push(encodeNum(element - 1));
  return true;
}

function op_negate(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = decodeNum(stack.pop());
  stack.push(encodeNum(-element));
  return true;
}

function op_abs(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = decodeNum(stack.pop());
  stack.push(encodeNum(Math.abs(element)));
  return true;
}

function op_not(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = stack.pop();
  if (decodeNum(element) === 0) {
    stack.push(encodeNum(1));
  } else {
    stack.push(encodeNum(0));
  }
  return true;
}

function op_0notequal(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = stack.pop();
  if (decodeNum(element) === 0) {
    stack.push(encodeNum(0));
  } else {
    stack.push(encodeNum(1));
  }
  return true;
}

function op_add(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element1 + element2));
  return true;
}

function op_sub(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element2 - element1));
  return true;
}

function op_booland(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element1 && element2 ? 1 : 0));
  return true;
}

function op_boolor(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element1 || element2 ? 1 : 0));
  return true;
}

function op_numequal(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element1 === element2 ? 1 : 0));
  return true;
}

function op_numequalverify(stack) {
  return op_numequal(stack) && op_verify(stack);
}

function op_numnotequal(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element1 !== element2 ? 1 : 0));
  return true;
}

function op_lessthan(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element2 < element1 ? 1 : 0));
  return true;
}

function op_greaterthan(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element2 > element1 ? 1 : 0));
  return true;
}

function op_lessthanorequal(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element2 <= element1 ? 1 : 0));
  return true;
}

function op_greaterthanorequal(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(element2 >= element1 ? 1 : 0));
  return true;
}

function op_min(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(Math.min(element1, element2)));
  return true;
}

function op_max(stack) {
  if (stack.length < 2) {
    return false;
  }
  const element1 = decodeNum(stack.pop());
  const element2 = decodeNum(stack.pop());
  stack.push(encodeNum(Math.max(element1, element2)));
  return true;
}

function op_within(stack) {
  if (stack.length < 3) {
    return false;
  }
  const maximum = decodeNum(stack.pop());
  const minimum = decodeNum(stack.pop());
  const element = decodeNum(stack.pop());
  stack.push(encodeNum(element >= minimum && element < maximum ? 1 : 0));
  return true;
}

function op_ripemd160(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = stack.pop();
  stack.push(crypto.createHash("ripemd160").update(element).digest());
  return true;
}

function op_sha1(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = stack.pop();
  stack.push(crypto.createHash("sha1").update(element).digest());
  return true;
}

function op_sha256(stack) {
  if (stack.length < 1) {
    return false;
  }
  const element = stack.pop();
  stack.push(crypto.createHash("sha256").update(element).digest());
  return true;
}
function op_hash160(stack) {
  if (stack.length < 1) {
    return false;
  }
  const data = stack.pop();
  const hash = crypto.createHash("sha256").update(data).digest();
  const ripemd160Hash = crypto.createHash("ripemd160").update(hash).digest();
  stack.push(ripemd160Hash);
  return true;
}

function op_hash256(stack) {
  if (stack.length < 1) {
    return false;
  }
  const data = stack.pop();
  const hash = crypto.createHash("sha256").update(data).digest();
  const doubleHash = crypto.createHash("sha256").update(hash).digest();
  stack.push(doubleHash);
  return true;
}

function op_checksig(stack, z) {
  if (stack.length < 2) {
    return false;
  }
  const secPubkey = stack.pop();
  const derSignature = stack.pop().slice(0, -1);
  let point, sig;
  try {
    point = S256Point.parse(secPubkey);
    sig = Signature.parse(derSignature);
  } catch (e) {
    console.error(e);
    return false;
  }
  if (point.verify(z, sig)) {
    stack.push(encodeNum(1));
  } else {
    stack.push(encodeNum(0));
  }
  return true;
}

function op_checksigverify(stack, z) {
  return op_checksig(stack, z) && op_verify(stack);
}

function op_checkmultisig(stack, z) {
  if (stack.length < 1) {
    return false;
  }
  const n = decodeNum(stack.pop());
  if (stack.length < n + 1) {
    return false;
  }
  const secPubkeys = [];
  for (let i = 0; i < n; i++) {
    secPubkeys.push(stack.pop());
  }
  const m = decodeNum(stack.pop());
  if (stack.length < m + 1) {
    return false;
  }
  const derSignatures = [];
  for (let i = 0; i < m; i++) {
    derSignatures.push(stack.pop().slice(0, -1));
  }
  stack.pop(); // extra element
  try {
    const points = secPubkeys.map((sec) => S256Point.parse(sec));
    const signatures = derSignatures.map((der) => Signature.parse(der));
    for (const sig of signatures) {
      let valid = false;
      while (points.length > 0) {
        const point = points.shift();
        if (point.verify(z, sig)) {
          valid = true;
          break;
        }
      }
      if (!valid) {
        stack.push(encodeNum(0));
        return true;
      }
    }
    stack.push(encodeNum(1));
  } catch (e) {
    return false;
  }
  return true;
}

function op_checkmultisigverify(stack, z) {
  return op_checkmultisig(stack, z) && op_verify(stack);
}

function op_checklocktimeverify(stack, locktime, sequence) {
  if (sequence === 0xffffffff) {
    return false;
  }
  if (stack.length < 1) {
    return false;
  }
  const element = decodeNum(stack[stack.length - 1]);
  if (element < 0) {
    return false;
  }
  if (element < 500000000 && locktime > 500000000) {
    return false;
  }
  if (locktime < element) {
    return false;
  }
  return true;
}

function op_checksequenceverify(stack, version, sequence) {
  if (sequence & (1 << 31)) {
    return false;
  }
  if (stack.length < 1) {
    return false;
  }
  const element = decodeNum(stack[stack.length - 1]);
  if (element < 0) {
    return false;
  }
  if (element & (1 << 31)) {
    if (version < 2) {
      return false;
    }
    if (sequence & (1 << 31)) {
      return false;
    }
    if ((element & (1 << 22)) !== (sequence & (1 << 22))) {
      return false;
    }
    if ((element & 0xffff) > (sequence & 0xffff)) {
      return false;
    }
  }
  return true;
}

module.exports = {
  encodeNum,
  decodeNum,
  op_0,
  op_1negate,
  op_1,
  op_2,
  op_3,
  op_4,
  op_5,
  op_6,
  op_7,
  op_8,
  op_9,
  op_10,
  op_11,
  op_12,
  op_13,
  op_14,
  op_15,
  op_16,
  op_nop,
  op_if,
  op_notif,
  op_verify,
  op_return,
  op_toaltstack,
  op_fromaltstack,
  op_2drop,
  op_2dup,
  op_3dup,
  op_2over,
  op_2rot,
  op_2swap,
  op_ifdup,
  op_depth,
  op_drop,
  op_dup,
  op_nip,
  op_over,
  op_pick,
  op_roll,
  op_rot,
  op_swap,
  op_tuck,
  op_size,
  op_hash160,
  op_hash256,
  op_ripemd160,
  op_checksig,
  op_checksigverify,
  op_checkmultisig,
  op_checkmultisigverify,
  op_checklocktimeverify,
  op_checksequenceverify,
};

