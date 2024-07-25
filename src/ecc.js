const bigInt = require("big-integer");
const crypto = require("crypto");

class FieldElement {
  constructor(num, prime) {
    if (num.ge(prime) || num.lt(0)) {
      throw new Error(`Num ${num} not in field range 0 to ${prime.minus(1)}`);
    }
    this.num = num;
    this.prime = prime;
  }

  equals(other) {
    if (other === null) return false;
    return this.num.equals(other.num) && this.prime.equals(other.prime);
  }

  add(other) {
    if (!this.prime.equals(other.prime)) {
      throw new TypeError("Cannot add two numbers in different Fields");
    }
    const num = this.num.add(other.num).mod(this.prime);
    return new FieldElement(num, this.prime);
  }

  sub(other) {
    if (!this.prime.equals(other.prime)) {
      throw new TypeError("Cannot subtract two numbers in different Fields");
    }
    const num = this.num.subtract(other.num).mod(this.prime);
    return new FieldElement(num, this.prime);
  }

  mul(other) {
    if (!this.prime.equals(other.prime)) {
      throw new TypeError("Cannot multiply two numbers in different Fields");
    }
    const num = this.num.multiply(other.num).mod(this.prime);
    return new FieldElement(num, this.prime);
  }

  pow(exponent) {
    const n = exponent.mod(this.prime.subtract(1));
    const num = this.num.modPow(n, this.prime);
    return new FieldElement(num, this.prime);
  }

  truediv(other) {
    if (!this.prime.equals(other.prime)) {
      throw new TypeError("Cannot divide two numbers in different Fields");
    }
    const num = this.num
      .multiply(other.num.modPow(this.prime.subtract(2), this.prime))
      .mod(this.prime);
    return new FieldElement(num, this.prime);
  }

  rmul(coefficient) {
    const num = this.num.multiply(bigInt(coefficient)).mod(this.prime);
    return new FieldElement(num, this.prime);
  }
}

class Point {
  constructor(x, y, a, b) {
    this.a = a;
    this.b = b;
    this.x = x;
    this.y = y;
    if (this.x === null && this.y === null) return;
    if (
      !this.y.pow(2).equals(this.x.pow(3).add(this.a.mul(this.x)).add(this.b))
    ) {
      throw new Error(`(${x}, ${y}) is not on the curve`);
    }
  }

  equals(other) {
    return (
      this.x.equals(other.x) &&
      this.y.equals(other.y) &&
      this.a.equals(other.a) &&
      this.b.equals(other.b)
    );
  }

  add(other) {
    if (!this.a.equals(other.a) || !this.b.equals(other.b)) {
      throw new TypeError(`Points ${this}, ${other} are not on the same curve`);
    }
    if (this.x === null) return other;
    if (other.x === null) return this;
    if (this.x.equals(other.x) && !this.y.equals(other.y)) {
      return new Point(null, null, this.a, this.b);
    }
    if (!this.x.equals(other.x)) {
      const s = other.y.sub(this.y).truediv(other.x.sub(this.x));
      const x = s.pow(2).sub(this.x).sub(other.x);
      const y = s.mul(this.x.sub(x)).sub(this.y);
      return new Point(x, y, this.a, this.b);
    }
    if (this.equals(other) && this.y.equals(bigInt(0).mul(this.x))) {
      return new Point(null, null, this.a, this.b);
    }
    if (this.equals(other)) {
      const s = bigInt(3)
        .mul(this.x.pow(2))
        .add(this.a)
        .truediv(bigInt(2).mul(this.y));
      const x = s.pow(2).sub(bigInt(2).mul(this.x));
      const y = s.mul(this.x.sub(x)).sub(this.y);
      return new Point(x, y, this.a, this.b);
    }
  }

  rmul(coefficient) {
    let coef = coefficient;
    let current = this;
    let result = new Point(null, null, this.a, this.b);
    while (coef) {
      if (coef.and(bigInt(1)).equals(bigInt(1))) {
        result = result.add(current);
      }
      current = current.add(current);
      coef = coef.shiftRight(1);
    }
    return result;
  }
}

const A = bigInt(0);
const B = bigInt(7);
const P = bigInt(2).pow(256).subtract(bigInt(2).pow(32)).subtract(bigInt(977));
const N = bigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16
);

class S256Field extends FieldElement {
  constructor(num, prime = P) {
    super(num, prime);
  }

  sqrt() {
    return this.pow(P.add(1).divide(4));
  }
}

class S256Point extends Point {
  constructor(x, y, a = S256Field(A), b = S256Field(B)) {
    if (typeof x === "number") {
      super(new S256Field(bigInt(x)), new S256Field(bigInt(y)), a, b);
    } else {
      super(x, y, a, b);
    }
  }

  rmul(coefficient) {
    const coef = coefficient.mod(N);
    return super.rmul(coef);
  }

  verify(z, sig) {
    const s_inv = sig.s.modPow(N.subtract(2), N);
    const u = z.multiply(s_inv).mod(N);
    const v = sig.r.multiply(s_inv).mod(N);
    const total = u.rmul(G).add(v.rmul(this));
    return total.x.num.equals(sig.r);
  }

  sec(compressed = true) {
    if (compressed) {
      if (this.y.num.mod(2).equals(0)) {
        return Buffer.concat([Buffer.from([0x02]), this.x.num.toBytes(32)]);
      } else {
        return Buffer.concat([Buffer.from([0x03]), this.x.num.toBytes(32)]);
      }
    } else {
      return Buffer.concat([
        Buffer.from([0x04]),
        this.x.num.toBytes(32),
        this.y.num.toBytes(32),
      ]);
    }
  }

  hash160(compressed = true) {
    return hash160(this.sec(compressed));
  }

  address(compressed = true, testnet = false) {
    const h160 = this.hash160(compressed);
    const prefix = testnet ? Buffer.from([0x6f]) : Buffer.from([0x00]);
    return encodeBase58Checksum(Buffer.concat([prefix, h160]));
  }

  static parse(secBin) {
    if (secBin[0] === 4) {
      const x = bigInt.fromArray(secBin.slice(1, 33), 256, false);
      const y = bigInt.fromArray(secBin.slice(33, 65), 256, false);
      return new S256Point(x, y);
    }
    const isEven = secBin[0] === 2;
    const x = new S256Field(bigInt.fromArray(secBin.slice(1), 256, false));
    const alpha = x.pow(3).add(S256Field(B));
    const beta = alpha.sqrt();
    const [evenBeta, oddBeta] = beta.num.mod(2).equals(0)
      ? [beta, new S256Field(P.subtract(beta.num))]
      : [new S256Field(P.subtract(beta.num)), beta];
    return new S256Point(x, isEven ? evenBeta : oddBeta);
  }
}

const G = new S256Point(
  bigInt(
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    16
  ),
  bigInt(
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    16
  )
);

class Signature {
  constructor(r, s) {
    this.r = r;
    this.s = s;
  }

  der() {
    let rbin = this.r.toBytes(32);
    rbin = Buffer.from(rbin.filter((byte) => byte !== 0));
    if (rbin[0] & 0x80) {
      rbin = Buffer.concat([Buffer.from([0x00]), rbin]);
    }
    let result = Buffer.concat([Buffer.from([0x02, rbin.length]), rbin]);
    let sbin = this.s.toBytes(32);
    sbin = Buffer.from(sbin.filter((byte) => byte !== 0));
    if (sbin[0] & 0x80) {
      sbin = Buffer.concat([Buffer.from([0x00]), sbin]);
    }
    result = Buffer.concat([result, Buffer.from([0x02, sbin.length]), sbin]);
    return Buffer.concat([Buffer.from([0x30, result.length]), result]);
  }

  static parse(sigBin) {
    const compound = sigBin[0];
    if (compound !== 0x30) {
      throw new Error("Bad Signature");
    }
    let len = sigBin[1];
    let marker = sigBin[2];
    let rlen = sigBin[3];
    let r = bigInt.fromArray(sigBin.slice(4, 4 + rlen), 256, false);
    let slen = sigBin[4 + rlen + 1];
    let s = bigInt.fromArray(
      sigBin.slice(4 + rlen + 2, 4 + rlen + 2 + slen),
      256,
      false
    );
    return new Signature(r, s);
  }
}

function hash160(buffer) {
  return crypto
    .createHash("ripemd160")
    .update(crypto.createHash("sha256").update(buffer).digest())
    .digest();
}

function encodeBase58Checksum(payload) {
  const checksum = crypto
    .createHash("sha256")
    .update(crypto.createHash("sha256").update(payload).digest())
    .digest()
    .slice(0, 4);
  const combined = Buffer.concat([payload, checksum]);
  const BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = bigInt.fromArray([...combined], 256, false);
  let result = "";
  while (num.gt(0)) {
    const mod = num.mod(58);
    result = BASE58_ALPHABET[mod] + result;
    num = num.divide(58);
  }
  for (const byte of combined) {
    if (byte === 0x00) {
      result = "1" + result;
    } else {
      break;
    }
  }
  return result;
}

function hash256(buffer) {
  return crypto
    .createHash("sha256")
    .update(crypto.createHash("sha256").update(buffer).digest())
    .digest();
}
class PrivateKey {
  constructor(secret) {
    this.secret = BigInt(secret); // Ensure secret is a BigInt
    this.point = this.secret * G; // Calculate point, implementation may vary
  }

  hex() {
    return this.secret.toString(16).padStart(64, "0");
  }

  sign(z) {
    const k = this.deterministicK(z);
    const r = (k * G).x; // Assuming .x gives x coordinate, implementation may vary
    const kInv = pow(k, N - 2n, N);
    let s = ((z + r * this.secret) * kInv) % N;
    if (s > N / 2n) {
      s = N - s;
    }
    return new Signature(r, s); // Assuming Signature class is implemented
  }

  deterministicK(z) {
    let k = Buffer.alloc(32, 0x00);
    let v = Buffer.alloc(32, 0x01);
    if (z > N) {
      z -= N;
    }
    const zBytes = z.toString(16).padStart(64, "0");
    const secretBytes = this.secret.toString(16).padStart(64, "0");
    const s256 = crypto.createHash("sha256");

    k = hmac(
      k,
      Buffer.concat([
        v,
        Buffer.from([0x00]),
        Buffer.from(secretBytes, "hex"),
        Buffer.from(zBytes, "hex"),
      ]),
      s256
    ).digest();
    v = hmac(k, v, s256).digest();
    k = hmac(
      k,
      Buffer.concat([
        v,
        Buffer.from([0x01]),
        Buffer.from(secretBytes, "hex"),
        Buffer.from(zBytes, "hex"),
      ]),
      s256
    ).digest();
    v = hmac(k, v, s256).digest();

    while (true) {
      v = hmac(k, v, s256).digest();
      const candidate = BigInt("0x" + v.toString("hex"));
      if (candidate >= 1n && candidate < N) {
        return candidate;
      }
      k = hmac(k, Buffer.from([0x00]), s256).digest();
      v = hmac(k, v, s256).digest();
    }
  }

  wif(compressed = true, testnet = false) {
    const secretBytes = Buffer.from(
      this.secret.toString(16).padStart(64, "0"),
      "hex"
    );
    const prefix = testnet ? Buffer.from([0xef]) : Buffer.from([0x80]);
    const suffix = compressed ? Buffer.from([0x01]) : Buffer.alloc(0);

    return encodeBase58Checksum(Buffer.concat([prefix, secretBytes, suffix]));
  }
}

function pow(base, exponent, modulus) {
  return base ** exponent % modulus;
}

function hmac(key, message, hashFunction) {
  return crypto.createHmac(hashFunction, key).update(message);
}
module.exports = {
  PrivateKey,
  FieldElement,
  Point,
  S256Field,
  S256Point,
  Signature,
  G,
  N,
};
