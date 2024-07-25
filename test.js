const { decodeBase58, hash256, littleEndianToInt } = require("./src/helper");
const { PrivateKey } = require("./src/ecc");
const { p2pkhScript } = require("./src/script");
const { TxIn, TxOut, Tx } = require("./src/tx");

const targetAddress = "mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv";
const passphrase = Buffer.from("this is mine arihantsinghrana2004@gmail.com");
const s = littleEndianToInt(hash256(passphrase));
const p = new PrivateKey(s);
const changeAddress = p.getAddress(true, true);
const preTx = Buffer.from(
  "a1fbb4ee3c92b063dfe192647aee3fd6cac17c69f7ce70b595c491254f9699ea",
  "hex"
);
const preIndex = 1;
const txIns = [new TxIn(preTx, preIndex)];
const targetAmount = (30 / 100) * 0.00032681;
const changeAmount = 0.00032681 - targetAmount - (60 / 100) * 0.00032681;
const txOuts = [];

// Target TxOut
const targetH160 = decodeBase58(targetAddress);
const targetScriptPubKey = p2pkhScript(targetH160);
const targetSatoshis = Math.floor(targetAmount * 100000000);
txOuts.push(new TxOut(targetSatoshis, targetScriptPubKey));

// Change TxOut
const changeH160 = decodeBase58(changeAddress);
const changeScriptPubKey = p2pkhScript(changeH160);
const changeSatoshis = Math.floor(changeAmount * 100000000);
txOuts.push(new TxOut(changeSatoshis, changeScriptPubKey));

// Create and sign transaction
const txObj = new Tx(1, txIns, txOuts, 0, true);
console.log(txObj.signInput(0, p));
console.log(txObj.serialize().toString("hex"));
