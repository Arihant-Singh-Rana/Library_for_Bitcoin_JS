const Mnemonic = require("bitcore-mnemonic");
const bitcore = require("bitcore-lib");
const { Networks, PrivateKey } = bitcore;

const createWallet = (network = Networks.testnet) => {
  const privateKey = new PrivateKey(network);
  const address = privateKey.toAddress(network);

  return {
    privateKey: privateKey.toString(),
    address: address.toString(),
  };
};

/**
A Hierarchical Deterministic (HD) wallet is the term used to describe a wallet which uses a seed to derive public and private keys
**/

const createHDWallet = (network = mainnet) => {
  let passPhrase = new Mnemonic(Mnemonic.Words.SPANISH);
  let xpriv = passPhrase.toHDPrivateKey(passPhrase.toString(), network);

  return {
    xpub: xpriv.xpubkey,
    privateKey: xpriv.privateKey.toString(),
    address: xpriv.publicKey.toAddress().toString(),
    mnemonic: passPhrase.toString(),
  };
};

module.exports = {
  createHDWallet,
  createWallet,
};
