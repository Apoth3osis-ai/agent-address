const { generateMnemonic, mnemonicToSeedSync } = require("@scure/bip39");
const { wordlist } = require("@scure/bip39/wordlists/english.js");
const { HDKey } = require("@scure/bip32");
const { keccak_256 } = require("@noble/hashes/sha3.js");
const { bytesToHex } = require("@noble/hashes/utils.js");
const secp = require("@noble/secp256k1");
const { evmChains } = require("./chains");

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { words: 12, index: 0, json: false, mnemonic: null };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--words" && args[i + 1]) {
      out.words = Number(args[++i]);
    } else if ((a === "--index" || a === "-i") && args[i + 1]) {
      out.index = Number(args[++i]);
    } else if (a === "--json") {
      out.json = true;
    } else if (a === "--mnemonic" && args[i + 1]) {
      out.mnemonic = args[++i];
    }
  }
  if (![12, 24].includes(out.words)) {
    throw new Error("--words must be 12 or 24");
  }
  return out;
}

function toChecksumAddress(hexAddr) {
  const stripped = hexAddr.toLowerCase().replace("0x", "");
  const hash = bytesToHex(keccak_256(Buffer.from(stripped, "hex")));
  let ret = "0x";
  for (let i = 0; i < stripped.length; i++) {
    ret += parseInt(hash[i], 16) >= 8 ? stripped[i].toUpperCase() : stripped[i];
  }
  return ret;
}

function deriveEvm(seed, index) {
  const hd = HDKey.fromMasterSeed(seed);
  const path = `m/44'/60'/0'/0/${index}`;
  const node = hd.derive(path);
  const priv = node.privateKey;
  if (!priv) throw new Error("Failed to derive EVM private key");
  const pub = secp.getPublicKey(priv, false).slice(1); // uncompressed, drop 0x04
  const addrBytes = keccak_256(pub).slice(-20);
  const address = toChecksumAddress("0x" + bytesToHex(addrBytes));
  return {
    path,
    privateKeyHex: "0x" + bytesToHex(priv),
    address,
  };
}

function generate(opts = {}) {
  const mnemonic = opts.mnemonic || generateMnemonic(wordlist, opts.words === 12 ? 128 : 256);
  const seed = mnemonicToSeedSync(mnemonic);

  const evm = deriveEvm(seed, opts.index);
  const output = {
    mnemonic,
    evmAddress: evm.address,
    evmPrivateKey: evm.privateKeyHex,
    evmChains,
  };
  return output;
}

function main() {
  const opts = parseArgs();
  const output = generate(opts);
  if (opts.json) {
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log("=== EVM Wallet Generator ===\n");
    console.log("Mnemonic (write down, never share):\n" + output.mnemonic + "\n");
    console.log("[EVM] Address: " + output.evmAddress);
    console.log("[EVM] Private key (hex): " + output.evmPrivateKey);
    console.log("[EVM] Path: " + output.evmDerivationPath);
    console.log("[EVM] Works on: " + evmChains.join(", "));
    console.log("\nNOTE: EVM address is identical across all listed EVM chains.");
    console.log("Keep keys and mnemonic secret. This script does not write to disk.");
  }
}

module.exports = { generate };

if (require.main === module) {
  main();
}
