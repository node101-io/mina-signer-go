import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Field, Poseidon } from 'o1js';

const prefix = 'pulsar';
const chunkSize = 31;
const stopByte = 0x01n;
const dirname = path.dirname(fileURLToPath(import.meta.url));
const o1jsPackage = JSON.parse(
  fs.readFileSync(path.join(dirname, 'node_modules/o1js/package.json'), 'utf8'),
);

function bytesToField(bytes, addStopByte) {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value += BigInt(bytes[i]) << BigInt(8 * i);
  }
  if (addStopByte) {
    value += stopByte << BigInt(8 * bytes.length);
  }
  return Field(value);
}

function o1jsBytesToFields(hex) {
  const bytes = Buffer.from(hex, 'hex');
  const fields = [];
  let offset = 0;

  while (bytes.length - offset >= chunkSize) {
    fields.push(bytesToField(bytes.subarray(offset, offset + chunkSize), false));
    offset += chunkSize;
  }

  fields.push(bytesToField(bytes.subarray(offset), true));
  return fields;
}

function field(value) {
  return Field(BigInt(value));
}

function hashWithPrefixBytes(name, inputHex) {
  return {
    name,
    prefix,
    inputHex,
    outputDecimal: Poseidon.hashWithPrefix(prefix, o1jsBytesToFields(inputHex)).toString(),
  };
}

function hashFieldsWithPrefix(name, fieldsDecimal) {
  return {
    name,
    prefix,
    fieldsDecimal,
    outputDecimal: Poseidon.hashWithPrefix(prefix, fieldsDecimal.map(field)).toString(),
  };
}

function merkleList(name, elementsDecimal) {
  let root = Field(0);
  for (const element of elementsDecimal) {
    root = Poseidon.hashWithPrefix(prefix, [root, field(element)]);
  }

  return {
    name,
    prefix,
    elementsDecimal,
    rootDecimal: root.toString(),
  };
}

const boundary31 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e';
const boundary32 = `${boundary31}1f`;
const boundary62 = `${boundary31}${boundary31}`;
const boundary63 = `${boundary62}1f`;

const vectors = {
  o1jsVersion: o1jsPackage.version,
  hashWithPrefixBytes: [
    hashWithPrefixBytes('empty', ''),
    hashWithPrefixBytes('zero-byte', '00'),
    hashWithPrefixBytes('one-byte', '01'),
    hashWithPrefixBytes('one-zero', '0100'),
    hashWithPrefixBytes('ascii-mina-signer-go', Buffer.from('mina-signer-go', 'utf8').toString('hex')),
    hashWithPrefixBytes('boundary-31', boundary31),
    hashWithPrefixBytes('boundary-32', boundary32),
    hashWithPrefixBytes('boundary-62', boundary62),
    hashWithPrefixBytes('boundary-63', boundary63),
  ],
  hashFieldsWithPrefix: [
    hashFieldsWithPrefix('empty-fields', []),
    hashFieldsWithPrefix('one-field', ['1']),
    hashFieldsWithPrefix('two-fields', ['1', '2']),
    hashFieldsWithPrefix('right-zero', ['1', '0']),
    hashFieldsWithPrefix('three-fields', ['1', '2', '3']),
  ],
  merkleLists: [
    merkleList('empty', []),
    merkleList('append-1', ['1']),
    merkleList('append-1-to-10', ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']),
  ],
};

fs.writeFileSync(
  path.join(dirname, '..', 'o1js_alignment_vectors.json'),
  `${JSON.stringify(vectors, null, 2)}\n`,
);
