import * as fs from 'fs'
import * as path from 'path'
import * as assert from 'assert'
import { promisify } from 'util'
import * as yaml from 'js-yaml'
import { TrieNode as MPTTrieNode, BranchNode, LeafNode, ExtensionNode } from './trieNode'
import { bufferToNibbles, nibblesToBuffer } from './util/nibbles'
import VM from 'ethereumjs-vm'
import Account from 'ethereumjs-account'
import { toBuffer, keccak256 } from 'ethereumjs-util'
import * as rlp from 'rlp'
const Block = require('ethereumjs-block')
const blockFromRPC = require('ethereumjs-block/from-rpc')
const SecureTrie = require('merkle-patricia-tree/secure')
const { prove } = require('merkle-patricia-tree/proof')

export type TrieNode = MPTTrieNode | HashNode

export class HashNode {
  _hash: Buffer

  constructor(hash: Buffer) {
    this._hash = hash
  }
}

export enum TrieDomain {
  Account,
  Storage
}

export async function buildFromWitness(trie: any, witness: any, depth: number = 0, domain: TrieDomain = TrieDomain.Account, debug: boolean = false): Promise<TrieNode | null> {
  const put = promisify(trie._putRaw).bind(trie)

  // Empty children in branches are sent as an empty string
  if (typeof witness === 'string') {
    if (witness.length > 0) throw new Error(`Invalid item in witness: ${witness}`)
    return null
  }

  assert(Array.isArray(witness), 'Witness should be array')
  const typ = witness[0]
  if (typ === 'branch') {
    return buildBranch(trie, witness.slice(1), depth, domain, debug)
  } else if (typ === 'hash') {
    // TODO: Bug in witness, some hashes don't have 0x
    const h = witness[1].slice(0, 2) === '0x' ? witness[1] : `0x${witness[1]}`
    return new HashNode(toBuffer(h))
  } else if (typ === 'extension') {
    return buildExtension(trie, witness.slice(1), depth, domain, debug)
  } else if (typ === 'leaf') {
    return buildLeaf(trie, witness.slice(1), depth, domain, debug)
  } else if (typ === 'leaf_for_exclusion_proof') {
    return buildLeafForExclusionProof(trie, witness.slice(1), depth, domain, debug)
  }

  throw new Error('Shouldnt reach here')
}

export async function buildBranch(trie: any, witness: any, depth: number = 0, domain: TrieDomain = TrieDomain.Account, debug: boolean = false): Promise<TrieNode | null> {
  const put = promisify(trie._putRaw).bind(trie)

  const children: any = []
  for (const child of witness) {
    const node = await buildFromWitness(trie, child, depth + 1, domain, debug)
    if (node === null) {
      children.push(null)
    } else if (node instanceof HashNode) {
      children.push(node._hash)
    } else if (node instanceof BranchNode) {
      const serialized = node.serialize()
      // Check if child node has to be embedded in parent
      if (serialized.length < 32) {
        children.push(node.raw())
      } else {
        children.push(node.hash())
      }
    } else {
      // Assume no embedded leaf/ext
      throw new Error('Invalid built branch node')
    }
  }

  // Branch's 17th element is value
  children.push(null)
  const branch = BranchNode.fromArray(children)

  // If should be embedded return complete node
  // else insert into db and return hash
  if (branch.serialize().length < 32) {
    return branch
  } else {
    await put(branch.hash(), branch.serialize())
    return new HashNode(branch.hash())
  }
}

const leafHashes: any = {}
const storageHashes: any = {}

export async function buildLeaf(trie: any, fields: any, depth: number = 0, domain: TrieDomain = TrieDomain.Account, debug: boolean = false): Promise<TrieNode | null> {
  const put = promisify(trie._putRaw).bind(trie)

  const key = toBuffer(fields[0])
  // Derive nibbles from address and current depth
  const keyHash = keccak256(key)
  const fullKeyNibbles = bufferToNibbles(keyHash)
  const pathNibbles = fullKeyNibbles.slice(depth)

  let leafNode: LeafNode
  const account = new Account()
  if (domain === TrieDomain.Account) {
    if (fields.length !== 3 && fields.length !== 5) {
      throw new Error('Invalid leaf node')
    }

    // EoA leaves have: address, nonce, balance
    // Contract leaves have: address, nonce, balance, code, storage
    const nonce = toBuffer(fields[1])
    const balance = toBuffer(fields[2])
    account.balance = balance
    account.nonce = nonce
    // Contract
    if (fields.length === 5) {
      const code = toBuffer(fields[3])
      account.codeHash = keccak256(code)

      // Re-build contract's storage trie
      const storageNode = typeof fields[4] === 'string' ? ['hash', fields[4]] : fields[4]
      let debug = false
      //if (fields[0] === '0x0ffef1bf3a19dd96310194e73b38c069d1d1c31f') debug = true
      const storageRoot = await buildFromWitness(trie, storageNode, 0, TrieDomain.Storage, debug)
      assert(storageRoot instanceof HashNode, `buildFromWitness should return HashNode but got ${JSON.stringify(storageRoot)}`)
      account.stateRoot = (storageRoot as HashNode)._hash
    }
    const value = account.serialize()
    leafNode = new LeafNode(pathNibbles, value)
  } else {
    // Storage leaves have: storageKey, storageValue

    // TODO: Bug in witness, values don't have 0x
    const v = fields[1].slice(0, 2) === '0x' ? fields[1] : `0x${fields[1]}`
    const value = toBuffer(v)
    const encodedValue = rlp.encode(value)
    leafNode = new LeafNode(pathNibbles, encodedValue)
  }

  /*if (fields[0] === '0x0ffef1bf3a19dd96310194e73b38c069d1d1c31f') {
    console.log('found leaf', account)
  }*/
  if (debug) {
    storageHashes[fields[0]] = { exclusion: false, value: fields[1], hash: leafNode.hash().toString('hex') }
    //console.log('SlotHash for', fields[0], ' = ', fields[1])
    //console.log('SlotHash for', fields[0], ' = ', leafNode.hash().toString('hex'))
  }
  /*if (fields[0].slice(2) === '0xef7c33bda271c3e47148927a1cb9a05ecab0d69ffe2f048a798ba400dce0757f') {
    console.log('MySlot', leafNode)
  }*/
  if (domain === TrieDomain.Account) {
    leafHashes[fields[0]] = leafNode.hash().toString('hex')
    //console.log('leafhash for', fields[0].slice(2), 'is', leafNode.hash().toString('hex'))
  }

  if (leafNode.serialize().length < 32) {
    return leafNode
  } else {
    await put(leafNode.hash(), leafNode.serialize())
    return new HashNode(leafNode.hash())
  }
}

export async function buildLeafForExclusionProof(trie: any, fields: any, depth: number = 0, domain: TrieDomain = TrieDomain.Account, debug: boolean = false): Promise<TrieNode | null> {
  const put = promisify(trie._putRaw).bind(trie)

  /*if (fields[0] === '0xb3c16128726e802abcc68437a396fac8da16b8b67cdb12b90c9600f64ae') {
    fields[0] = '0xb3c16128726e802abcc68437a396fac8da16b8b67cdb12b90c9600f64a'
  }*/
  const nibbles = []
  for (const n of fields[0].slice(2)) {
    nibbles.push(parseInt(n, 16))
  }
  //const path = Buffer.from(fields[0], 'hex')
  //const nibbles = bufferToNibbles(path)

  let leafNode: LeafNode
  const account = new Account()
  if (domain === TrieDomain.Account) {
    if (fields.length !== 3 && fields.length !== 5) {
      throw new Error('Invalid leaf node')
    }

    // EoA leaves have: address, nonce, balance
    // Contract leaves have (note difference to normal leaves): address, nonce, balance, stateRoot, codeHash
    const nonce = toBuffer(ensureHexPrefix(fields[1]))
    const balance = toBuffer(ensureHexPrefix(fields[2]))
    account.balance = balance
    account.nonce = nonce
    // Contract
    if (fields.length === 5) {
      const stateRoot = toBuffer(ensureHexPrefix(fields[3]))
      account.stateRoot = stateRoot

      const codeHash = toBuffer(ensureHexPrefix(fields[4]))
      account.codeHash = codeHash
    }
    const value = account.serialize()
    leafNode = new LeafNode(nibbles, value)
  } else {
    const value = toBuffer(fields[1].slice(0, 2) === '0x' ? fields[1] : `0x${fields[1]}`)
    const encodedValue = rlp.encode(value)
    leafNode = new LeafNode(nibbles, encodedValue)
  }

  if (fields[0] == '0xfc9801ce2e30afc3bbdcf8a592e0167536e2866d48b32990e08fc5c32') {
    console.log(account)
  }

  if (debug) {
    //storageHashes[fields[0]] = { exclusion: true, value: value.toString('hex'), hash: leafNode.hash().toString('hex') }
    //console.log('ExclusionLeaf', fields[0], path.length, ' = ', value)
  }

  if (leafNode.serialize().length < 32) {
    return leafNode
  } else {
    await put(leafNode.hash(), leafNode.serialize())
    return new HashNode(leafNode.hash())
  }
}

export async function buildExtension(trie: any, fields: any, depth: number = 0, domain: TrieDomain = TrieDomain.Account, debug: boolean = false): Promise<TrieNode | null> {
  const put = promisify(trie._putRaw).bind(trie)

  const numNibbles = fields[0][0]
  const nibbleStr = fields[0][1].slice(2)
  const nibbles = []
  for (const nibble of nibbleStr) {
    nibbles.push(parseInt(nibble, 16))
  }

  const child = await buildFromWitness(trie, fields[1], depth + numNibbles, domain, debug)
  let extNode
  if (child instanceof BranchNode) {
    throw new Error('Not supporting nested branch nodes yet')
  } else if (child instanceof HashNode) {
    extNode = new ExtensionNode(nibbles, child._hash)
  } else {
    throw new Error('Invalid extension child')
  }

  if (extNode.serialize().length < 32) {
    return extNode
  } else {
    await put(extNode.hash(), extNode.serialize())
    return new HashNode(extNode.hash())
  }
}

function ensureHexPrefix(s: string): string {
  return s.slice(0, 2) === '0x' ? s : `0x${s}`
}

export async function main() {
  //const testCase = yaml.safeLoad(fs.readFileSync(path.join(__dirname, 'fixture/ethereum_blocks.yaml'), 'utf8'))
  //assert(testCase.trees.length === 1, 'Only supporting one tree in witness')
  const testCase = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixture/10547608_witness_fixed.json'), 'utf8'))
  const witness = testCase.witness
  //const rpcBlock = (JSON.parse(fs.readFileSync(path.join(__dirname, 'fixture/block_10455400.json'), 'utf8'))).result
  //const block = blockFromRPC(rpcBlock)
  const block = blockFromRPC(testCase.block)
  // TODO: Get expected root from testcase
  //const expectedRoot = Buffer.from('6cc9f96f2246444c6cb2f22b38067845956656a3586d4f893a17cc9ccdccfac0', 'hex')
  const expectedRoot = toBuffer(testCase.prestate)

  const trie = new SecureTrie()
  const rootNode = await buildFromWitness(trie, witness, 0, TrieDomain.Account)

  assert(rootNode instanceof HashNode, `buildFromWitness should return HashNode but ${rootNode}`)
  //assert((rootNode as HashNode)._hash.equals(expectedRoot), `Should match expected root. Got: ${(rootNode as HashNode)._hash.toString('hex')} Expected: ${expectedRoot.toString('hex')}`)
  trie.root = (rootNode as HashNode)._hash

  const leafAddrs = Object.keys(leafHashes)
  leafAddrs.sort()
  /*for (const addr of leafAddrs) {
    console.log('LeafHash for', addr, ' = ', leafHashes[addr])
  }*/
  const storageAddrs = Object.keys(storageHashes)
  storageAddrs.sort()
  //console.log(storageAddrs.length, 'slot keys')
  for (const addr of storageAddrs) {
    const s = storageHashes[addr]
    if (s.exclusion) {
      console.log('ExclHash for', addr, ' = ', s.hash)
    } else {
      console.log('SlotHash for', addr, ' = ', s.hash)
    }
  }

  /*const getP = promisify(trie.get).bind(trie)
  const proveP = promisify(prove)
  const sender = await getP(toBuffer('0x912656188616e0184e3181f019022990a63280b1'))
  const proof = await proveP(trie, keccak256(toBuffer('0x77986bb8f9cab36a300dab432387518c622515ac')))
  for (const n of proof) {
    console.log(rlp.decode(n))
  }*/
  //console.log(proof)
  assert((rootNode as HashNode)._hash.equals(expectedRoot), `Should match expected root. Got: ${(rootNode as HashNode)._hash.toString('hex')} Expected: ${expectedRoot.toString('hex')}`)
  /*const senderAcc = new Account(sender)
  trie.root = senderAcc.stateRoot
  const slot = await getP(toBuffer('0x000000000000000000000000000000000000000000000000000000000000000a'))
  console.log('slot is', slot)*/

  const vm = new VM({ state: trie, hardfork: 'muirGlacier' })
  const res = await vm.runBlock({ block, skipBlockValidation: true })
}

main().then().catch((err: Error) => { throw err })
