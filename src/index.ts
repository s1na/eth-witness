import * as fs from 'fs'
import * as path from 'path'
import * as assert from 'assert'
import { promisify } from 'util'
import * as yaml from 'js-yaml'
import { TrieNode as MPTTrieNode, BranchNode } from './trieNode'
import VM from 'ethereumjs-vm'
const Block = require('ethereumjs-block')
const blockFromRPC = require('ethereumjs-block/from-rpc')
const SecureTrie = require('merkle-patricia-tree/secure')

export type TrieNode = MPTTrieNode | HashNode

export class HashNode {
  _hash: Buffer

  constructor(hash: Buffer) {
    this._hash = hash
  }
}

export async function buildFromWitness(trie: any, witness: any): Promise<TrieNode | null> {
  const put = promisify(trie._putRaw).bind(trie)
  // Empty children in branches are sent as an empty string
  if (typeof witness === 'string') {
    if (witness.length > 0) throw new Error('Invalid item in witness')
    return null
  }

  if (witness.hasOwnProperty('branch')) {
    const children: any = []
    for (const child of witness.branch) {
      const node = await buildFromWitness(trie, child)
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
  } else if (witness.hasOwnProperty('hash')) {
    return new HashNode(Buffer.from(witness.hash.slice(2), 'hex'))
  } else if (witness.hasOwnProperty('extension')) {
    throw new Error('Unimplemented')
  } else if (witness.hasOwnProperty('leaf')) {
    throw new Error('Unimplemented')
  }

  throw new Error('Shouldnt reach here')
}

export async function main() {
  const testCase = yaml.safeLoad(fs.readFileSync(path.join(__dirname, 'fixture/ethereum_blocks.yaml'), 'utf8'))
  assert(testCase.trees.length === 1, 'Only supporting one tree in witness')
  // TODO: Get expected root from testcase
  const expectedRoot = Buffer.from('d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544', 'hex')
  const rpcBlock = (JSON.parse(fs.readFileSync(path.join(__dirname, 'fixture/block1.json'), 'utf8'))).result
  const block = blockFromRPC(rpcBlock)

  const trie = new SecureTrie()
  const rootNode = await buildFromWitness(trie, testCase.trees[0])

  assert(rootNode instanceof HashNode, 'buildFromWitness should return HashNode')
  assert((rootNode as HashNode)._hash.equals(expectedRoot), 'Should match expected root')
  trie.root = expectedRoot

  const vm = new VM({ state: trie, hardfork: 'byzantium' })
  const res = await vm.runBlock({ block })
}

main().then().catch((err: Error) => { throw err })
