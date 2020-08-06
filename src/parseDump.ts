import * as fs from 'fs'
import * as path from 'path'
import * as rlp from 'rlp'
import Account from 'ethereumjs-account'
import { toBuffer } from 'ethereumjs-util'
import { decodeNode, LeafNode } from './trieNode'
import { nibblesToBuffer } from './util/nibbles'

export async function main() {
  const dump = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixture/10547608_dump.json'), 'utf8'))
  const addrs = Object.keys(dump)
  addrs.sort()
  for (const addr of addrs) {
    const accData = dump[addr]
    const proof = accData.proof.accountProof
    const nonce = toBuffer(accData.proof.nonce)
    const balance = toBuffer(accData.proof.balance)
    const codeHash = toBuffer(accData.proof.codeHash)
    const stateRoot = toBuffer(accData.proof.storageHash)
    const account = new Account({ nonce, balance, codeHash, stateRoot })

    const leaf = decodeNode(proof[proof.length - 1])
    if (account.isEmpty()) {
      console.log('Empty account, exclusion proof', addr, leaf instanceof LeafNode ? 'leaf' : 'nonleaf')
      if (addr === '0x77986bb8f9cab36a300dab432387518c622515ac') {
      for (const encodedNode of proof) {
        const node = decodeNode(encodedNode)
        if (node instanceof LeafNode) {
          console.log(new Account(node.raw()[1]))
        } else {
          console.log(node)
        }
      }
      }
      continue
    }
    if (leaf instanceof LeafNode) {
      //console.log('LeafHash for', addr, ' = ', leaf.hash().toString('hex'))
      if (addr === '0x77986bb8f9cab36a300dab432387518c622515ac') {
        console.log(account)
        console.log(leaf)
        const slots: any = {}
        for (const sp of accData.proof.storageProof) {
          const slotLeaf = decodeNode(sp.proof[sp.proof.length - 1])
          if (sp.value === '0x0') {
            if (slotLeaf instanceof LeafNode) {
              const k = '0x' + (nibblesToBuffer((slotLeaf as LeafNode).key).toString('hex'))
              slots[k] = { exclusion: true, value: rlp.decode(slotLeaf.value), hash: slotLeaf.hash().toString('hex') }
              if (k == '0xb3c16128726e802abcc68437a396fac8da16b8b67cdb12b90c9600f64a') {
                console.log(slotLeaf)
              }
              //console.log('ExclusionProof', (slotLeaf as LeafNode).raw()[0].toString('hex'), ' = ', slotLeaf.value)
            } else {
              //console.log('Slot not leaf', slotLeaf)
            }
          } else {
            slots[sp.key] = { exclusion: false, value: sp.value, hash: slotLeaf.hash().toString('hex') }
            //console.log('SlotHash for', sp.key, ' = ', sp.value)
          }
          //console.log('SlotHash for', sp.key, ' = ', slotLeaf.hash().toString('hex'))
        }
        const slotAddrs = Object.keys(slots)
        slotAddrs.sort()
        console.log(slotAddrs.length, 'slot keys')
        for (const a of slotAddrs) {
          const s = slots[a]
          const value = toBuffer(s.value).toString('hex')
          if (s.exclusion) {
            console.log('ExclHash for', a, ' = ', s.hash)
          } else {
            console.log('SlotHash for', a, ' = ', s.hash)
          }
        }
      }
    } else {
      //console.log('Last node for', addr, ' is not leaf', leaf)
    }
    /*for (const encodedNode of proof) {
      console.log(rlp.decode(encodedNode))
    }*/
  }
}

main().then().catch((err: Error) => { throw err })
