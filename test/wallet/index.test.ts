/* globals describe it beforeEach afterEach */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';

import memdown from 'memdown';
import Database from '../../src/database';
import MerkleTree from '../../src/merkletree';
import Note from '../../src/note';
import utils from '../../src/utils';

import Wallet, { WalletDetails } from '../../src/wallet';

import type { Commitment } from '../../src/merkletree';

chai.use(chaiAsPromised);
const { expect } = chai;

let db: Database;
let merkletree: MerkleTree;
let wallet: Wallet;

const testMnemonic = 'test test test test test test test test test test test junk';
const testEncryptionKey = '01';

const keypairs = [{ // Primary 0
  privateKey: '0852ea0ca28847f125cf5c206d8f62d4dc59202477dce90988dc57d5e9b2f144',
  publicKey: 'c95956104f69131b1c269c30688d3afedd0c3a155d270e862ea4c1f89a603a1b',
  address: 'rgeth1q8y4j4ssfa53xxcuy6wrq6yd8tld6rp6z4wjwr5x96jvr7y6vqapk0tmp0s',
},
{ // Primary 1
  privateKey: '0d65921bba9cd412064b41cf915266f5d9302e8bcbfd3ed8457ea914edbb01c2',
  publicKey: '6dd2398c78ea7662655bbce41224012c4948645ba12fc843f9dbb9a6b9e24005',
  address: 'rgeth1q9kaywvv0r48vcn9tw7wgy3yqykyjjrytwsjljzrl8dmnf4eufqq2qdalzf',
},
{ // Primary 5
  privateKey: '0a84aed056690cf95db7a35a2f79795f3f6656203a05b35047b7cb7b6f4d27c3',
  publicKey: '49036a0ebd462c2a7e4311de737a92b6e36bd0c5505c446ec8919dfccc5d448e',
  address: 'rgeth1q9ysx6swh4rzc2n7gvgauum6j2mwx67sc4g9c3rwezgemlxvt4zgujlt072',
},
{ // Change 2
  privateKey: '0ad38aeedddc5a9cbc51007ce04d1800a628cc5aea50c5c8fb4cd23c13941500',
  publicKey: 'e4fb4c45e08bf87ba679185d03b0d5de4df67b5079226eff9d7e990a30773e07',
  address: 'rgeth1q8j0knz9uz9ls7ax0yv96qas6h0ymanm2pujymhln4lfjz3swulqwn5p63t',
}];

const senderPublicKey = '37e3984a41b34eaac002c140b28e5d080f388098a51d34237f33e84d14b9e491';

const keypairsPopulated = keypairs.map((key) => ({
  ...key,
  sharedKey: utils.babyjubjub.ecdh(key.privateKey, senderPublicKey),
}));

const notesPrep = [
  0, 1, 2, 3, 2, 0,
];

const leaves: Commitment[] = notesPrep.map((keyIndex) => {
  const note = new Note.ERC20(
    keypairsPopulated[keyIndex].publicKey,
    '1e686e7506b0f4f21d6991b4cb58d39e77c31ed0577a986750c8dce8804af5b9',
    'ffff',
    '21543ad39bf8f7649d6325e44f53cbc84f501847cf42bd9fb14d63be21dcffc8',
  );

  return {
    hash: note.hash,
    senderPublicKey,
    ciphertext: note.encrypt(keypairsPopulated[keyIndex].sharedKey),
  };
});

describe('Wallet/Index', () => {
  beforeEach(async () => {
    // Create database and wallet
    db = new Database(memdown());
    merkletree = new MerkleTree(db, 1, 'erc20', async () => true);
    wallet = await Wallet.fromMnemonic(db, testEncryptionKey, testMnemonic);
  });

  it('Should load existing wallet', async () => {
    const wallet2 = await Wallet.loadExisting(db, testEncryptionKey, wallet.id);
    expect(wallet2.id).to.equal(wallet.id);
  });

  it('Should get wallet prefix path', async () => {
    expect(wallet.getWalletDBPrefix(1)).to.deep.equal([
      '000000000000000000000000000000000000000000000000000077616c6c6574',
      'c9855eb0e997395c2e4e2ada52487860509e0daf2ef8f74a6fe7ded9853efa42',
      '0000000000000000000000000000000000000000000000000000000000000001',
    ]);
  });

  it('Should derive addresses correctly', async () => {
    const vectors = [
      {
        index: 0,
        change: false,
        chainID: 1,
        address: 'rgeth1q8y4j4ssfa53xxcuy6wrq6yd8tld6rp6z4wjwr5x96jvr7y6vqapk0tmp0s',
      },
      {
        index: 1,
        change: false,
        chainID: 1,
        address: 'rgeth1q9kaywvv0r48vcn9tw7wgy3yqykyjjrytwsjljzrl8dmnf4eufqq2qdalzf',
      },
      {
        index: 5,
        change: false,
        chainID: 1,
        address: 'rgeth1q9ysx6swh4rzc2n7gvgauum6j2mwx67sc4g9c3rwezgemlxvt4zgujlt072',
      },
      {
        index: 2,
        change: true,
        chainID: 1,
        address: 'rgeth1q8j0knz9uz9ls7ax0yv96qas6h0ymanm2pujymhln4lfjz3swulqwn5p63t',
      },
      {
        index: 0,
        change: false,
        chainID: 56,
        address: 'rgbsc1q8y4j4ssfa53xxcuy6wrq6yd8tld6rp6z4wjwr5x96jvr7y6vqapknjv6r8',
      },
      {
        index: 13,
        change: true,
        chainID: 1,
        address: 'rgeth1qy87jfm8nwnl0t4y2f2tnv5vyzfxlt8sgphhvg2wya79t0uqpskpzpercjs',
      },
      {
        index: 0,
        change: false,
        chainID: undefined,
        address: 'rgany1q8y4j4ssfa53xxcuy6wrq6yd8tld6rp6z4wjwr5x96jvr7y6vqapkz2ffkk',
      },
    ];

    vectors.forEach((vector) => {
      expect(wallet.getAddress(
        vector.index,
        vector.change,
        vector.chainID,
      )).to.deep.equal(vector.address);
    });
  });

  it('Should get empty wallet details', async () => {
    expect(await wallet.getWalletDetails(1)).to.deep.equal({
      treeScannedHeights: [],
      primaryHeight: 0,
      changeHeight: 0,
    });
  });

  it('Should scan ERC20 balances at index', async () => {
    merkletree.queueLeaves(0, leaves, 0);
    expect(await wallet.scanIndex(0, false, leaves))
      .to.deep.equal([true, false, false, false, false, true]);
  });

  it('Should scan ERC20 balances', async () => {
    await merkletree.queueLeaves(0, leaves, 0);
    await wallet.scan(merkletree);
  });

  it('Should find the highest index of wallet', async () => {
    let walletDetails: WalletDetails = {
      treeScannedHeights: [],
      primaryHeight: 0,
      changeHeight: 0,
    };

    // mock scanIndex
    // user is deemed to have a balance on indices 0, 1 and 2
    // both on main address and change address
    let counter = 0;
    wallet.scanIndex = async () => {
      if (counter < 6) {
        counter += 1;
        return [true, false, false, true, false, false];
      }
      return [false, false, false, false, false, false];
    };

    walletDetails = await wallet.findWalletHighestIndex(walletDetails, leaves);
    const expectedWalletDetails = { ...walletDetails, primaryHeight: 2 };
    expect(walletDetails).to.deep.equal(expectedWalletDetails);
  });

  afterEach(() => {
    // Clean up database
    db.level.close();
  });
});
