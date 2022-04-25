import BN from 'bn.js';
import msgpack from 'msgpack-lite';
import EventEmitter from 'events';
import type { AbstractBatch } from 'abstract-leveldown';
import { HDNode } from '@ethersproject/hdnode';
import { hexToBytes } from 'ethereum-cryptography/utils';
import { ed25519, encryption, hash, keysUtils } from '../utils';
import { Database } from '../database';
import { mnemonicToSeed } from '../keyderivation/bip39';
import { Note } from '../note';
import type { Commitment, MerkleTree } from '../merkletree';
import { bech32, Node } from '../keyderivation';
import { LeptonDebugger } from '../models/types';
import { BytesData, NoteSerialized } from '../models/transaction-types';
import {
  arrayify,
  combine,
  formatToByteLength,
  fromUTF8String,
  hexlify,
  nToHex,
  numberify,
  padToLength,
} from '../utils/bytes';
import { SpendingKeyPair, ViewingKeyPair } from '../keyderivation/bip32';

const { poseidon } = keysUtils;

export type WalletDetails = {
  treeScannedHeights: number[];
};

export type TXO = {
  tree: number;
  position: number;
  index: number;
  txid: string;
  spendtxid: string | false;
  dummyKey?: string; // For dummy notes
  note: Note;
};

export type TreeBalance = {
  balance: bigint;
  utxos: TXO[];
};

export type Balances = {
  [key: string]: TreeBalance;
  // Key: Token
};

export type BalancesByTree = {
  [key: string]: TreeBalance[];
  // Index = tree
};

export type ScannedEventData = {
  chainID: number;
};

export type AddressKeys = {
  masterPublicKey: bigint;
  viewingPublicKey: Uint8Array;
};

export type WalletData = { mnemonic: string; index: number };

export type WalletNodes = { spending: Node; viewing: Node };
/**
 * constant defining the derivation path prefixes for spending and viewing keys
 * must be appended with index' to form a complete path
 */
const DERIVATION_PATH_PREFIXES = {
  SPENDING: "m/44'/1984'/0'/0'/",
  VIEWING: "m/420'/1984'/0'/0'/",
};

/**
 * Helper to append DERIVATION_PATH_PREFIXES with index'
 */
export function derivePathsForIndex(index: number = 0) {
  return {
    spending: `${DERIVATION_PATH_PREFIXES.SPENDING}${index}'`,
    viewing: `${DERIVATION_PATH_PREFIXES.VIEWING}${index}'`,
  };
}

export function deriveNodes(mnemonic: string, index: number = 0): WalletNodes {
  const paths = derivePathsForIndex(index);
  return {
    // eslint-disable-next-line no-use-before-define
    spending: Node.fromMnemonic(mnemonic).derive(paths.spending),
    // eslint-disable-next-line no-use-before-define
    viewing: Node.fromMnemonic(mnemonic).derive(paths.viewing),
  };
}

class Wallet extends EventEmitter {
  private db: Database;

  readonly id: string;

  // #viewingKey: Node;

  #viewingKeyPair!: ViewingKeyPair;

  masterPublicKey!: bigint;

  readonly merkletree: MerkleTree[] = [];

  // Lock scanning operations to prevent race conditions
  private scanLockPerChain: boolean[] = [];

  public spendingPublicKey!: [bigint, bigint];

  private leptonDebugger: LeptonDebugger = console;

  /**
   * Create Wallet controller
   * @param id - wallet ID
   * @param db - database
   */
  constructor(id: string, db: Database) {
    super();
    this.id = id;
    this.db = db;
  }

  async initialize(nodes: WalletNodes): Promise<Wallet> {
    const { spending, viewing } = nodes;
    this.#viewingKeyPair = await viewing.getViewingKeyPair();
    const spendingKeyPair = spending.getSpendingKeyPair();
    this.masterPublicKey = Node.getMasterPublicKey(spendingKeyPair.pubkey, this.getNullifyingKey());
    this.spendingPublicKey = spendingKeyPair.pubkey;

    return this;
  }

  /**
   * Loads merkle tree into wallet
   * @param merkletree - merkletree to load
   */
  loadTree(merkletree: MerkleTree) {
    this.merkletree[merkletree.chainID] = merkletree;
  }

  /**
   * Unload merkle tree by chainID
   * @param chainID - chainID of tree to unload
   */
  unloadTree(chainID: number) {
    delete this.merkletree[chainID];
  }

  /**
   * Construct DB path from chainID
   * Prefix consists of ['wallet', id, chainID]
   * May be appended with tree and position
   * @param chainID - chainID
   * @returns wallet DB prefix
   */
  getWalletDBPrefix(chainID: number, tree?: number, position?: number): string[] {
    const path = [fromUTF8String('wallet'), hexlify(this.id), hexlify(new BN(chainID))].map(
      (element) => element.padStart(64, '0'),
    );
    if (tree !== undefined) path.push(hexlify(padToLength(new BN(tree), 32)));
    if (position !== undefined) path.push(hexlify(padToLength(new BN(position), 32)));
    return path;
  }

  /**
   * Construct DB path from chainID
   * @returns wallet DB path
   */
  getWalletDetailsPath(chainID: number): string[] {
    return this.getWalletDBPrefix(chainID);
  }

  /**
   * Sign message with ed25519 node derived at path index
   * @param message - hex or Uint8 bytes of message to sign
   * @param index - index to get keypair at
   * @returns Promise<Uint8Array>
   */
  async signEd25519(message: string | Uint8Array) {
    return await ed25519.sign(message, nToHex(this.#viewingKeyPair.privateKey));
  }

  /**
   * Load encrypted spending key Node from database and return babyjubjub private key
   * @returns Promise<string>
   */
  async getSpendingKeyPair(encryptionKey: BytesData): Promise<SpendingKeyPair> {
    const node = await this.loadSpendingKey(encryptionKey);
    return node.getSpendingKeyPair();
  }

  getViewingKeyPair(): ViewingKeyPair {
    return this.#viewingKeyPair;
  }

  /**
   * Nullifying Key aka Viewing Private Key aka vpk derived on ed25519 curve
   * Used to decrypt and nullify notes
   * @todo protect like spending private key
   */
  getNullifyingKey(): bigint {
    return poseidon([this.#viewingKeyPair.privateKey]);
  }

  /**
   * Get Viewing Public Key (VK)
   * @returns string
   */
  get viewingPublicKey(): Uint8Array {
    return this.#viewingKeyPair.pubkey;
  }

  /**
   * Public keys of wallet encoded in address
   */
  get addressKeys(): AddressKeys {
    return {
      masterPublicKey: this.masterPublicKey,
      viewingPublicKey: this.viewingPublicKey,
    };
  }

  /**
   * Encode address from (MPK, VK) + chainID
   * @returns address
   */
  getAddress(chainID: number | undefined): string {
    return bech32.encode({ ...this.addressKeys, chainID });
  }

  /**
   * Get encrypted wallet details for this wallet
   */
  async getWalletDetails(chainID: number): Promise<WalletDetails> {
    let walletDetails: WalletDetails;

    try {
      // Try fetching from database
      walletDetails = msgpack.decode(
        arrayify(
          // @todo use different key?
          await this.db.getEncrypted(
            this.getWalletDetailsPath(chainID),
            nToHex(this.masterPublicKey),
          ),
        ),
      );
    } catch {
      // If details don't exist yet, return defaults
      walletDetails = {
        treeScannedHeights: [],
      };
    }

    return walletDetails;
  }

  /**
   * Scans wallet at index for new balances
   * @param index - index of address to scan
   * Commitment index in array should be same as commitment index in tree
   * @param tree - tree number we're scanning
   * @param chainID - chainID we're scanning
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async scanLeaves(leaves: Commitment[], tree: number, chainID: number): Promise<boolean> {
    this.leptonDebugger?.log(
      `wallet:scanLeaves ${tree} ${chainID} leaves.length: ${leaves.length}`,
    );
    const vpk = this.#viewingKeyPair.privateKey;

    const writeBatch: AbstractBatch[] = [];

    // Loop through passed commitments
    for (let position = 0; position < leaves.length; position += 1) {
      let note: Note | undefined;
      const leaf = leaves[position];

      if ('ciphertext' in leaf) {
        // Derive shared secret
        // eslint-disable-next-line no-await-in-loop
        const sharedKey = await encryption.getSharedKey(
          nToHex(vpk),
          leaf.ciphertext.ephemeralKeys[0],
        );

        // Decrypt
        try {
          note = Note.decrypt(leaf.ciphertext.ciphertext, hexToBytes(sharedKey));
          // } catch (e: any) {} // not addressed to us
        } catch (e: any) {
          // debug test
          this.leptonDebugger?.error(e);
        }
      } else {
        // preimage
        // Deserialize
        const serialized: NoteSerialized = {
          npk: leaf.preimage.npk,
          encryptedRandom: leaf.encryptedRandom,
          token: leaf.preimage.token.tokenAddress,
          value: leaf.preimage.value,
        };
        try {
          note = Note.deserialize(serialized, vpk, this.addressKeys);
          // } catch (e: any) {} // not addressed to us
        } catch (e: any) {
          // debug test
          this.leptonDebugger?.error(e);
        }
      }

      // If this note is addressed to us add to write queue
      // @todo shouldn't need to check if note is not undefined
      if (note !== undefined) {
        // }.masterPublicKey === this.masterPublicKey) {
        const storedCommitment = {
          spendtxid: false,
          txid: hexlify(leaf.txid),
          nullifier: nToHex(Note.getNullifier(vpk, position)),
          decrypted: note.serialize(nToHex(vpk)),
        };
        writeBatch.push({
          type: 'put',
          key: this.getWalletDBPrefix(chainID, tree, position).join(':'),
          value: msgpack.encode(storedCommitment),
        } as AbstractBatch);
      }
    }

    // Write to DB
    await this.db.batch(writeBatch);

    // Return if we found any leaves we could decrypt
    return writeBatch.length > 0;
  }

  /**
   * Get TXOs list of a chain
   * @param chainID - chainID to get UTXOs for
   * @returns UTXOs list
   */
  async TXOs(chainID: number): Promise<TXO[]> {
    const address = this.addressKeys;
    const vpk = this.getViewingKeyPair().privateKey;

    const latestTree = await this.merkletree[chainID].latestTree();
    // Get chain namespace
    const namespace = this.getWalletDBPrefix(chainID, latestTree);

    // Stream list of keys out
    const keys: string[] = await new Promise((resolve) => {
      const keyList: string[] = [];

      // Stream list of keys and resolve on end
      this.db
        .streamNamespace(namespace)
        .on('data', (key) => {
          keyList.push(key);
        })
        .on('end', () => {
          resolve(keyList);
        });
    });

    // Calculate UTXOs
    return Promise.all(
      keys.map(async (key) => {
        // Split key into path components
        const keySplit = key.split(':');

        // Decode UTXO
        const UTXO = msgpack.decode(arrayify(await this.db.get(keySplit)));

        // If this UTXO hasn't already been marked as spent, check if it has
        if (!UTXO.spendtxid) {
          // Get nullifier
          const nullifierTX = await this.merkletree[chainID].getNullified(UTXO.nullifier);

          // If it's nullified write spend txid to wallet storage
          if (nullifierTX) {
            UTXO.spendtxid = nullifierTX;

            // Write nullifier spend txid to db
            await this.db.put(keySplit, msgpack.encode(UTXO));
          }
        }

        const tree = numberify(keySplit[3]).toNumber();
        const position = numberify(keySplit[4]).toNumber();

        const note = Note.deserialize(UTXO.decrypted, vpk, address);

        return {
          tree,
          position,
          index: UTXO.index,
          txid: UTXO.txid,
          spendtxid: UTXO.spendtxid,
          note,
        };
      }),
    );
  }

  /**
   * Gets wallet balances
   * @param chainID - chainID to get balances for
   * @returns balances
   */
  async balances(chainID: number): Promise<Balances> {
    const TXOs = await this.TXOs(chainID);
    const balances: Balances = {};

    // Loop through each TXO and add to balances if unspent
    TXOs.forEach((txOutput) => {
      const token = formatToByteLength(txOutput.note.token, 32, false);
      // If we don't have an entry for this token yet, create one
      if (!balances[token]) {
        balances[token] = {
          balance: BigInt(0),
          utxos: [],
        };
      }

      // If txOutput is unspent process it
      if (!txOutput.spendtxid) {
        // Store txo
        balances[token].utxos.push(txOutput);

        // Increment balance
        balances[token].balance += txOutput.note.value;
      }
    });

    return balances;
  }

  async getBalance(chainID: number, tokenAddress: string) {
    return (await this.balances(chainID))[formatToByteLength(tokenAddress, 32, false)]?.balance;
  }

  /**
   * Sort token balances by tree
   * @param chainID - chainID of token
   * @returns balances by tree
   */
  async balancesByTree(chainID: number): Promise<BalancesByTree> {
    // Fetch balances
    const balances = await this.balances(chainID);

    // Sort token balances by tree
    const balancesByTree: BalancesByTree = {};

    // Loop through each token
    Object.keys(balances).forEach((token) => {
      // Create balances tree array
      balancesByTree[token] = [];

      // Loop through each UTXO and sort by ree
      balances[token].utxos.forEach((utxo) => {
        if (!balancesByTree[token][utxo.tree]) {
          balancesByTree[token][utxo.tree] = {
            balance: utxo.note.value,
            utxos: [utxo],
          };
        } else {
          balancesByTree[token][utxo.tree].balance += utxo.note.value;
          balancesByTree[token][utxo.tree].utxos.push(utxo);
        }
      });
    });

    return balancesByTree;
  }

  /**
   * Scans for new balances
   * @param chainID - chainID to scan
   */
  async scan(chainID: number) {
    // Don't proceed if scan write is locked
    if (this.scanLockPerChain[chainID]) {
      this.leptonDebugger?.log(`wallet: scan(${chainID}) locked`);
      return;
    }
    this.leptonDebugger?.log(`wallet: scan(${chainID})`);

    // Lock scan on this chain
    this.scanLockPerChain[chainID] = true;

    // Fetch wallet details
    const walletDetails = await this.getWalletDetails(chainID);

    // Get latest tree
    const latestTree = await this.merkletree[chainID].latestTree();

    // Refresh list of trees
    while (walletDetails.treeScannedHeights.length < latestTree + 1) {
      // Instantiate new trees in wallet data
      walletDetails.treeScannedHeights.push(0);
    }

    // Loop through each tree and scan
    for (let tree = 0; tree < walletDetails.treeScannedHeights.length; tree += 1) {
      // Get scanned height
      const scannedHeight = walletDetails.treeScannedHeights[tree];

      // Create sparse array of tree
      // eslint-disable-next-line no-await-in-loop
      const fetcher = new Array(await this.merkletree[chainID].getTreeLength(tree));

      // Fetch each leaf we need to scan
      for (let index = scannedHeight; index < fetcher.length; index += 1) {
        fetcher[index] = this.merkletree[chainID].getCommitment(tree, index);
      }

      // Wait till all leaves are fetched
      // eslint-disable-next-line no-await-in-loop
      const leaves: Commitment[] = await Promise.all(fetcher);

      // Delete undefined values and return sparse array
      leaves.forEach((value, index) => {
        if (value === undefined) {
          this.leptonDebugger?.log('wallet.scan: value was undefined');
          delete leaves[index];
        }
      });

      // Start scanning primary and change
      // eslint-disable-next-line no-await-in-loop
      await this.scanLeaves(leaves, tree, chainID); // @todo add start index

      // Commit new scanned height
      walletDetails.treeScannedHeights[tree] = leaves.length > 0 ? leaves.length - 1 : 0;
    }

    // Write wallet details to db
    await this.db.putEncrypted(
      this.getWalletDetailsPath(chainID),
      nToHex(this.masterPublicKey),
      msgpack.encode(walletDetails),
    );

    // Emit scanned event for this chain
    this.leptonDebugger?.log(`wallet: scanned ${chainID}`);
    this.emit('scanned', { chainID } as ScannedEventData);

    // Release lock
    this.scanLockPerChain[chainID] = false;
  }

  static dbPath(id: string): BytesData[] {
    return [fromUTF8String('wallet'), id];
  }

  static async read(db: Database, id: string, encryptionKey: BytesData): Promise<WalletData> {
    return msgpack.decode(arrayify(await db.getEncrypted(Wallet.dbPath(id), encryptionKey)));
  }

  static async write(
    db: Database,
    id: string,
    encryptionKey: BytesData,
    data: WalletData,
  ): Promise<void> {
    await db.putEncrypted(Wallet.dbPath(id), encryptionKey, msgpack.encode(data));
  }

  /**
   * Calculate Wallet ID from mnemonic and derivation path index
   * @param {string} mnemonic
   * @param {index} number
   * @returns {string} - hash of mnemonic and index
   */
  static generateID(mnemonic: string, index: number) {
    return hash.sha256(combine([mnemonicToSeed(mnemonic), index.toString(16)]));
  }

  /**
   * Create a wallet from mnemonic
   * @param {Database} db - database
   * @param {BytesData} encryptionKey - encryption key to use with database
   * @param {string} mnemonic - mnemonic to load wallet from
   * @param {number} index - index of derivation path to derive if not 0
   * @returns {Wallet} Wallet
   */
  static async fromMnemonic(
    db: Database,
    encryptionKey: BytesData,
    mnemonic: string,
    index: number = 0,
  ): Promise<Wallet> {
    const id = Wallet.generateID(mnemonic, index);

    // Write encrypted mnemonic to DB
    await Wallet.write(db, id, encryptionKey, { mnemonic, index });

    const nodes = deriveNodes(mnemonic, index);

    // Create wallet object and return
    return await new Wallet(id, db).initialize(nodes);
  }

  /**
   * Loads wallet data from database and creates wallet object
   * @param {Database} db - database
   * @param {BytesData} encryptionKey - encryption key to use with database
   * @param {string} id - wallet id
   * @returns {Wallet} Wallet
   */
  static async loadExisting(db: Database, encryptionKey: BytesData, id: string): Promise<Wallet> {
    // Get encrypted mnemonic and derivation path from DB
    const { mnemonic, index } = await Wallet.read(db, id, encryptionKey);
    const nodes = deriveNodes(mnemonic, index);

    // Create wallet object and return
    return await new Wallet(id, db).initialize(nodes);
  }

  /**
   * Load encrypted node from database with encryption key
   * @param {BytesData} encryptionKey
   * @returns {Node} BabyJubJub node
   */
  async loadSpendingKey(encryptionKey: BytesData): Promise<Node> {
    const { mnemonic, index } = await Wallet.read(this.db, this.id, encryptionKey);

    return deriveNodes(mnemonic, index).spending;
  }

  /**
   * Helper to get the ethereum/whatever address is associated with this wallet
   */
  async getChainAddress(encryptionKey: BytesData): Promise<string> {
    const { mnemonic, index } = await Wallet.read(this.db, this.id, encryptionKey);
    const path = `m/44'/60'/0'/0/${index}`;
    const hdnode = HDNode.fromMnemonic(mnemonic).derivePath(path);
    return hdnode.address;
  }
}

export { Wallet };
