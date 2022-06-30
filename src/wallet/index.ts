import { HDNode } from '@ethersproject/hdnode';
import type { AbstractBatch } from 'abstract-leveldown';
import BN from 'bn.js';
import EventEmitter from 'events';
import msgpack from 'msgpack-lite';
import { Database } from '../database';
import LeptonDebug from '../debugger';
import { bech32, Node } from '../keyderivation';
import { SpendingKeyPair, ViewingKeyPair } from '../keyderivation/bip32';
import { mnemonicToSeed } from '../keyderivation/bip39';
import { MerkleTree } from '../merkletree';
import { LeptonEvent, ScannedEventData } from '../models/event-types';
import { BytesData, Commitment, NoteSerialized } from '../models/formatted-types';
import { TXO } from '../models/txo-types';
import { Note } from '../note';
import { hash } from '../utils';
import {
  arrayify,
  ByteLength,
  combine,
  formatToByteLength,
  fromUTF8String,
  hexlify,
  hexStringToBytes,
  nToHex,
  numberify,
  padToLength
} from '../utils/bytes';
import { poseidon } from '../utils/hash';
import { getSharedSymmetricKey, signED25519 } from '../utils/keys-utils';
import {
  AddressKeys,
  Balances,
  BalancesByTree, TransactionLogEntry, TransactionsLog, TransferDirection, TreeBalance, WalletData, WalletDetails
} from './types';

type WalletNodes = { spending: Node; viewing: Node };

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

  #viewingKeyPair!: ViewingKeyPair;

  masterPublicKey!: bigint;

  nullifyingKey!: bigint;

  readonly merkletree: MerkleTree[] = [];

  public spendingPublicKey!: [bigint, bigint];

  /**
   * Create Wallet controller
   * @param id - wallet ID
   * @param db - database
   */
  constructor(id: string, db: Database) {
    super();
    this.id = hexlify(id);
    this.db = db;
  }

  async initialize(nodes: WalletNodes): Promise<Wallet> {
    const { spending, viewing } = nodes;
    this.#viewingKeyPair = await viewing.getViewingKeyPair();
    const spendingKeyPair = spending.getSpendingKeyPair();
    this.nullifyingKey = poseidon([BigInt(hexlify(this.#viewingKeyPair.privateKey, true))]);
    this.masterPublicKey = Node.getMasterPublicKey(spendingKeyPair.pubkey, this.getNullifyingKey());
    this.spendingPublicKey = spendingKeyPair.pubkey;

    return this;
  }

/**
 * Groups a list of transaction logs by txid
 * @param list - list of transaction logs 
 * @returns map of transaction logs by txid
 */
  private static groupBy(list: TransactionLogEntry[]): Map<string, TransactionLogEntry[]> {
    const map = new Map();
    list.forEach((item) => {
         const key = item.txid;
         const collection = map.get(key);
         if (!collection) {
             map.set(key, [item]);
         } else {
             collection.push(item);
         }
    });
    return map;
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
   * @optional tree - without this param, all trees
   * @optional position - without this param, all positions
   * @returns wallet DB prefix
   */
  getWalletDBPrefix(chainID: number, tree?: number, position?: number): string[] {
    const path = [fromUTF8String('wallet'), hexlify(this.id), hexlify(new BN(chainID))].map(
      (element) => element.padStart(64, '0'),
    );
    if (tree != null) path.push(hexlify(padToLength(new BN(tree), 32)));
    if (position != null) path.push(hexlify(padToLength(new BN(position), 32)));
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
   * Load encrypted spending key Node from database
   * Spending key should be kept private and only accessed on demand
   * @returns {Promise<SpendingKeyPair>}
   */
  async getSpendingKeyPair(encryptionKey: BytesData): Promise<SpendingKeyPair> {
    const node = await this.loadSpendingKey(encryptionKey);
    return node.getSpendingKeyPair();
  }

  /**
   * Return object of Viewing privateKey and pubkey
   * @returns {ViewingKeyPair}
   */
  getViewingKeyPair(): ViewingKeyPair {
    return this.#viewingKeyPair;
  }

  /**
   * Used only to sign Relayer fee messages.
   * Verified using Relayer's viewingPublicKey, which is encoded in its rail address.
   * @param {Uint8Array} message - message to sign as Uint8Array
   */
  async signWithViewingKey(message: Uint8Array): Promise<Uint8Array> {
    const viewingPrivateKey = this.getViewingKeyPair().privateKey;
    return signED25519(message, viewingPrivateKey);
  }

  /**
   * Nullifying Key (ie poseidon hash of Viewing Private Key) aka vpk derived on ed25519 curve
   * Used to decrypt and nullify notes
   * @returns {bigint}
   */
  getNullifyingKey(): bigint {
    return this.nullifyingKey;
  }

  /**
   * Get Viewing Public Key (VK)
   * @returns {Uint8Array}
   */
  get viewingPublicKey(): Uint8Array {
    return this.#viewingKeyPair.pubkey;
  }

  /**
   * Return masterPublicKey and viewingPublicKey used to encode RAILGUN addresses
   * @returns {AddressKeys}
   */
  get addressKeys(): AddressKeys {
    return {
      masterPublicKey: this.masterPublicKey,
      viewingPublicKey: this.viewingPublicKey,
    };
  }

  /**
   * Encode address from (MPK, VK) + chainID
   * @returns {string} bech32 encoded RAILGUN address
   */
  getAddress(chainID: number | undefined): string {
    return bech32.encode({ ...this.addressKeys, chainID });
  }

  /**
   * Get encrypted wallet details for this wallet
   * @param {number} chainID
   * @returns {WalletDetails} including treeScannedHeight
   */
  async getWalletDetails(chainID: number): Promise<WalletDetails> {
    let walletDetails: WalletDetails;

    try {
      // Try fetching from database
      walletDetails = msgpack.decode(
        arrayify(await this.db.get(this.getWalletDetailsPath(chainID))),
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
   * Commitment index in array should be same as commitment index in tree
   * @param {Commitment[]} leaves - commitments from events to attempt parsing
   * @param {number} tree - tree number we're scanning
   * @param {number} chainID - chainID we're scanning
   * @param {number} scannedHeight - starting position
   */
  async scanLeaves(
    leaves: (Commitment | undefined)[],
    tree: number,
    chainID: number,
    scannedHeight: number,
    treeHeight: number,
  ): Promise<boolean> {
    LeptonDebug.log(
      `wallet:scanLeaves tree:${tree} chain:${chainID} leaves:${leaves.length}, scannedHeight:${scannedHeight}`,
    );
    const vpk = this.getViewingKeyPair().privateKey;

    const writeBatch: AbstractBatch[] = [];

    // Loop through passed commitments
    for (let position = scannedHeight; position < treeHeight; position += 1) {
      LeptonDebug.log(
        `Inserting ${leaves.length - scannedHeight} leaves. Current position ${position}/${
          leaves.length - 1
        }`,
      );
      let note: Note | undefined;
      const leaf = leaves[position];
      if (leaf == null) {
        continue;
      }

      if ('ciphertext' in leaf) {
        // Derive shared secret
        const ephemeralKey = leaf.ciphertext.ephemeralKeys[0];
        // eslint-disable-next-line no-await-in-loop
        const sharedKey = await getSharedSymmetricKey(vpk, hexStringToBytes(ephemeralKey));
        // Try to decrypt.
        if (sharedKey) {
          try {
            note = Note.decrypt(leaf.ciphertext.ciphertext, sharedKey);
          } catch (e: any) {
            // Expect error if leaf not addressed to us.
          }
        }
      } else {
        // preImage
        // Deserialize
        const serialized: NoteSerialized = {
          npk: leaf.preImage.npk,
          encryptedRandom: leaf.encryptedRandom,
          token: leaf.preImage.token.tokenAddress,
          value: leaf.preImage.value,
        };
        try {
          note = Note.deserialize(serialized, vpk, this.addressKeys);
        } catch (e: any) {
          // Expect error if leaf not addressed to us.
        }
      }

      // If this note is addressed to us, add to write queue
      if (note !== undefined) {
        const nullifier = Note.getNullifier(this.nullifyingKey, position);
        const storedCommitment = {
          spendtxid: false,
          txid: hexlify(leaf.txid),
          nullifier: nToHex(nullifier, ByteLength.UINT_256),
          decrypted: note.serialize(vpk),
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

    // Get chain namespace
    const namespace = this.getWalletDBPrefix(chainID);

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

    const keySplits = keys.map((key) => key.split(':')).filter((keySplit) => keySplit.length === 5);

    // Calculate UTXOs
    return Promise.all(
      keySplits.map(async (keySplit) => {
        // Decode UTXO
        // @todo clarify stored commitment / UTXO type
        const UTXO = msgpack.decode(arrayify(await this.db.get(keySplit)));

        // If this UTXO hasn't already been marked as spent, check if it has
        if (!UTXO.spendtxid) {
          // Get nullifier
          const storedNullifier = await this.merkletree[chainID].getStoredNullifier(UTXO.nullifier);

          // If it's nullified write spend txid to wallet storage
          if (storedNullifier) {
            UTXO.spendtxid = storedNullifier;

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
          txid: UTXO.txid,
          spendtxid: UTXO.spendtxid,
          note,
        };
      }),
    );
  }
    /**
   * Gets transactions history
   * @param chainID - chainID to get balances for
   * @returns history
   */

  async transactionsLog(chainID: number): Promise<TransactionsLog> {
    const TXOs = await this.TXOs(chainID);
    const tmpHistory: TransactionsLog = {};

    // loop through each TXO and add it to the history
    TXOs.forEach((txOutput) => {
      const token = formatToByteLength(txOutput.note.token, 32, false);
      // If we don't have an entry for this token yet, create one
      if (!tmpHistory[token]) {
        tmpHistory[token] = []
      }
      // first add entry for the token when it was received
      tmpHistory[token].push({
        txid: txOutput.txid,
        amount: txOutput.note.value,
        direction: TransferDirection.Incoming
      })
      // then add another entry if it was spent
      if(txOutput.spendtxid) {
        tmpHistory[token].push({
          txid: txOutput.spendtxid,
          amount: txOutput.note.value,
          direction: TransferDirection.Outgoing
        })
      }
    });  

    // process history by handling joinsplit of TXOs within transactions
    const history: TransactionsLog = {};
    const tokens = Object.keys(tmpHistory);
    tokens.forEach(token => {
      if(!history[token]) {
        history[token] = []
      }
      // group entries by txid 
      const entries = tmpHistory[token];
      const transactions = Wallet.groupBy(entries);
      // eslint-disable-next-line no-restricted-syntax
      for(const [key, value] of transactions) {
        let spent = 0n;
        let received = 0n;
        const txid = key;
        // sum amounts according to the direction
        value.forEach(logEntry => {
          if(logEntry.direction === TransferDirection.Outgoing)
          spent += logEntry.amount;
          else
          received += logEntry.amount;
        })
        // receive only
        if(spent === 0n) {
          history[token].push({
            txid,
            amount: received,
            direction: TransferDirection.Incoming
          });
        }
        // spend only
        else if(received === 0n) {
          history[token].push({
            txid,
            amount: spent,
            direction: TransferDirection.Outgoing
        });
        }
        else {
        // spend and receive
      history[token].push({
        txid,
        amount: spent - received,
        direction: TransferDirection.Outgoing
      });
      }
    }
  });
  return history;
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
        // Store utxo
        balances[token].utxos.push(txOutput);

        // Increment balance
        balances[token].balance += txOutput.note.value;
      }
    });

    return balances;
  }

  async getBalance(chainID: number, tokenAddress: string): Promise<bigint | undefined> {
    const balances = await this.balances(chainID);
    const balanceForToken = balances[formatToByteLength(tokenAddress, 32, false)];
    return balanceForToken ? balanceForToken.balance : undefined;
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

      // Loop through each UTXO and sort by tree
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
  async scanBalances(chainID: number) {
    LeptonDebug.log(`scan wallet balances: chainID ${chainID}`);

    try {
      // Fetch wallet details and latest tree.
      const [walletDetails, latestTree] = await Promise.all([
        this.getWalletDetails(chainID),
        this.merkletree[chainID].latestTree(),
      ]);

      // Fill list of tree heights with 0s up to # of trees
      while (walletDetails.treeScannedHeights.length <= latestTree) {
        walletDetails.treeScannedHeights.push(0);
      }

      // Loop through each tree and scan
      for (let tree = 0; tree <= latestTree; tree += 1) {
        // Get scanned height
        const scannedHeight = walletDetails.treeScannedHeights[tree];

        // Create sparse array of tree
        // eslint-disable-next-line no-await-in-loop
        const treeHeight = await this.merkletree[chainID].getTreeLength(tree);
        const fetcher: Promise<Commitment | undefined>[] = new Array(treeHeight);

        // Fetch each leaf we need to scan
        for (let index = scannedHeight; index < treeHeight; index += 1) {
          fetcher[index] = this.merkletree[chainID].getCommitment(tree, index);
        }

        // Wait until all leaves are fetched
        // eslint-disable-next-line no-await-in-loop
        const leaves = await Promise.all(fetcher);

        // Start scanning primary and change
        // eslint-disable-next-line no-await-in-loop
        await this.scanLeaves(leaves, tree, chainID, scannedHeight, treeHeight);

        // Commit new scanned height
        walletDetails.treeScannedHeights[tree] = leaves.length;
      }

      // Write wallet details to db
      await this.db.put(this.getWalletDetailsPath(chainID), msgpack.encode(walletDetails));

      // Emit scanned event for this chain
      LeptonDebug.log(`wallet: scanned ${chainID}`);
      this.emit(LeptonEvent.WalletScanComplete, { chainID } as ScannedEventData);
    } catch (err: any) {
      LeptonDebug.log(`wallet.scan error: ${err.message}`);
      LeptonDebug.error(err);
    }
  }

  /**
   * Clears balances scanned from merkletrees and stored to database.
   * @param chainID - chainID to clear
   */
  async clearScannedBalances(chainID: number) {
    const namespace = this.getWalletDetailsPath(chainID);
    await this.db.clearNamespace(namespace);
  }

  /**
   * Clears stored balances and re-scans fully.
   * @param chainID - chainID to rescan
   */
  async fullRescanBalances(chainID: number) {
    await this.clearScannedBalances(chainID);
    return this.scanBalances(chainID);
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

  /**
   * Loads encrypted wallet data from database.
   * @param db - database
   * @param encryptionKey - encryption key to use with database
   * @param id - wallet id
   * @returns Data (JSON any)
   */
  static async getEncryptedData(db: Database, encryptionKey: BytesData, id: string) {
    return msgpack.decode(
      arrayify(await db.getEncrypted([fromUTF8String('wallet'), id], encryptionKey)),
    );
  }
}

export {
  Wallet,
  WalletDetails,
  AddressKeys,
  Balances,
  BalancesByTree,
  ScannedEventData,
  TXO,
  WalletData,
  TreeBalance,
  WalletNodes,
};
