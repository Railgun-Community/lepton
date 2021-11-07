import BN from 'bn.js';
import msgpack from 'msgpack-lite';
import utils from '../utils';
import Database from '../database';
import keyderivation from '../keyderivation';
import bip39 from '../keyderivation/bip39';
import { BytesData } from '../utils/bytes';
import Note from '../note';
import type BIP32Node from '../keyderivation';
import type MerkleTree from '../merkletree';
import type { Commitment } from '../merkletree';

export type WalletDetails = {
  treeScannedHeights: number[],
  primaryHeight: number,
  changeHeight: number,
};

class Wallet {
  db: Database;

  id: string;

  #encryptionKey: BytesData;

  #addressNode: BIP32Node;

  #changeNode: BIP32Node;

  // Lock scanning operations to prevent race conditions
  private scanLock = false;

  /**
   * Create Wallet controller
   * @param db - database
   * @param merkletree - merkle tree to use
   * @param id - wallet ID
   * @param encryptionKey - database encryption key
   */
  constructor(
    db: Database,
    encryptionKey: BytesData,
    mnemonic: string,
    derivationPath: string,
  ) {
    this.db = db;
    this.#encryptionKey = encryptionKey;

    // Calculate ID
    this.id = utils.hash.sha256(utils.bytes.combine([
      bip39.mnemonicToSeed(mnemonic),
      utils.bytes.fromUTF8String(derivationPath),
    ]));

    this.#addressNode = keyderivation.fromMnemonic(mnemonic).derive(`${derivationPath}/0'`);
    this.#changeNode = keyderivation.fromMnemonic(mnemonic).derive(`${derivationPath}/1'`);

    // Write encrypted mnemonic to DB
    this.db.putEncrypted([
      utils.bytes.fromUTF8String('wallet'),
      this.id,
    ], encryptionKey, msgpack.encode({
      mnemonic,
      derivationPath,
    }));
  }

  /**
   * Construct DB path from chainID
   * @param chainID - chainID
   * @returns wallet DB prefix
   */
  getWalletDBPrefix(chainID: number): string[] {
    return [
      utils.bytes.fromUTF8String('wallet'),
      utils.bytes.hexlify(this.id),
      utils.bytes.hexlify(new BN(chainID)),
    ].map((element) => element.padStart(64, '0'));
  }

  /**
   * Get keypair at index
   * @param index - index to get keypair at
   * @param change - get change keypair
   * @param chainID - chainID for keypair
   * @returns keypair
   */
  #getKeypair(
    index: number,
    change: boolean,
    chainID: number | undefined = undefined,
  ) {
    if (change) {
      return this.#changeNode.derive(`m/${index}'`).getBabyJubJubKey(chainID);
    }
    return this.#addressNode.derive(`m/${index}'`).getBabyJubJubKey(chainID);
  }

  /**
   * Get Address at index
   * @param index - index to get address at
   * @param change - get change address
   * @param chainID - chainID for address
   * @returns addresses
   */
  getAddress(
    index: number,
    change: boolean,
    chainID: number | undefined = undefined,
  ): string {
    return this.#getKeypair(index, change, chainID).address;
  }

  /**
   * Gets wallet details for this wallet
   */
  async getWalletDetails(chainID: number): Promise<WalletDetails> {
    let walletDetails: WalletDetails;

    try {
      // Try fetching from database
      walletDetails = msgpack.decode(
        utils.bytes.arrayify(
          await this.db.getEncrypted(
            this.getWalletDBPrefix(chainID),
            this.#encryptionKey,
          ),
        ),
      );
    } catch {
      // If details don't exist yet, return defaults
      walletDetails = {
        treeScannedHeights: [],
        primaryHeight: 0,
        changeHeight: 0,
      };
    }

    return walletDetails;
  }

  /**
   * Scans wallet at index for new balances
   * @param index - index of address to scan
   * @param change - whether we're scanning the change address
   * @param commitments - commitments to scan
   */
  async scanIndex(index: number, change: boolean, commitments: Commitment[]): Promise<boolean[]> {
    // Derive keypair
    const key = this.#getKeypair(index, change);

    // Loop through passed commitments
    return commitments.map((commitment) => {
      // Derive shared secret
      const sharedKey = utils.babyjubjub.ecdh(
        key.privateKey,
        commitment.senderPublicKey,
      );

      // Attempt to decrypt
      const note = Note.ERC20.decrypt(commitment.ciphertext, sharedKey);

      // Return if this note is addressed to us
      return note.publicKey === key.publicKey;
    });
  }

  /**
   * Scans for new balances
   * @param merkletree - merkletree to scan
   */
  async scan(merkletree: MerkleTree) {
    // Don't proceed if scan write is locked
    if (this.scanLock) return;

    // Lock
    this.scanLock = true;

    // Fetch wallet details
    let walletDetails = await this.getWalletDetails(merkletree.chainID);

    // Refresh list of trees
    // eslint-disable-next-line no-await-in-loop
    while (await merkletree.getTreeLength(walletDetails.treeScannedHeights.length) !== 0) {
      // Instantiate new trees in wallet data until we encounter a tree with tree length 0
      walletDetails.treeScannedHeights[walletDetails.treeScannedHeights.length] = 0;
    }

    // Loop through each tree
    walletDetails.treeScannedHeights = await Promise.all(
      walletDetails.treeScannedHeights.map(async (scannedHeight, tree) => {
      // For each tree fetch every leaf we haven't scanned yet
        const leaves = await Promise.all(
          new Array(await merkletree.getTreeLength(tree) - scannedHeight).map(
            (value, index) => merkletree.getCommitment(tree, index),
          ),
        );

        walletDetails = await this.findWalletHighestIndex(walletDetails, leaves);

        // Calculate new scanned height, don't call getTreeLength again incase new leaves were
        // committed while we were scanning
        return scannedHeight + leaves.length;
      }),
    );

    // Write wallet details to db
    await this.db.putEncrypted(
      this.getWalletDBPrefix(merkletree.chainID),
      this.#encryptionKey,
      msgpack.encode(walletDetails),
    );

    // Release lock
    this.scanLock = false;
  }

  /**
   * Find the highest index of the wallet
   * @param walletDetails - Wallet details of the user
   * @param commitments - User's commitments
   */
  async findWalletHighestIndex(
    walletDetails: WalletDetails,
    commitments: Commitment[],
  ): Promise<WalletDetails> {
    const updatedWalletDetails = { ...walletDetails };

    for (let index = 0; index < updatedWalletDetails.primaryHeight + 20; index += 1) {
      // eslint-disable-next-line no-await-in-loop
      const commitmentsInIndices = await Promise.all([true, false].map(
        (changeValue) => this.scanIndex(index, changeValue, commitments),
      ));
      const hasAsset = commitmentsInIndices.flat().includes(true);
      if (hasAsset && index > walletDetails.primaryHeight) {
        updatedWalletDetails.primaryHeight = index;
      }
    }

    return updatedWalletDetails;
  }

  /**
   * Create a wallet from mnemonic
   * @param db - database
   * @param encryptionKey - encryption key to use with database
   * @param mnemonic - mnemonic to load wallet from
   * @param derivationPath - wallet derivation path
   * @returns Wallet
   */
  static async fromMnemonic(
    db: Database,
    encryptionKey: BytesData,
    mnemonic: string,
    derivationPath: string = "m/1984'/0'/0'",
  ): Promise<Wallet> {
    // Calculate ID
    const id = utils.hash.sha256(utils.bytes.combine([
      bip39.mnemonicToSeed(mnemonic),
      utils.bytes.fromUTF8String(derivationPath),
    ]));

    // Write encrypted mnemonic to DB
    db.putEncrypted([
      utils.bytes.fromUTF8String('wallet'),
      msgpack.encode({
        id,
        derivationPath,
      }),
    ], encryptionKey, mnemonic);

    // Create wallet object and return
    return new Wallet(db, encryptionKey, mnemonic, derivationPath);
  }

  /**
   * Loads wallet data from database and creates wallet object
   * @param db - database
   * @param encryptionKey - encryption key to use with database
   * @param id - wallet id
   * @returns Wallet
   */
  static async loadExisting(
    db: Database,
    encryptionKey: BytesData,
    id: BytesData,
  ): Promise<Wallet> {
    // Get encrypted mnemonic and derivation path from DB
    const { mnemonic, derivationPath } = msgpack.decode(
      utils.bytes.arrayify(
        await db.getEncrypted([
          utils.bytes.fromUTF8String('wallet'),
          id,
        ], encryptionKey),
      ),
    );

    // Create wallet object and return
    return new Wallet(db, encryptionKey, mnemonic, derivationPath);
  }
}

export default Wallet;
