/* eslint-disable no-bitwise */
import BN from 'bn.js';
import type { AbstractBatch } from 'abstract-leveldown';
import utils from '../utils';
import type Database from '../database';
import { BytesData } from '../utils/bytes';

// Declare depth
const depths = {
  erc20: 16,
  erc721: 8,
} as const;

// Declare purposes
export type TreePurpose = keyof typeof depths;

// Calculate tree zero value
const MERKLE_ZERO_VALUE: string = utils.bytes.hexlify(
  utils.bytes.numberify(
    utils.hash.keccak256(
      utils.bytes.fromUTF8String('Railgun'),
    ),
  ).mod(utils.constants.SNARK_PRIME),
);

class MerkleTree {
  private db: Database;

  readonly chainID: number;

  readonly purpose: TreePurpose;

  readonly depth: number;

  readonly zeroValues: string[] = [];

  private treeLengthCache: number[] = [];

  // tree[level[index]]
  private writeCache: string[][][] = [];

  // tree[startingIndex[leaves]]
  private writeQueue: BytesData[][][] = [];

  // Tree write queue lock to prevent race conditions
  private queueLock = false;

  /**
   * Create MerkleTree controller from database
   * @param db - database object to use
   * @param chainID - Chain ID to use
   * @param purpose - purpose of merkle tree
   * @param depth - merkle tree depth
   */
  constructor(
    db: Database,
    chainID: number,
    purpose: TreePurpose,
    depth: number = depths[purpose],
  ) {
    // Set passed values
    this.db = db;
    this.chainID = chainID;
    this.purpose = purpose;
    this.depth = depth;

    // Calculate zero values
    this.zeroValues[0] = MERKLE_ZERO_VALUE;
    for (let level = 1; level <= this.depth; level += 1) {
      this.zeroValues[level] = MerkleTree.hashLeftRight(
        this.zeroValues[level - 1],
        this.zeroValues[level - 1],
      );
    }
  }

  /**
   * Hash 2 elements together
   * @param left - left element
   * @param right - right element
   * @returns hash
   */
  static hashLeftRight(left: BytesData, right: BytesData): string {
    return utils.hash.poseidon([left, right]);
  }

  /**
   * Clears write cache of merkle tree
   * @param tree - tree number to clear
   */
  clearWriteCache(tree: number) {
    this.writeCache[tree] = [];
  }

  /**
   * Construct DB prefix from tree number, level
   * @param tree - tree number
   * @param level - merkle tree level
   */
  getTreeDBPrefix(tree: number): string[] {
    return [
      utils.bytes.hexlify(new BN(this.chainID)),
      utils.bytes.fromUTF8String(`merkletree-${this.purpose}`),
      utils.bytes.hexlify(new BN(tree)),
    ].map((element) => element.padStart(64, '0'));
  }

  /**
   * Construct DB path from tree number, level, and index
   * @param tree - tree number
   * @param level - merkle tree level
   * @param index - leaf/node index
   */
  getNodeDBPath(tree: number, level: number, index: number): string[] {
    return [
      ...this.getTreeDBPrefix(tree),
      utils.bytes.hexlify(new BN(level)),
      utils.bytes.hexlify(new BN(index)),
    ].map((element) => element.padStart(64, '0'));
  }

  /**
   * Gets node from tree
   * @param tree - tree to get node from
   * @param level - tree level
   * @param index - index of node
   * @returns node
   */
  async getNode(tree: number, level: number, index: number) {
    try {
      return await this.db.get(this.getNodeDBPath(
        tree,
        level,
        index,
      ));
    } catch {
      return this.zeroValues[level];
    }
  }

  /**
   * Gets length of tree
   * @param tree - tree to get length of
   */
  async getTreeLength(tree: number) {
    this.treeLengthCache[tree] = this.treeLengthCache[tree]
      || await this.db.countNamespace(this.getTreeDBPrefix(tree));

    return this.treeLengthCache[tree];
  }

  /**
   * Gets node from tree
   * @param tree - tree to get root of
   * @returns tree root
   */
  getRoot(tree: number) {
    return this.getNode(tree, this.depth, 0);
  }

  /**
   * Write tree cache to DB
   * @param tree - tree to write
   */
  async writeTreeCache(tree: number) {
    // Build write cache
    const writeBatch: AbstractBatch[] = [];

    // Get new leaves
    const newTreeLength = this.writeCache[tree][0].length;

    // Loop through each level
    this.writeCache[tree].forEach((levelElement, level) => {
      // Loop through each index
      levelElement.forEach((node, index) => {
        // Push to writeBatch array
        writeBatch.push({ type: 'put', key: this.getNodeDBPath(tree, level, index).join(':'), value: node });
      });
    });

    // Batch write to DB
    await this.db.batch(writeBatch);

    // Update tree length
    this.treeLengthCache[tree] = newTreeLength;

    // Clear write cache
    this.clearWriteCache(tree);
  }

  /**
   * Inserts array of leaves into tree
   * @param tree - Tree to insert leaves into
   * @param leaves - Leaves to insert
   * @param startIndex - Starting index of leaves to insert
   */
  async insertLeaves(tree: number, leaves: BytesData[], startIndex: number) {
    // Convert leaves to hex string
    const writeArray = leaves.map(utils.bytes.hexlify);

    // Start insertion at startIndex
    let index = startIndex;

    // Calculate ending index
    let endIndex = startIndex + writeArray.length;

    // Start at level 0
    let level = 0;

    // Store next level index for when we begin updating the next level up
    let nextLevelStartIndex = startIndex;

    // Push values to leaves of write index
    writeArray.forEach((leaf) => {
      // Ensure writecache array exists
      this.writeCache[tree] = this.writeCache[tree] || [];
      this.writeCache[tree][level] = this.writeCache[tree][level] || [];

      // Set writecache value
      this.writeCache[tree][level][index] = leaf;

      // Increment index
      index += 1;
    });

    // Loop through each level and calculate values
    while (level < this.depth) {
      // Set starting index for this level
      index = nextLevelStartIndex;

      // Ensure writecache array exists for next level
      this.writeCache[tree][level + 1] = this.writeCache[tree][level + 1] || [];

      // Loop through every pair
      for (index; index <= endIndex; index += 2) {
        if (index % 2 === 0) {
          // Left
          this.writeCache[tree][level + 1][index >> 1] = MerkleTree.hashLeftRight(
            // eslint-disable-next-line no-await-in-loop
            this.writeCache[tree][level][index] || await this.getNode(tree, level, index),
            // eslint-disable-next-line no-await-in-loop
            this.writeCache[tree][level][index + 1] || await this.getNode(tree, level, index + 1),
          );
        } else {
          // Right
          this.writeCache[tree][level + 1][index >> 1] = MerkleTree.hashLeftRight(
            // eslint-disable-next-line no-await-in-loop
            this.writeCache[tree][level][index - 1] || await this.getNode(tree, level, index - 1),
            // eslint-disable-next-line no-await-in-loop
            this.writeCache[tree][level][index],
          );
        }
      }

      // Calculate starting and ending index for the next level
      nextLevelStartIndex >>= 1;
      endIndex >>= 1;

      // Increment level
      level += 1;
    }

    // Commit to DB
    await this.writeTreeCache(tree);
  }

  async updateTrees() {
    // Don't proceed if queue write is locked
    if (this.queueLock) return;

    // Write lock queue
    this.queueLock = true;

    // Loop until there isn't work to do
    let workToDo = true;

    while (workToDo) {
      const treeLengthPromises: Promise<number>[] = [];

      // Loop through each tree present in write queue and get tree length
      this.writeQueue.forEach((tree, index) => {
        treeLengthPromises[index] = this.getTreeLength(index);
      });

      // eslint-disable-next-line no-await-in-loop
      const treeLengths = await Promise.all(treeLengthPromises);

      const updatePromises: (Promise<void> | never)[] = [];

      // Loop through each tree and check if there are updates to be made
      this.writeQueue.forEach((tree, treeIndex) => {
        // Delete all queue entries less than tree length
        tree.forEach((element, elementIndex) => {
          if (elementIndex < treeLengths[treeIndex]) {
            delete this.writeQueue[treeIndex][elementIndex];
          }
        });

        // If there aren't any elements in the write queue delete it
        if (tree.reduce((x) => x + 1, 0) === 0) delete this.writeQueue[treeIndex];

        // If there is an element in the write queue equal to the tree length, process it
        if (this.writeQueue[treeIndex]?.[treeLengths[treeIndex]]) {
          updatePromises.push(this.insertLeaves(
            treeIndex,
            this.writeQueue[treeIndex][treeLengths[treeIndex]],
            treeLengths[treeIndex],
          ));
        }
      });

      // Wait for updates to complete
      // eslint-disable-next-line no-await-in-loop
      await Promise.all(updatePromises);

      // If no work was done exit
      if (updatePromises.length === 0) workToDo = false;
    }

    // Release queue lock
    this.queueLock = false;
  }

  /**
   * Adds leaves to queue to be added to tree
   * @param tree - tree number to add to
   * @param leaves - leaves to add
   * @param startingIndex - index of first leaf
   */
  async queueLeaves(tree: number, leaves: BytesData[], startingIndex: number) {
    // Ensure write queue for tree exists
    this.writeQueue[tree] = this.writeQueue[tree] || [];

    // Create set leaves as queue
    this.writeQueue[tree][startingIndex] = leaves;

    // Process tree updates
    await this.updateTrees();
  }
}

export default MerkleTree;