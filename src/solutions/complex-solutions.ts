import { SpendingSolutionGroup, TXO } from '../models/txo-types';
import { Note } from '../note';
import { minBigInt } from '../utils/bigint';
import { TreeBalance } from '../wallet/types';
import { VALID_NULLIFIER_COUNTS, isValidNullifierCount } from './nullifiers';
import { calculateTotalSpend, sortUTXOsBySize } from './utxos';

export const createSpendingSolutionGroupsForOutput = (
  treeSortedBalances: TreeBalance[],
  output: Note,
  remainingOutputs: Note[],
  excludedUTXOIDs: string[],
): SpendingSolutionGroup[] => {
  const requiredOutputValue = output.value;
  let amountLeft = output.value;

  const spendingSolutionGroups: SpendingSolutionGroup[] = [];

  treeSortedBalances.forEach((treeBalance, tree) => {
    while (amountLeft > 0) {
      const utxos = findNextSolutionBatch(treeBalance, amountLeft, excludedUTXOIDs);
      if (!utxos) {
        // No more solutions in this tree.
        break;
      }

      // Don't allow these UTXOs to be used twice.
      excludedUTXOIDs.push(...utxos.map((utxo) => utxo.txid));

      // Decrement amount left by total spend in UTXOs.
      const totalSpend = calculateTotalSpend(utxos);
      amountLeft -= totalSpend;

      // Solution Value is the smaller of Solution spend value, or required output value.
      const solutionValue = minBigInt(totalSpend, requiredOutputValue);

      // Generate new output note and spending solution group, which will
      // be used to create a Transaction.
      const solutionOutput = output.newNoteWithValue(solutionValue);
      spendingSolutionGroups.push({
        spendingTree: tree,
        utxos,
        outputs: [solutionOutput],
        withdrawValue: BigInt(0),
      });

      // Remove this "used" output note.
      remainingOutputs.splice(0, 1);

      const needsMoreUTXOs = amountLeft > 0;
      if (needsMoreUTXOs) {
        // Add another remaining output note for any Amount Left.
        remainingOutputs.unshift(output.newNoteWithValue(amountLeft));
      }

      if (!needsMoreUTXOs) {
        // Break out from the forEach loop, and continue with next output.
        return;
      }
    }
  });

  if (amountLeft > 0) {
    // Could not find enough solutions.
    throw consolidateBalanceError();
  }

  return spendingSolutionGroups;
};

/**
 * Wallet has appropriate balance in aggregate, but no solutions remain.
 * This means these UTXOs were already excluded, which can only occur in multi-send situations with multiple destination addresses.
 * eg. Out of a 225 balance (200 and 25), sending 75 each to 3 people becomes difficult, because of the constraints on the number of outputs.
 */
export const consolidateBalanceError = (): Error => {
  throw new Error(
    'Please consolidate balances before multi-sending. Send tokens to one destination address at a time to resolve.',
  );
};

/**
 * Finds next valid nullifier count above the current nullifier count.
 */
const nextNullifierTarget = (utxoCount: number): number | undefined =>
  VALID_NULLIFIER_COUNTS.find((n) => n > utxoCount);

const shouldAddMoreUTXOsForSolutionBatch = (
  spendingUTXOs: TXO[],
  allUTXOs: TXO[],
  totalRequired: bigint,
) => {
  const nullifierCount = spendingUTXOs.length;
  const totalSpend = calculateTotalSpend(spendingUTXOs);

  if (totalSpend >= totalRequired) {
    // We've hit the target required.
    // Keep adding nullifiers until the count is valid.
    return !isValidNullifierCount(nullifierCount);
  }

  const nullifierTarget = nextNullifierTarget(nullifierCount);

  if (!nullifierTarget) {
    // No next nullifiers.
    // Keep adding nullifiers until the count is valid.
    return !isValidNullifierCount(nullifierCount);
  }

  const totalNullifierCount = allUTXOs.length;
  if (nextNullifierTarget(nullifierCount) > totalNullifierCount) {
    // Not reachable.
    // Keep adding nullifiers until the count is valid.
    return !isValidNullifierCount(nullifierCount);
  }

  // Total spend < total required, and next nullifier target is reachable.
  // Continue adding nullifiers.
  return true;
};

export function findNextSolutionBatch(
  treeBalance: TreeBalance,
  totalRequired: bigint,
  excludedUTXOIDs: string[],
): TXO[] | undefined {
  const filteredUTXOs = treeBalance.utxos.filter((utxo) => !excludedUTXOIDs.includes(utxo.txid));

  if (!filteredUTXOs.length) {
    // No more solutions in this tree.
    return undefined;
  }

  // Sort UTXOs by size
  sortUTXOsBySize(filteredUTXOs);

  // Accumulate UTXOs until we hit the target value
  const utxos: TXO[] = [];

  // Check if sum of UTXOs selected is greater than target
  while (shouldAddMoreUTXOsForSolutionBatch(utxos, filteredUTXOs, totalRequired)) {
    utxos.push(filteredUTXOs[utxos.length]);
  }

  if (!isValidNullifierCount(utxos.length)) {
    throw new Error('Invalid nullifier count');
  }

  return utxos;
}
