import { TXO } from '../models/txo-types';

export type WalletDetails = {
  treeScannedHeights: number[];
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

export type AddressKeys = {
  masterPublicKey: bigint;
  viewingPublicKey: Uint8Array;
};

export type WalletData = { mnemonic: string; index: number };

export enum TransferDirection {
  Incoming = 'Incoming',
  Outgoing = 'Outgoing'
}
export type TransactionLogEntry = {
  txid: string;
  amount: bigint;
  direction: TransferDirection
}

export type TransactionsLog = {
  [key: string]: TransactionLogEntry[];
}
