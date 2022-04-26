import { CommitmentPreimage, EncryptedRandom } from '../models/transaction-types';
import { encryption } from '../utils';
import { ByteLength, formatEncryptedRandom, hexToBigInt, nToHex } from '../utils/bytes';
import { getCircomlibJS } from '../utils/circomlibjs-loader';
import { ZERO_ADDRESS } from '../utils/constants';

export class Deposit {
  constructor(
    public masterPublicKey: bigint,
    public random: string,
    public value: bigint,
    public token: string,
  ) {}

  get tokenData() {
    return {
      tokenAddress: this.token,
      tokenSubID: ZERO_ADDRESS,
      tokenType: ZERO_ADDRESS,
    };
  }

  get notePublicKey(): bigint {
    return getCircomlibJS().poseidon([this.masterPublicKey, hexToBigInt(this.random)]);
  }

  /**
   * Get note hash
   */
  get hash(): bigint {
    return getCircomlibJS().poseidon([this.notePublicKey, hexToBigInt(this.token), this.value]);
  }

  /**
   * Gets JSON serialized version of note
   * @param viewingPrivateKey - viewing private key for decryption
   * @param forContract - if we should 0x prefix the hex strings to make them ethers compatible
   * @returns serialized note
   */
  serialize(viewingPrivateKey: Uint8Array): {
    preImage: Partial<CommitmentPreimage>;
    encryptedRandom: EncryptedRandom;
  } {
    const ciphertext = encryption.aes.gcm.encrypt([this.random], viewingPrivateKey);
    return {
      preImage: {
        npk: nToHex(this.notePublicKey, ByteLength.UINT_256, true),
        token: this.tokenData,
        value: this.value,
      },
      encryptedRandom: formatEncryptedRandom(ciphertext),
    };
  }
}
