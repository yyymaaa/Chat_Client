'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    throw ('not implemented!')
    const certificate = {}
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    throw ('not implemented!')
  }

    async deriveMessageKey(chainKey) {
                const messageKey = await HMACtoAESKey(chainKey, 'message');
                const nextChainKey = await HMACtoHMACKey(chainKey, 'chain');
                return { messageKey, nextChainKey };
            }


  async sendMessage (name, plaintext) {
    throw ('not implemented!')
    const header = {}
    const ciphertext = ''
    return [header, ciphertext]
  }

 async findMessageKey(chain, Ns) {
                if (chain.skipped.has(Ns)) {
                    const messageKey = chain.skipped.get(Ns);
                    chain.skipped.delete(Ns);
                    return messageKey;
                }
                if (Ns < chain.Nr) {
                    throw new Error(`Message replay or too old. Got Ns: ${Ns}, but expected Nr >= ${chain.Nr}`);
                }

                let messageKey;
                let currentCKr = chain.CKr;
                let currentNr = chain.Nr;

                if (Ns === currentNr) {
                    const { messageKey: derivedKey, nextChainKey } = await this.deriveMessageKey(currentCKr);
                    messageKey = derivedKey;
                    chain.CKr = nextChainKey;
                    chain.Nr++;
                    return messageKey;
                }

                while (currentNr < Ns) {
                    const { messageKey: skippedKey, nextChainKey } = await this.deriveMessageKey(currentCKr);
                    chain.skipped.set(currentNr, skippedKey);
                    currentCKr = nextChainKey;
                    currentNr++;
                }

                const { messageKey: derivedKey, nextChainKey } = await this.deriveMessageKey(currentCKr);
                messageKey = derivedKey;
                chain.CKr = nextChainKey;
                chain.Nr = currentNr + 1;
                return messageKey;
            }

            
  async receiveMessage (name, [header, ciphertext]) {
    throw ('not implemented!')
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
