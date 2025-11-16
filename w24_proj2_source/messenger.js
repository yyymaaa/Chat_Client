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

     this.EGKeyPair = await generateEG()
    this.username = username
    const certificate = {
      username: username,
      publicKey: this.EGKeyPair.pub
    }
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
    const headerKey = header.dhPublicKey


    // 1. Connection/Ratchet State Check 
    let chain
    let isOldChain = false


    if (!conn) {
      // 1a. Initialize Connection (if first message received)
      conn = this.conns[name] = {}
      const dhSecret = await computeDH(this.EGKeyPair.sec, headerKey)
      const [RK, CKr] = await HKDF(dhSecret, dhSecret, 'DoubleRatchet')
      conn.RK = RK
      conn.Ns = 0
      conn.PNs = 0
     
      // Set current chain
      conn.currentDHr = headerKey
      conn.currentCKr = CKr
      conn.currentNr = 0
      conn.currentSkipped = new Map()
      conn.oldChains = new Map()


      // Perform DH ratchet for *sending*
      conn.DHs = await generateEG()
      const dhSecretNext = await computeDH(conn.DHs.sec, conn.currentDHr)
      const [RK_next, CKs] = await HKDF(conn.RK, dhSecretNext, 'DoubleRatchet')
      conn.RK = RK_next
      conn.CKs = CKs
     
      chain = { CKr: conn.currentCKr, Nr: conn.currentNr, skipped: conn.currentSkipped }
    } else if (headerKey === conn.currentDHr) {
      // 1b. Message for Current Chain 
      chain = { CKr: conn.currentCKr, Nr: conn.currentNr, skipped: conn.currentSkipped }
    } else if (conn.oldChains.has(headerKey)) {
      // 1c. Message for Old, Saved Chain 
      chain = conn.oldChains.get(headerKey)
      isOldChain = true
    } else {
      // 1d. New Key: Perform DH Ratchet
     
      // Save the current chain before overwriting
      conn.oldChains.set(conn.currentDHr, { CKr: conn.currentCKr, Nr: conn.currentNr, skipped: conn.currentSkipped })


      // Perform DH ratchet (receiving)
      conn.PNs = conn.Ns
      conn.Ns = 0
      const dhSecret = await computeDH(conn.DHs.sec, headerKey)
      const [RK, CKr] = await HKDF(conn.RK, dhSecret, 'DoubleRatchet')
      conn.RK = RK
     
      // Update current chain
      conn.currentDHr = headerKey
      conn.currentCKr = CKr
      conn.currentNr = 0
      conn.currentSkipped = new Map()


      // Perform DH ratchet (sending)
      conn.DHs = await generateEG()
      const dhSecretNext = await computeDH(conn.DHs.sec, conn.currentDHr)
      const [RK_next, CKs] = await HKDF(conn.RK, dhSecretNext, 'DoubleRatchet')
      conn.RK = RK_next
      conn.CKs = CKs


      chain = { CKr: conn.currentCKr, Nr: conn.currentNr, skipped: conn.currentSkipped }
    }


    // 2. Find/Derive Message Key
    const messageKey = await this.findMessageKey(chain, header.Ns) 


    // 3. Update Main State (if not old chain) 
    // If it's the current chain, we need to update the connection's
    // state from the temporary 'chain' object.
    // If it's an old chain, the 'chain' object *is* the state
    // (it's a reference from the map), so changes persist automatically.
    if (!isOldChain) {
      conn.currentCKr = chain.CKr
      conn.currentNr = chain.Nr
    }


    // 4. Decrypt Message 
    try {
      const plaintextBuffer = await decryptWithGCM(
        messageKey,
        ciphertext,
        header.receiverIV,
        JSON.stringify(header)
      )
      return bufferToString(plaintextBuffer)
    } catch (error) {
      console.error('Decryption failed!', error)
      throw new Error('Decryption failed: Possible tampering or key mismatch')
    }

    return plaintext
  }
};

module.exports = {
  MessengerClient
}
