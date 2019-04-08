const EventEmitter = require('events').EventEmitter
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const log = require('loglevel')
const type = 'External Account'
const Transaction = require('ethereumjs-tx')

class ExternalAccountKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor (opts) {
    super()
    this.type = type
    this.accounts = []
    this.deserialize(opts)
    this.getState = () => { throw new Error('ExternalAccountKeyring was improperly initialized. Please run setExtCallback() before signing!') }
    this.updateState = () => { throw new Error('ExternalAccountKeyring was improperly initialized. Please run setExtCallback() before signing!') }
  }

  setExtCallback (getExternalState, setExternalState) {
    this.getState = getExternalState
    this.updateState = setExternalState
  }

  serialize () {
    return Promise.resolve(this.accounts.slice())
  }

  deserialize (accounts = []) {
    return new Promise((resolve, reject) => {
      try {
        this.accounts = accounts.slice()
      } catch (e) {
        reject(e)
      }
      resolve()
    })
  }

  addAccounts (n = 1) {
    throw new Error('Not supported')
  }

  getAccounts () {
    return Promise.resolve(this.accounts.slice())
  }

  // tx is an instance of the ethereumjs-tx class.
  signTransaction (address, tx) {
    var intervalCounter = 0
    log.info('ExternalAccountKeyring - signTransaction - address:' + address)
    if (!(tx instanceof Transaction)) return Promise.reject(new Error('Invalid transaction'))
    if (!ethUtil.isValidAddress(address)) return Promise.reject(new Error('Invalid address: ' + address))

    var extToSign = this.getState().extToSign
    const serialized = this._serializeUnsigned(tx, address)
    const id = ethUtil.sha3(JSON.stringify(serialized) + Date.now().toString()).toString('hex')
    extToSign.push({type: 'sign_transaction', payload: serialized, from: address, id})
    this.updateState({extToSign})
    //
    // check for user provided signature
    log.info('ExternalAccountKeyring - signTransaction: extToSign:' + JSON.stringify(extToSign))
    return new Promise((resolve, reject) => {
        var interval = setInterval(() => {
          const state = this.getState()
          var extSigned = state['extSigned']
          var extCancel = state['extCancel']
          var extKeepAlive = state['extKeepAlive']

          // if signing modal was closed
          if (intervalCounter > 25) {
            clearInterval(interval)
            reject(new Error('Cancel pressed'))
          }
          // signing modal sent keep alive
          if (extKeepAlive.find((eid) => eid === id)) {
            extKeepAlive = extKeepAlive.filter((eid) => eid !== id)
            this.updateState({extKeepAlive})
            intervalCounter = 0
          } else {
            intervalCounter++
          }

          var signedTx = extSigned.find((txn) => this._sameTx(txn, tx, id, address))
          var cancelTx = extCancel.find((txn) => this._sameTx(txn, tx, id, address))
          log.info('signedTx: ' + JSON.stringify(signedTx) + ' cancelTx: ' + JSON.stringify(cancelTx))
          if (cancelTx) {
            log.info('user canceled tx')
            clearInterval(interval)
            extCancel = extCancel.filter(txn => !this._sameTx(txn, tx, id, address))
            this.updateState({extCancel})
            // if we could have besides tx state of 'signed' and 'failed'
            // one called 'canceled', we could return in a more meaningful way
            reject(new Error('Cancel pressed'))
          }
          if (signedTx) {
            log.info('user signed Tx tx')
            clearInterval(interval)
            extSigned = extSigned.filter((txn) => !this._sameTx(txn, tx, id, address))
            this.updateState({extSigned})
            const {v, r, s} = this._signatureHexToVRS(signedTx.signature)
            tx.v = v
            tx.r = r
            tx.s = s
            if (tx.verifySignature()) {
              resolve(tx)
            } else {
              reject(new Error('Invalid signature provided'))
            }
          }
        }, 500)
    })
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage (withAccount, data) {
    return this._signMsg('sign_message', withAccount, data)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex) {
    return this._signMsg('sign_personal_message', withAccount, msgHex)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData) {
    return this._signMsg('sign_typed_data', withAccount, typedData)
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount (address) {
    throw new Error('Not supported')
  }

  removeAccount (address) {
    if (!this.accounts.map(acc => ethUtil.bufferToHex(acc).toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`)
    }
    this.accounts = this.accounts.filter(acc => acc.toLowerCase() !== address.toLowerCase())
  }

/**
 *  Determines with good enough probability that an
 *  externally signed transaction and a transaction are the same.
 *
 * @param {Object} extTx Externally signed transaction provided by ui.
 * @param {Object} tx Transaction object of type 'ethereumjs-tx'
 * @param {String} id tx id during external signature process
 * @param {String} address Sender address of tx
 * @return {Boolean} true if they match, and false otherwise
 */
  _sameTx (extTx, tx, id, address) {

    if (extTx.id) {
      return extTx.id === id
    } else {
      return extTx.payload.nonce === ethUtil.bufferToHex(tx.nonce) &&
      extTx.payload.to === ethUtil.bufferToHex(tx.to) &&
      extTx.payload.value === ethUtil.bufferToHex(tx.value) &&
      extTx.payload.data === ethUtil.bufferToHex(tx.data) &&
      extTx.from === address &&
      extTx.payload.gasPrice === ethUtil.bufferToHex(tx.gasPrice) &&
      extTx.payload.gasLimit === ethUtil.bufferToHex(tx.gasLimit) &&
      extTx.payload.chainId === tx.getChainId().toString() &&
      extTx.type === 'sign_transaction'
    }
  }
  // serializes an unsigned Transaction object
  _serializeUnsigned (tx, address) {
    return {
      from: address,
      nonce: ethUtil.bufferToHex(tx.nonce),
      gasPrice: ethUtil.bufferToHex(tx.gasPrice),
      gasLimit: ethUtil.bufferToHex(tx.gasLimit),
      to: ethUtil.bufferToHex(tx.to),
      value: ethUtil.bufferToHex(tx.value),
      data: ethUtil.bufferToHex(tx.data),
      v: ethUtil.bufferToHex(tx.v),
      r: ethUtil.bufferToHex(tx.r),
      s: ethUtil.bufferToHex(tx.s),
      chainId: tx.getChainId() ? tx.getChainId() : 0,
    }
  }

/**
 * Marks messages for external signature. And checks in everi 500 ms
 * that the user has provided signature externally.
 *
 * @param {String} type The message type. Can be one of 'sign_message',
 * 'sign_personal_message", or 'sign_typed_data'
 *
 * @param {String} witnAccount The account with which the messages must be signed with.
 * @param {Object} msg The message to be signed
 * @return {Promise} signed Signed message
 */
  _signMsg (type, withAccount, msg) {
    var intervalCounter = 0
    var extToSign = this.getState().extToSign
    let msgStr
    if (type === 'sign_typed_data') {
      if (typeof msg !== 'string') {
        msgStr = JSON.stringify(msg)
      }
    } else {
      msgStr = msg
    }
    const id = ethUtil.sha3(type + msgStr + withAccount + Date.now().toString()).toString('hex')
    extToSign.push({type: type, payload: msgStr, from: withAccount, id})
    this.updateState({extToSign})
    return new Promise((resolve, reject) => {
      //
      // check for user provided signature
      var interval = setInterval(() => {
        const state = this.getState()
        var extSigned = state['extSigned']
        var extCancel = state['extCancel']
        var extKeepAlive = state['extKeepAlive']

        // signing modal was closed
        if (intervalCounter > 25) {
          clearInterval(interval)
        }
        // signing modal sent keep alive
        if (extKeepAlive.find((eid) => eid === id)) {
          extKeepAlive = extKeepAlive.filter((eid) => eid !== id)
          this.updateState({extKeepAlive})
          intervalCounter = 0
        } else {
          intervalCounter++
        }

        var signedMsg = extSigned.find((sg) => this._eq(sg, msg, withAccount, type, id))
        var cancelMsg = extCancel.find((ca) => this._eq(ca, msg, withAccount, type, id))
        if (cancelMsg) {
          this._cleanup(extCancel, 'extCancel', interval, msg, withAccount, type)
          // if we could have besides msg state of 'signed' and 'failed'
          // one called 'canceled', we could return in a more meaningful way
          reject(new Error('Cancel pressed'))
        }
        if (signedMsg) {
          this._cleanup(extSigned, 'extSigned', interval, msg, withAccount, type)
          try {
            const {v, r, s} = this._signatureHexToVRS(signedMsg.signature)
            if (type === 'sign_message') {
              ethUtil.ecrecover(ethUtil.sha3(ethUtil.toBuffer(signedMsg.payload)), ethUtil.bufferToInt(v), r, s)
            }
            if (type === 'sign_personal_message') {
              ethUtil.ecrecover(ethUtil.hashPersonalMessage(ethUtil.toBuffer(signedMsg.payload)), ethUtil.bufferToInt(v), r, s)
            }
            if (type === 'sign_typed_data') {
              ethUtil.ecrecover(sigUtil.sign(signedMsg.payload), ethUtil.bufferToInt(v), r, s)
            }
            var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(v, r, s))
            resolve(rawMsgSig)
          } catch (e) {
            reject(new Error('Signature invalid'))
          }
        }
      }, 500)
    })
  }

/**
 * Compares extMsg with msg and returs true if they match.
 *
 * @param {Object} extMsg Message object signed by metamask ui.
 * @param {Object} msg Message to compare with
 * @param {String} withAccount Address that has signed msg.
 * @param {String} type Type of message one of 'sign_message',
 *   'sign_personal_message', or 'sign_typed_data'
 * @param {String} id External sign id of msg,
 * @return {Promise} signed Signed message
 */
  _eq (extMsg, msg, withAccount, type, id) {
    return extMsg.id === id || (id === null && extMsg.id === null &&
      extMsg.payload &&
      extMsg.payload === msg.msgParams.data &&
      extMsg.from === withAccount &&
      extMsg.type === type)
  }

  // cleanup memStore and stop polling
  _cleanup (toClean, key, interval, msg, withAccount, type) {
    clearInterval(interval)
    toClean = toClean.filter((sg) => !this._eq(sg, msg, withAccount, type))
    this.updateState({[key]: toClean})
  }

  // converts hex encoded signature to r, s, v signature
  _signatureHexToVRS (signature) {
    signature = ethUtil.stripHexPrefix(signature)
    const r = ethUtil.toBuffer('0x' + signature.substr(0, 64))
    const s = ethUtil.toBuffer('0x' + signature.substr(64, 64))
    const v = ethUtil.toBuffer('0x' + signature.substr(128, 2))
    return {r: r, s: s, v: v}
  }
}

ExternalAccountKeyring.type = type
module.exports = ExternalAccountKeyring
