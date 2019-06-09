const EventEmitter = require('events').EventEmitter
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const log = require('loglevel')
const type = 'Bidirectional Qr Account'
const Transaction = require('ethereumjs-tx')
const ObservableStore = require('obs-store')

class BidirectionalQrKeyring extends EventEmitter {

  /* PUBLIC METHODS */
  constructor (opts) {
    if (BidirectionalQrKeyring.instance) {
      BidirectionalQrKeyring.instance.deserialize(opts)
      return BidirectionalQrKeyring.instance
    }
    super()
    this.type = type
    this.accounts = []
    this.memStore = new ObservableStore({
      bidirectionalQrSignables: [],
    })
    BidirectionalQrKeyring.instance = this
    this.deserialize(opts)
  }

  serialize () {
    return Promise.resolve(this.accounts.slice())
  }

  deserialize (accounts = []) {
    return new Promise((resolve, reject) => {
      try {
        this.accounts = this.accounts.concat(accounts.slice())
      } catch (e) {
        reject(e)
      }
      resolve()
    })
  }

  addAccounts (n = 1, opts = {accounts: []}) {
    if (opts.accounts.length !== n) {
      return Promise.reject(new Error('Number of accounts do not match.'))
    }
    this.accounts = this.accounts.concat(opts.accounts.slice())
    return Promise.resolve(opts.accounts)
  }

  getAccounts () {
    return Promise.resolve(this.accounts.slice())
  }

  // tx is an instance of the ethereumjs-tx class.
  signTransaction (address, tx, opts = {txId: null}) {
    log.info(`BidirectionalQrKeyring - signTransaction - address: ${address}`)

    if (!(tx instanceof Transaction)) {
      return Promise.reject(new Error('Invalid transaction'))
    }

    if (!ethUtil.isValidAddress(address)) {
      return Promise.reject(new Error('Invalid address: ' + address))
    }

    var bidirectionalQrSignables = this.memStore
      .getState().bidirectionalQrSignables

    const serialized = this._serializeUnsigned(tx, address)
    if (opts.txId) var id = opts.txId
    else {
      id = ethUtil.sha3(
        JSON.stringify(serialized) +
        Date.now().toString()
      ).toString('hex')
    }

    bidirectionalQrSignables.push({
      type: 'sign_transaction',
      payload: serialized,
      from: address,
      id,
    })

    this.memStore
      .updateState({bidirectionalQrSignables})

    log.info('BidirectionalQrKeyring - signTransaction: bidirectionalQrSignables:' + JSON.stringify(bidirectionalQrSignables))
    return new Promise((resolve, reject) => {
      this.once(`${id}:signed`, (r, s, v) => {
        log.info(`BidirectionalQrKeyring - signTransaction signed id: ${id}`)
        tx.r = r
        tx.s = s
        tx.v = v
        resolve(tx)
      })
      this.once(`${id}:canceled`, () => {
        log.info(`BidirectionalQrKeyring - signTransaction canceled id: ${id}`)
        reject(new Error('Cancel pressed'))
      })
    })
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage (withAccount, data, opts = {msgId: null}) {
    return this._signMsg('sign_message', withAccount, data, opts.msgId)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex, opts = {msgId: null}) {
    return this._signMsg('sign_personal_message', withAccount, msgHex, opts.msgId)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData, opts = {msgId: null}) {
    return this._signMsg('sign_typed_data', withAccount, typedData, opts.msgId)
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount (address) {
    return Promise.reject(new Error('Not supported'))
  }

  removeAccount (address) {
    if (!this.accounts.map(acc => ethUtil.bufferToHex(acc).toLowerCase()).includes(address.toLowerCase())) {
      return Promise.reject(new Error(`Address ${address} not found in this keyring`))
    }
    this.accounts = this.accounts.filter(acc => acc.toLowerCase() !== address.toLowerCase())
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
    log.info(`BidirectionalQrKeyring - ${type} - address: ${withAccount}`)

    var bidirectionalQrSignables = this.memStore
      .getState().bidirectionalQrSignables

    let msgStr
    if (type === 'sign_typed_data') {
      if (typeof msg !== 'string') {
        msgStr = JSON.stringify(msg)
      }
    } else {
      msgStr = msg
    }

    const id = ethUtil.sha3(type + msgStr + withAccount + Date.now().toString()).toString('hex')
    bidirectionalQrSignables.push({
      type: type,
      payload: msgStr,
      from: withAccount,
      id,
    })

    this.memStore.updateState({bidirectionalQrSignables})
    log.info(`BidirectionalQrKeyring - ${type} - bidirectionalQrSignables:` + JSON.stringify(bidirectionalQrSignables))
    return new Promise((resolve, reject) => {

      this.once(`${id}:signed`, (rawMsgSig) => {
        log.info(`BidirectionalQrKeyring - signTransaction signed id: ${id}`)
        resolve(rawMsgSig)
      })

      this.once(`${id}:canceled`, () => {
        log.info(`BidirectionalQrKeyring - signTransaction canceled id: ${id}`)
        reject(new Error('Cancel pressed'))
      })
    })
  }

  submitSignature (id, r, s, v) {
    r = ethUtil.toBuffer(r)
    s = ethUtil.toBuffer(s)
    v = ethUtil.toBuffer(v)

    var signables = this.memStore
      .getState()
      .bidirectionalQrSignables
      .filter(signable => signable.id === id)

    if (!signables || signables.length !== 1) {
      return Promise.reject(new Error('Signable id not found.'))
    }

    const signable = signables[0]
    if (signable.type === 'sign_transaction') {
      const tx = new Transaction(signable.payload)
      tx.r = r
      tx.s = s
      tx.v = v
      if (!tx.verifySignature()) {
        return Promise.reject(new Error('Invalid signature.'))
      }
      this.emit(`${id}:signed`, r, s, v)
    } else {
      try {
        if (signable.type === 'sign_message') {
          ethUtil.ecrecover(
            ethUtil.sha3(ethUtil.toBuffer(signable.payload)),
            ethUtil.bufferToInt(v),
            r,
            s
          )
        } else if (signable.type === 'sign_personal_message') {
          ethUtil.ecrecover(
            ethUtil.hashPersonalMessage(
              ethUtil.toBuffer(signable.payload)),
              ethUtil.bufferToInt(v),
              r,
              s
          )
        } else if (signable.type === 'sign_typed_data') {
          ethUtil.ecrecover(
            sigUtil.sign(signable.payload),
            ethUtil.bufferToInt(v),
            r,
            s
          )
        } else return Promise.reject(new Error('Unsupported signature type.'))

        const rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(v, r, s))
        this.emit(`${id}:signed`, rawMsgSig)
      } catch (e) {
        return Promise.reject(new Error('Invalid signature'))
      }
    }
    const idRemoved = this.memStore
      .getState()
      .bidirectionalQrSignables
      .filter(signable => signable.id !== id)

    this.memStore
      .updateState({
        bidirectionalQrSignables: idRemoved,
      })

    return Promise.resolve()
  }

  cancelSignature (id) {
    const idRemoved = this.memStore
      .getState()
      .bidirectionalQrSignables
      .filter(signable => signable.id !== id)

    this.memStore
      .updateState({
        bidirectionalQrSignables: idRemoved,
      })

    this.emit(`${id}:canceled`)
    return Promise.resolve()
  }
}

BidirectionalQrKeyring.type = type
BidirectionalQrKeyring.instance = null

module.exports = BidirectionalQrKeyring
