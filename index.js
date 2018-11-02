const EventEmitter = require('events').EventEmitter
const ethUtil = require('ethereumjs-util')
const type = 'External Account'

class ExternalAccountKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor (opts) {
    super()
    this.type = type
    this.accounts = []
    this.deserialize(opts)
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

  // tx is an instance of the ethereumjs-transaction class.
  signTransaction (address, tx) {
    throw new Error('Not supported')
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage (withAccount, data) {
    throw new Error('Not supported')
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex) {
    throw new Error('Not supported')
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData) {
    throw new Error('Not supported')
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount (address) {
    throw new Error('Not supported')
  }

  removeAccount (address) {
    if(!this.accounts.map(acc => ethUtil.bufferToHex(acc).toLowerCase()).includes(address.toLowerCase())){
      throw new Error(`Address ${address} not found in this keyring`)
    }
    this.accounts = this.accounts.filter( acc => acc.toLowerCase() !== address.toLowerCase())
  }
}

ExternalAccountKeyring.type = type
module.exports = ExternalAccountKeyring
