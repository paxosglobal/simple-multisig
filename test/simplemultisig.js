var SimpleMultiSig = artifacts.require("./SimpleMultiSig.sol")
var TestRegistry = artifacts.require("./TestRegistry.sol")
var lightwallet = require('eth-lightwallet')
const Promise = require('bluebird')

const web3SendTransaction = Promise.promisify(web3.eth.sendTransaction)
const web3GetBalance = Promise.promisify(web3.eth.getBalance)

let DOMAIN_SEPARATOR
const TXTYPE_HASH = '0x3ee892349ae4bbe61dce18f95115b5dc02daf49204cc602458cd4c1f540d56d7'
const NAME_HASH = '0xb7a0bfa1b79f2443f4d73ebb9259cddbcd510b18be6fc4da7d1aa7b1786e73e6'
const VERSION_HASH = '0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6'
const EIP712DOMAINTYPE_HASH = '0xd87cd6ef79d4e2b95e15ce8abf732db51ec771f1ca2edccf22a46c729ac56472'
const SALT = '0x251543af6a222378665a76fe38dbceae4871a070b7fdaf5c6c30cf758dc33cc0'


const CHAINID = 1
const ZEROADDR = '0x0000000000000000000000000000000000000000'

contract('SimpleMultiSig', function(accounts) {

  let keyFromPw
  let acct
  let lw

  let packMsg = function(multisigAddr, nonce, destinationAddr, value, data, executor, gasLimit) {
    const domainData = EIP712DOMAINTYPE_HASH + NAME_HASH.slice(2) + VERSION_HASH.slice(2) + CHAINID.toString(16).padStart(64, '0') + multisigAddr.slice(2).padStart(64, '0') + SALT.slice(2)
    DOMAIN_SEPARATOR = web3.utils.sha3Raw(domainData)

    let txInput = TXTYPE_HASH + destinationAddr.slice(2).padStart(64, '0') + web3.utils.toHex(value).padStart(64, '0') + web3.utils.sha3Raw(data).slice(2) + nonce.toString(16).padStart(64, '0') + executor.slice(2).padStart(64, '0') + gasLimit.toString(16).padStart(64, '0')
    let txInputHash = web3.utils.sha3Raw(txInput)

    let input = '0x19' + '01' + DOMAIN_SEPARATOR.slice(2) + txInputHash.slice(2)
    let hash = web3.utils.sha3Raw(input)

    return hash
  }

  let createSigs = function(signers, multisigAddr, nonce, destinationAddr, value, data, executor, gasLimit) {

    let hash = packMsg(multisigAddr, nonce, destinationAddr, value, data, executor, gasLimit)

    let sigV = []
    let sigR = []
    let sigS = []

    for (var i=0; i<signers.length; i++) {
      let sig = lightwallet.signing.signMsgHash(lw, keyFromPw, hash, signers[i])
      sigV.push(sig.v)
      sigR.push('0x' + sig.r.toString('hex'))
      sigS.push('0x' + sig.s.toString('hex'))
    }

    return {sigV: sigV, sigR: sigR, sigS: sigS}

  }

  let setupContract = async function(owners, threshold) {

    let multisig = await SimpleMultiSig.new(threshold, owners, CHAINID, {from: accounts[0]})

    // Receive funds
    await web3SendTransaction({from: accounts[0], to: multisig.address, value: web3.utils.toWei('0.1', 'ether')})

    return multisig
  }

  let executeSendSuccess = async function(owners, threshold, signers, done) {

    let multisig = await setupContract(owners, threshold)
    let randomAddr = web3.utils.sha3Raw(Math.random().toString()).slice(0,42)
    let executor = accounts[0]
    let msgSender = accounts[0]

    let nonce = await multisig.nonce.call()
    assert.equal(nonce.toNumber(), 0)

    let bal = await web3GetBalance(multisig.address)
    assert.equal(bal, web3.utils.toWei('0.1', 'ether'))

    // check that owners are stored correctly
    let ownersArr = await multisig.owners.call()
    // checksum capitalized or all lowercase addresses are not consistent here
    assert.equal(ownersArr.toString().toLowerCase(), owners.toString().toLowerCase())
    for (var i=0; i<owners.length; i++) {
      let ownerFromContract = await multisig.ownersArr.call(i)
      assert.equal(web3.utils.toChecksumAddress(owners[i]), web3.utils.toChecksumAddress(ownerFromContract))
    }

    let value = web3.utils.toWei('0.01', 'ether')
    let sigs = createSigs(signers, multisig.address, nonce, randomAddr, value, [], executor, 21000)
    await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, randomAddr, value, [], executor, 21000, {from: msgSender, gasLimit: 1000000})

    // Check funds sent
    bal = await web3GetBalance(randomAddr)
    assert.equal(bal.toString(), value.toString())

    // Check nonce updated
    nonce = await multisig.nonce.call()
    assert.equal(nonce.toNumber(), 1)

    // Send again
    // Check that it succeeds with executor = Zero address
    sigs = createSigs(signers, multisig.address, nonce, randomAddr, value, [], ZEROADDR, 21000)
    await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, randomAddr, value, [], ZEROADDR, 21000, {from: msgSender, gasLimit: 1000000})

    // Check funds
    bal = await web3GetBalance(randomAddr)
    assert.equal(bal.toString(), (value*2).toString())

    // Check nonce updated
    nonce = await multisig.nonce.call()
    assert.equal(nonce.toNumber(), 2)

    // Test contract interactions
    let reg = await TestRegistry.new({from: accounts[0]})

    let number = 12345
    let data = lightwallet.txutils._encodeFunctionTxData('register', ['uint256'], [number])

    sigs = createSigs(signers, multisig.address, nonce, reg.address, value, data, executor, 100000)
    await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, reg.address, value, data, executor, 100000, {from: msgSender, gasLimit: 1000000})

    // Check that number has been set in registry
    let numFromRegistry = await reg.registry(multisig.address)
    assert.equal(numFromRegistry.toNumber(), number)

    // Check funds in registry
    bal = await web3GetBalance(reg.address)
    assert.equal(bal.toString(), value.toString())

    // Check nonce updated
    nonce = await multisig.nonce.call()
    assert.equal(nonce.toNumber(), 3)

    done()
  }

  let executeSendFailure = async function(owners, threshold, signers, nonceOffset, executor, gasLimit, done) {

    let multisig = await setupContract(owners, threshold)

    let nonce = await multisig.nonce.call()
    assert.equal(nonce.toNumber(), 0)

    let randomAddr = web3.utils.sha3Raw(Math.random().toString()).slice(0,42)
    let value = web3.utils.toWei('0.1', 'ether')
    let sigs = createSigs(signers, multisig.address, nonce + nonceOffset, randomAddr, value, [], executor, gasLimit)

    let errMsg = ''
    try {
      await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, randomAddr, value, [], executor, gasLimit, {from: executor, gasLimit: 1000000})
    }
    catch(error) {
      errMsg = error.message
    }

    assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')

    done()
  }

  let creationFailure = async function(owners, threshold, done) {

    try {
      await SimpleMultiSig.new(threshold, owners, CHAINID, {from: accounts[0]})
    }
    catch(error) {
      errMsg = error.message
    }

    assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')

    done()
  }

  before((done) => {

    let seed = "pull rent tower word science patrol economy legal yellow kit frequent fat"

    lightwallet.keystore.createVault(
    {hdPathString: "m/44'/60'/0'/0",
     seedPhrase: seed,
     password: "test",
     salt: "testsalt"
    },
    function (err, keystore) {

      lw = keystore
      lw.keyFromPassword("test", function(e,k) {
        keyFromPw = k

        lw.generateNewAddress(keyFromPw, 20)
        let acctWithout0x = lw.getAddresses()
        acct = acctWithout0x.map((a) => {return a})
        acct.sort()
        done()
      })
    })
  })

  describe("Pack message encoding", () => {
    it("should get the expected hash", (done) => {
      let addr1 = "0x6a7681a3cBb4EC523a4737449452058a11D97e16"
      let addr2 = "0xdB1fc656627D00789121f54b649a833563857EbE"
      let addr3 = "0x415B4B4d13D21C030c9ecb8E9843ce3f6c0165c1"
      let value = web3.utils.toWei('0.01', 'ether')

      hash = packMsg(addr1, 0, addr2, value, [], addr3, 21000)
      assert.equal(hash, "0xf65d46b9f3c377a4fdd06b2a2efdd9bade6f900f1388683c93927876c15a168e")

      let number = 12345
      let data = lightwallet.txutils._encodeFunctionTxData('register', ['uint256'], [number])
      hash = packMsg(addr1, 1, addr2, value, data, addr3, 21000)
      assert.equal(hash, "0x7fc98c5b844576122f29b0119f532356459f553c67e32b68353e85850c647e38")
      done()
    })
  })

  describe("3 signers, threshold 2", () => {

    it("should succeed with signers 0, 1", (done) => {
      let signers = [acct[0], acct[1]]
      signers.sort()
      executeSendSuccess(acct.slice(0,3), 2, signers, done)
    })

    it("should succeed with signers 0, 2", (done) => {
      let signers = [acct[0], acct[2]]
      signers.sort()
      executeSendSuccess(acct.slice(0,3), 2, signers, done)
    })

    it("should succeed with signers 1, 2", (done) => {
      let signers = [acct[1], acct[2]]
      signers.sort()
      executeSendSuccess(acct.slice(0,3), 2, signers, done)
    })

    it("should fail due to non-owner signer", (done) => {
      let signers = [acct[0], acct[3]]
      signers.sort()
      executeSendFailure(acct.slice(0,3), 2, signers, 0, accounts[0], 100000, done)
    })

    it("should fail with more signers than threshold", (done) => {
      executeSendFailure(acct.slice(0,3), 2, acct.slice(0,3), 0, accounts[0], 100000, done)
    })

    it("should fail with fewer signers than threshold", (done) => {
      executeSendFailure(acct.slice(0,3), 2, [acct[0]], 0, accounts[0], 100000, done)
    })

    it("should fail with one signer signing twice", (done) => {
      executeSendFailure(acct.slice(0,3), 2, [acct[0], acct[0]], 0, accounts[0], 100000, done)
    })

    it("should fail with signers in wrong order", (done) => {
      let signers = [acct[0], acct[1]]
      signers.sort().reverse() //opposite order it should be
      executeSendFailure(acct.slice(0,3), 2, signers, 0, accounts[0], 100000, done)
    })

    it("should fail with the wrong nonce", (done) => {
      const nonceOffset = 1
      executeSendFailure(acct.slice(0,3), 2, [acct[0], acct[1]], nonceOffset, accounts[0], 100000, done)
    })

  })

  describe("Edge cases", () => {
    it("should succeed with 10 owners, 10 signers", (done) => {
      executeSendSuccess(acct.slice(0,10), 10, acct.slice(0,10), done)
    })

    it("should fail to create with signers 0, 0, 2, and threshold 3", (done) => {
      creationFailure([acct[0],acct[0],acct[2]], 3, done)
    })

    it("should fail with 0 signers", (done) => {
      executeSendFailure(acct.slice(0,3), 2, [], 0, accounts[0], 100000, done)
    })

    it("should fail with 11 owners", (done) => {
      creationFailure(acct.slice(0,11), 2, done)
    })
  })

  describe("Hash constants", () => {
    it("uses correct hash for EIP712DOMAINTYPE", (done) => {
      const eip712DomainType = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)'
      assert.equal(web3.utils.sha3Raw(eip712DomainType), EIP712DOMAINTYPE_HASH)
      done()
    })

    it("uses correct hash for NAME", (done) => {
      assert.equal(web3.utils.sha3Raw('Simple MultiSig'), NAME_HASH)
      done()
    })

    it("uses correct hash for VERSION", (done) => {
      assert.equal(web3.utils.sha3Raw('1'), VERSION_HASH)
      done()
    })

    it("uses correct hash for MULTISIGTX", (done) => {
      const multiSigTxType = 'MultiSigTransaction(address destination,uint256 value,bytes data,uint256 nonce,address executor,uint256 gasLimit)'
      assert.equal(web3.utils.sha3Raw(multiSigTxType), TXTYPE_HASH)
      done()
    })
  })

  describe("Browser MetaMask test", () => {
    it("Matches the signature from MetaMask", (done) => {

      // To test in MetaMask:
      //
      // Import the following private key in MetaMask:
      // 0xac6d4b13220cd81f3630b7714f7e205494acc0823fb07a63bb40e65f669cbb9e
      // It should give the address:
      // 0x01BF9878a7099b2203838f3a8E7652Ad7B127A26
      //
      // Make sure you are on Mainnet with the above account
      // Load the HTML page located at
      // browsertest/index.html
      // and click "Sign data" (using the default values).
      // You should see the signature values r,s,v below:

      const mmSigR = '0x91a622ccbd1c65debc16cfa1761b6200acc42099a19d753c7c59ceb12a8f5cfc'
      const mmSigS = '0x6814fae69a6cc506b11adf971ca233fbcdbdca312ab96a58eb6b6b6792771fd4'
      const mmSigV = 27

      const walletAddress = '0xe3de7de481cbde9b4d5f62c6d228ec62277560c8'
      const destination = '0x8582afea2dd8e47297dbcdcf9ca289756ee21430'
      const value = web3.utils.toWei('0.01', 'ether')
      const data = '0xf207564e0000000000000000000000000000000000000000000000000000000000003039'
      const nonce = 2
      const executor = '0x0be430662ec0659ee786c04925c0146991fbdc0f'
      const gasLimit = 100000
      const signers = [acct[0]]

      let sigs = createSigs(signers, walletAddress, nonce, destination, value, data, executor, gasLimit)

      assert.equal(sigs.sigR[0], mmSigR)
      assert.equal(sigs.sigS[0], mmSigS)
      assert.equal(sigs.sigV[0], mmSigV)

      done()
    })
  })

  describe("setOwners", () => {

    let noOp = ()=>{}
    let threshold = 2

    it("successfully migrates to new owners", (done) => {
      let accountsA = acct.slice(0,3)
      let accountsB = acct.slice(3,6)

      let signersA = [acct[0], acct[1]]
      signersA.sort()
      let signersB = [acct[3], acct[4]]
      signersB.sort()

      let nonce = 0
      let executor = accounts[0]

      let executeSetOwners = async function(done) {
        let multisig = await setupContract(accountsA, 2)

        // change the owners using a quorum of signatures from group A to group B
        let data = lightwallet.txutils._encodeFunctionTxData('setOwners', ['uint256', 'address[]'], [threshold, accountsB])
        let sigs = createSigs(signersA, multisig.address, nonce, multisig.address, 0, data, executor, 200000)
        await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, multisig.address, 0, data, executor, 200000, {from: executor, gasLimit: 1000000})

        let endOwners = await multisig.owners()
        assert.equal(endOwners.toString().toLowerCase(), accountsB.toString().toLowerCase())

        // check that the old owners can't send some eth
        let value = web3.utils.toWei('0.01', 'ether')
        let randomAddr = web3.utils.sha3Raw(Math.random().toString()).slice(0,42)
        nonce += 1
        let errMsg = ''
        try {
          sigs = createSigs(signersA, multisig.address, nonce, randomAddr, value, [], executor, 21000)
          await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, randomAddr, value, [], executor, 21000, {from: executor, gasLimit: 1000000})
        }
        catch(error) {
          errMsg = error.message
        }
        assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')
        bal = await web3GetBalance(randomAddr)
        assert.equal(bal.toString(), 0)

        // check that the new owners can send some eth
        sigs = createSigs(signersB, multisig.address, nonce, randomAddr, value, [], executor, 21000)
        await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, randomAddr, value, [], executor, 21000, {from: executor, gasLimit: 1000000})
        bal = await web3GetBalance(randomAddr)
        assert.equal(bal.toString(), value.toString())

        done()
      }

      executeSetOwners(done)
    })

    it("cannot be called with non-owner signatures", (done) => {
      let accountsA = acct.slice(0,3)
      let accountsB = acct.slice(3,6)

      let signersB = [acct[3], acct[4]]
      signersB.sort()

      let nonce = 0
      let executor = accounts[0]

      let executeSetOwners = async function(done) {
        let multisig = await setupContract(accountsA, threshold)

        // change the owners to group B using signatures from group B who are not already owners
        let data = lightwallet.txutils._encodeFunctionTxData('setOwners', ['uint256', 'address[]'], [threshold, accountsB])
        let sigs = createSigs(signersB, multisig.address, nonce, multisig.address, 0, data, executor, 200000)
        let errMsg = ''
        try {
          await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, multisig.address, 0, data, executor, 200000, {from: executor, gasLimit: 1000000})
        }
        catch(error) {
          errMsg = error.message
        }
        assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')

        let endOwners = await multisig.owners()
        assert.equal(endOwners.toString().toLowerCase(), accountsA.toString().toLowerCase())

        done()
      }

      executeSetOwners(done)
    })

    it("cannot be called directly", (done) => {
      let accountsA = acct.slice(0,3)

      let signersB = [acct[3], acct[4]]
      signersB.sort()

      let executor = accounts[0]

      let executeSetOwners = async function(done) {
        let multisig = await setupContract(accountsA, 2)

        let errMsg = ''
        try {
          await multisig.setOwners(threshold, signersB, {from: executor, gasLimit: 1000000})
        }
        catch(error) {
          errMsg = error.message
        }
        assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')

        let endOwners = await multisig.owners()
        assert.equal(endOwners.toString().toLowerCase(), accountsA.toString().toLowerCase())

        done()
      }

      executeSetOwners(done)
    })

    it("cannot set threshold to zero or pass zero owners", (done) => {
      let accountsA = acct.slice(0,3)
      let accountsB = acct.slice(3,6)

      let signersA = [acct[0], acct[1]]
      signersA.sort()

      let nonce = 0
      let executor = accounts[0]

      let executeSetOwners = async function(done) {
        let multisig = await setupContract(accountsA, threshold)

        // change the threshold to zero
        let zeroThreshold = 0
        let data = lightwallet.txutils._encodeFunctionTxData('setOwners', ['uint256', 'address[]'], [zeroThreshold, accountsB])
        let sigs = createSigs(signersA, multisig.address, nonce, multisig.address, 0, data, executor, 200000)
        let errMsg = ''
        try {
          await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, multisig.address, 0, data, executor, 200000, {from: executor, gasLimit: 1000000})
        }
        catch(error) {
          errMsg = error.message
        }
        assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')

        // change the owners to none
        let noAccounts = []
        data = lightwallet.txutils._encodeFunctionTxData('setOwners', ['uint256', 'address[]'], [threshold, noAccounts])
        sigs = createSigs(signersA, multisig.address, nonce, multisig.address, 0, data, executor, 200000)
        errMsg = ''
        try {
          await multisig.execute(sigs.sigV, sigs.sigR, sigs.sigS, multisig.address, 0, data, executor, 200000, {from: executor, gasLimit: 1000000})
        }
        catch(error) {
          errMsg = error.message
        }
        assert.equal(errMsg, 'Returned error: VM Exception while processing transaction: revert', 'Test did not throw')

        let endOwners = await multisig.owners()
        assert.equal(endOwners.toString().toLowerCase(), accountsA.toString().toLowerCase())

        done()
      }

      executeSetOwners(done)
    })
  })

})
