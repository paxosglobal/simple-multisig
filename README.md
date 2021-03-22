Forked from: https://github.com/christianlundkvist/simple-multisig

# simple-multisig

## Introduction

This is Paxos Simple Multisig, based off of [the original](https://github.com/christianlundkvist/simple-multisig). It is an Ethereum smart contract designed to be as simple as possible. The original is described further in this [medium post](https://medium.com/@ChrisLundkvist/exploring-simpler-ethereum-multisig-contracts-b71020c19037). 
Paxos has extended the contract to add a `setOwners` feature allowing a quorum of signers to change the entire set of signers. We have a blogpost [here](https://www.paxos.com/simple-multisig-how-it-works-and-why-its-awesome).

The main idea behind the contract is to pass in a threshold of detached signatures into the `execute` function and the contract will check the signatures and send off the transaction.

The original audit report by [ConsenSys Diligence'](https://consensys.net/diligence/) can be found [here](./audit.pdf). 

The updated audit report by [ConsenSys Diligence'](https://consensys.net/diligence/) can be found [here](https://consensys.net/diligence/audits/2020/11/paxos/).

## Data to be signed

The Simple MultiSig uses the [EIP712](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md) standard to package and hash the data to be signed. Each signer will sign a message over the following data fields, which encode the ethereum transaction to execute:

* `address destination` - The target address for the transaction
* `uint256 value` - The value of the transaction expressed in Wei
* `bytes data` - The data of the transaction in hex format
* `uint256 nonce` - The nonce for this transaction. Must match the current nonce in the multisig contract.
* `address executor` - Specifies which Ethereum address is allowed to call the `execute` function. It is allowed to specify the zero address as an executor, in which case any address can call the `execute` function. This field is mainly to address concerns about replay attacks in some edge cases.
* `uint256 gasLimit` - Specifies how much gas to pass on to the final `call`, independently of how much gas is supplied to the transaction calling the `execute` function. This can be used to constrain what kind of computations can be performed by the target smart contract. If the signers do not need this level of control a very high gasLimit of several million can be used for this data field.

The data to be signed also includes the following EIP712 Domain data that specifies the context of the signed data:

* Name (`"Simple MultiSig"`)
* Version (`"1"`)
* ChainId (Integer marking current chain, e.g. 1 for mainnet)
* Contract Address (Address of the specific multisig contract instance)
* Salt (`0x251543af6a222378665a76fe38dbceae4871a070b7fdaf5c6c30cf758dc33cc0`, unique identifier specific to SimpleMultisig)

## Setting Owners

Paxos Simple Multisig adds setOwners functionality to be able to add and remove owners directly using a quorum of signers.

## Installation and testing

Install global dependencies:

* `npm install -g truffle`
* `npm install -g ganache-cli`

To run the tests:

* Make sure `ganache-cli` is running in its own terminal window.
* `npm install`
* `npm run test`

## Testing signatures in a browser

If you have the [MetaMask](https://metamask.io) browser extension you can open the page `browsertest/index.html` in your browser and test signing data. The signature will be returned in a `(r,s,v)` format which can be plugged into the `execute` function.
