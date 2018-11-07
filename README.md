# simple-multisig
Simple multisig for Ethereum using detached signatures

This is an Ethereum multisig contract designed to be as simple as possible. It is described further in this [medium post](https://medium.com/@ChrisLundkvist/exploring-simpler-ethereum-multisig-contracts-b71020c19037).

The main idea behind the contract is to pass in a threshold of detached signatures into the `execute` function and the contract will check the signatures and send off the transaction.

For a review by maurelian, see the file `maurelian_review.md`.

Install global dependencies:

* `npm install -g truffle`
* `npm install -g ganache-cli`

To run the tests:

* Make sure `ganache-cli` is running in its own terminal window.
* `npm install`
* `npm run test`

## Operator role
Paxos has added an operator role that is the sole signer/sender that can send transactions to the contract.
This makes it so that instead of requiring just t of n signatures, it requires 
1 signature by the operator AND t of n signatures where n does not include the operator,
so it's more like t+1 of n+1 where the last signature has to be the operator.

The use case is where a server signature is required, plus and t of n 
other acters, in our case humans, where `1<=t<=n`. 
In particular the humans have to each, separately, sign a transaction 
before sending it to the server 
for centralized submission.
