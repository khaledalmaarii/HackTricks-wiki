<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


## Basic Concepts

- **Smart Contracts** are defined as programs that execute on a blockchain when certain conditions are met, automating agreement executions without intermediaries.
- **Decentralized Applications (dApps)** build upon smart contracts, featuring a user-friendly front-end and a transparent, auditable back-end.
- **Tokens & Coins** differentiate where coins serve as digital money, while tokens represent value or ownership in specific contexts.
- **Utility Tokens** grant access to services, and **Security Tokens** signify asset ownership.
- **DeFi** stands for Decentralized Finance, offering financial services without central authorities.
- **DEX** and **DAOs** refer to Decentralized Exchange Platforms and Decentralized Autonomous Organizations, respectively.

## Consensus Mechanisms

Consensus mechanisms ensure secure and agreed transaction validations on the blockchain:
- **Proof of Work (PoW)** relies on computational power for transaction verification.
- **Proof of Stake (PoS)** demands validators to hold a certain amount of tokens, reducing energy consumption compared to PoW.

## Bitcoin Essentials

### Transactions

Bitcoin transactions involve transferring funds between addresses. Transactions are validated through digital signatures, ensuring only the owner of the private key can initiate transfers.

#### Key Components:

- **Multisignature Transactions** require multiple signatures to authorize a transaction.
- Transactions consist of **inputs** (source of funds), **outputs** (destination), **fees** (paid to miners), and **scripts** (transaction rules).

### Lightning Network

Aims to enhance Bitcoin's scalability by allowing multiple transactions within a channel, only broadcasting the final state to the blockchain.

## Bitcoin Privacy Concerns

Privacy attacks, such as **Common Input Ownership** and **UTXO Change Address Detection**, exploit transaction patterns. Strategies like **Mixers** and **CoinJoin** improve anonymity by obscuring transaction links between users.

## Acquiring Bitcoins Anonymously

Methods include cash trades, mining, and using mixers. **CoinJoin** mixes multiple transactions to complicate traceability, while **PayJoin** disguises CoinJoins as regular transactions for heightened privacy.


# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

In the world of Bitcoin, the privacy of transactions and the anonymity of users are often subjects of concern. Here's a simplified overview of several common methods through which attackers can compromise Bitcoin privacy.

## **Common Input Ownership Assumption**

It is generally rare for inputs from different users to be combined in a single transaction due to the complexity involved. Thus, **two input addresses in the same transaction are often assumed to belong to the same owner**.

## **UTXO Change Address Detection**

A UTXO, or **Unspent Transaction Output**, must be entirely spent in a transaction. If only a part of it is sent to another address, the remainder goes to a new change address. Observers can assume this new address belongs to the sender, compromising privacy.

### Example
To mitigate this, mixing services or using multiple addresses can help obscure ownership.

## **Social Networks & Forums Exposure**

Users sometimes share their Bitcoin addresses online, making it **easy to link the address to its owner**.

## **Transaction Graph Analysis**

Transactions can be visualized as graphs, revealing potential connections between users based on the flow of funds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

This heuristic is based on analyzing transactions with multiple inputs and outputs to guess which output is the change returning to the sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior
Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions without change are likely between two addresses owned by the same user.
- **Round Numbers:** A round number in a transaction suggests it's a payment, with the non-round output likely being the change.
- **Wallet Fingerprinting:** Different wallets have unique transaction creation patterns, allowing analysts to identify the software used and potentially the change address.
- **Amount & Timing Correlations:** Disclosing transaction times or amounts can make transactions traceable.

## **Traffic Analysis**

By monitoring network traffic, attackers can potentially link transactions or blocks to IP addresses, compromising user privacy. This is especially true if an entity operates many Bitcoin nodes, enhancing their ability to monitor transactions.

## More
For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** merges multiple transactions from different users into one, complicating the process for anyone trying to match inputs with outputs. Despite its effectiveness, transactions with unique input and output sizes can still potentially be traced.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
**tlhIngan Hol:**

**vItlhutlh:** yIqaw PayJoin, vItlhutlh privacy vItlhutlh je vItlhutlh bitcoin transactions.

**PayJoin vItlhutlh** vItlhutlh je vItlhutlh traditional surveillance methods, vItlhutlh je vItlhutlh promising development vItlhutlh transactional privacy.

# **Cryptocurrencies vItlhutlh Best Practices for Privacy**

## **Wallet Synchronization Techniques**

vItlhutlh je vItlhutlh privacy je vItlhutlh security, vItlhutlh je vItlhutlh synchronizing wallets je vItlhutlh blockchain. vItlhutlh je vItlhutlh methods:

- **Full node**: vItlhutlh je vItlhutlh blockchain vItlhutlh, vItlhutlh je vItlhutlh maximum privacy. vItlhutlh je vItlhutlh transactions vItlhutlh stored locally, vItlhutlh je vItlhutlh impossible je vItlhutlh adversaries je vItlhutlh transactions je vItlhutlh addresses je vItlhutlh user je vItlhutlh interested.
- **Client-side block filtering**: vItlhutlh je vItlhutlh creating filters vItlhutlh je vItlhutlh block vItlhutlh blockchain, vItlhutlh je vItlhutlh wallets je vItlhutlh relevant transactions je vItlhutlh exposing specific interests je vItlhutlh network observers. Lightweight wallets vItlhutlh download filters, vItlhutlh fetching full blocks je vItlhutlh match je vItlhutlh user's addresses je vItlhutlh found.

## **Tor je vItlhutlh Utilizing je Anonymity**

Bitcoin vItlhutlh je vItlhutlh peer-to-peer network, vItlhutlh je vItlhutlh Tor je vItlhutlh recommended je vItlhutlh IP address, vItlhutlh je vItlhutlh privacy je vItlhutlh interacting je vItlhutlh network.

## **Preventing Address Reuse**

vItlhutlh je vItlhutlh privacy, vItlhutlh je vItlhutlh vital je vItlhutlh new address je vItlhutlh transaction. vItlhutlh je vItlhutlh address reuse vItlhutlh compromise privacy je vItlhutlh linking transactions je vItlhutlh entity. Modern wallets vItlhutlh discourage address reuse je vItlhutlh design.

## **Strategies je vItlhutlh Transaction Privacy**

- **Multiple transactions**: vItlhutlh je vItlhutlh splitting payment je vItlhutlh several transactions vItlhutlh obscure transaction amount, vItlhutlh je vItlhutlh privacy attacks.
- **Change avoidance**: vItlhutlh je vItlhutlh transactions vItlhutlh je vItlhutlh require change outputs vItlhutlh je vItlhutlh privacy je vItlhutlh disrupting change detection methods.
- **Multiple change outputs**: vItlhutlh je vItlhutlh avoiding change vItlhutlh feasible, vItlhutlh je vItlhutlh multiple change outputs vItlhutlh je vItlhutlh improve privacy.

# **Monero: vItlhutlh Beacon je Anonymity**

Monero vItlhutlh je vItlhutlh need je vItlhutlh absolute anonymity je vItlhutlh digital transactions, vItlhutlh je vItlhutlh high standard je vItlhutlh privacy.

# **Ethereum: Gas je vItlhutlh Transactions**

## **Understanding Gas**

Gas vItlhutlh je vItlhutlh computational effort je vItlhutlh execute operations je vItlhutlh Ethereum, vItlhutlh je vItlhutlh **gwei**. vItlhutlh je vItlhutlh transaction costing 2,310,000 gwei (je 0.00231 ETH) vItlhutlh je vItlhutlh gas limit je vItlhutlh base fee, vItlhutlh je vItlhutlh tip je vItlhutlh incentivize miners. Users vItlhutlh set max fee je vItlhutlh they don't overpay, vItlhutlh je vItlhutlh excess refunded.

## **Executing Transactions**

Transactions je vItlhutlh Ethereum vItlhutlh je vItlhutlh sender je vItlhutlh recipient, vItlhutlh je vItlhutlh user je vItlhutlh smart contract addresses. vItlhutlh je vItlhutlh fee vItlhutlh je vItlhutlh must be mined. Essential information je vItlhutlh transaction vItlhutlh je vItlhutlh recipient, sender's signature, value, optional data, gas limit, vItlhutlh fees. Notably, vItlhutlh je vItlhutlh sender's address vItlhutlh deduced je vItlhutlh signature, vItlhutlh je vItlhutlh need vItlhutlh je vItlhutlh transaction data.

vItlhutlh je vItlhutlh practices je vItlhutlh mechanisms vItlhutlh foundational je vItlhutlh anyone looking je vItlhutlh engage je vItlhutlh cryptocurrencies je vItlhutlh prioritizing privacy je vItlhutlh security.


## References

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
