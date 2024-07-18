{% hint style="success" %}
学习并练习AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## 基本概念

- **智能合约**被定义为在区块链上执行的程序，当满足特定条件时自动执行协议，无需中介。
- **去中心化应用程序 (dApps)** 建立在智能合约之上，具有用户友好的前端和透明、可审计的后端。
- **代币和加密货币** 区分为代币作为数字货币，而代币代表特定情境中的价值或所有权。
- **实用代币** 授予访问服务的权限，而 **安全代币** 表示资产所有权。
- **DeFi** 代表去中心化金融，提供无需中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指去中心化交易平台和去中心化自治组织。

## 共识机制

共识机制确保在区块链上进行安全且达成一致的交易验证：
- **工作量证明 (PoW)** 依赖计算能力进行交易验证。
- **权益证明 (PoS)** 要求验证者持有一定数量的代币，相较于 PoW 减少能源消耗。

## 比特币基础知识

### 交易

比特币交易涉及在地址之间转移资金。交易通过数字签名验证，确保只有私钥的所有者可以发起转账。

#### 关键组件：

- **多重签名交易** 需要多个签名来授权交易。
- 交易包括 **输入** (资金来源)、**输出** (目的地)、**费用** (支付给矿工) 和 **脚本** (交易规则)。

### 闪电网络

旨在通过允许通道内的多个交易，仅向区块链广播最终状态来增强比特币的可扩展性。

## 比特币隐私问题

隐私攻击，如 **共同输入所有权** 和 **UTXO 更改地址检测**，利用交易模式。像 **混币** 和 **CoinJoin** 这样的策略通过模糊用户之间的交易链接来提高匿名性。

## 匿名获取比特币

方法包括现金交易、挖矿和使用混币。**CoinJoin** 将多个交易混合在一起以增加追踪难度，而 **PayJoin** 将 CoinJoin 伪装成常规交易以提高隐私性。
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **强制地址重用**

攻击者可能向先前使用过的地址发送小额金额，希望接收方将这些金额与将来的其他输入合并在一起进行交易，从而将地址关联起来。

### 正确的钱包行为
钱包应避免使用已经使用过的空地址收到的硬币，以防止这种隐私泄漏。

## **其他区块链分析技术**

- **确切的支付金额：** 没有找零的交易很可能是同一用户拥有的两个地址之间的交易。
- **整数金额：** 交易中的整数金额表明这是一笔付款，而非整数输出很可能是找零。
- **钱包指纹识别：** 不同的钱包具有独特的交易创建模式，允许分析人员识别所使用的软件，可能还有找零地址。
- **金额和时间相关性：** 披露交易时间或金额可能使交易可追踪。

## **流量分析**

通过监视网络流量，攻击者可能将交易或区块与 IP 地址关联起来，危及用户隐私。如果一个实体运行许多比特币节点，尤其是真实，这一点尤为真实，增强了他们监视交易的能力。

## 更多
有关隐私攻击和防御的全面列表，请访问[比特币维基上的比特币隐私](https://en.bitcoin.it/wiki/Privacy)。

# 匿名比特币交易

## 匿名获取比特币的方法

- **现金交易：** 通过现金获取比特币。
- **现金替代品：** 购买礼品卡并在线兑换比特币。
- **挖矿：** 通过挖矿赚取比特币是最私密的方法，尤其是在独自进行挖矿时，因为挖矿池可能知道矿工的 IP 地址。[挖矿池信息](https://en.bitcoin.it/wiki/Pooled_mining)
- **盗窃：** 理论上，窃取比特币可能是另一种匿名获取比特币的方法，尽管这是非法的，不建议这样做。

## 混币服务

通过使用混币服务，用户可以**发送比特币**并收到**不同的比特币作为回报**，这使得追踪原始所有者变得困难。然而，这需要对服务的信任，不要保留日志并确实归还比特币。替代混币选项包括比特币赌场。

## CoinJoin

**CoinJoin**将来自不同用户的多个交易合并为一笔交易，使试图将输入与输出匹配的人的过程变得复杂。尽管其有效性，具有独特输入和输出大小的交易仍可能被追踪。

可能使用了CoinJoin的示例交易包括`402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a`和`85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

有关更多信息，请访问[CoinJoin](https://coinjoin.io/en)。对于以太坊上类似的服务，请查看[Tornado Cash](https://tornado.cash)，该服务使用矿工资金匿名化交易。

## PayJoin

作为CoinJoin的变体，**PayJoin**（或P2EP）将交易伪装成两个当事人（例如，客户和商家）之间的常规交易，而不具有CoinJoin特有的等额输出特征。这使得它极其难以检测，并且可能使交易监视实体使用的共同输入所有权启发式失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
## **加密货币中的隐私最佳实践**

### **钱包同步技术**

为了维护隐私和安全，与区块链同步钱包至关重要。有两种突出的方法：

- **完整节点**：通过下载整个区块链，完整节点确保最大隐私性。所有历史交易都存储在本地，使对手无法识别用户感兴趣的交易或地址。
- **客户端端区块过滤**：该方法涉及为区块链中的每个区块创建过滤器，允许钱包识别相关交易而不向网络观察者公开特定兴趣。轻量级钱包下载这些过滤器，仅在找到与用户地址匹配的完整区块时才获取完整区块。

### **利用 Tor 实现匿名性**

鉴于比特币在点对点网络上运行，建议使用 Tor 来掩盖您的 IP 地址，在与网络交互时增强隐私。

### **防止地址重复使用**

为了保护隐私，每次交易都使用新地址至关重要。重复使用地址可能通过将交易与同一实体关联来损害隐私。现代钱包通过设计阻止地址重复使用。

### **交易隐私策略**

- **多笔交易**：将支付拆分为多笔交易可以模糊交易金额，阻止隐私攻击。
- **避免找零**：选择不需要找零输出的交易可通过破坏找零检测方法来增强隐私。
- **多个找零输出**：如果避免找零不可行，生成多个找零输出仍可提高隐私性。

# **门罗币：匿名的灯塔**

门罗币满足了数字交易中绝对匿名的需求，为隐私设定了高标准。

# **以太坊：Gas 和交易**

### **理解 Gas**

Gas 衡量在以太坊上执行操作所需的计算工作量，以 **gwei** 定价。例如，一笔花费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas 限制、基本费用和激励矿工的小费。用户可以设置最大费用以确保不过度支付，多余部分将退还。

### **执行交易**

以太坊中的交易涉及发送方和接收方，可以是用户或智能合约地址。它们需要支付费用并且必须被挖掘。交易中的基本信息包括接收方、发送方签名、价值、可选数据、gas 限制和费用。值得注意的是，发送方地址是从签名中推断出来的，因此在交易数据中不需要它。

这些实践和机制对于任何希望参与加密货币并优先考虑隐私和安全性的人都是基础性的。

## 参考资料

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
