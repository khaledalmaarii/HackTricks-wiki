<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>


**原始帖子在** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 摘要
脚本输出表明当前用户拥有对两个注册表键的写权限：

- `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
- `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

为了进一步调查RpcEptMapper服务的权限，用户提到使用regedit GUI，并强调了高级安全设置窗口的有效权限选项卡的有用性。该选项卡允许用户检查授予特定用户或组的有效权限，而无需检查单个ACE。

提供的截图显示了低权限lab-user账户的权限。大多数权限是标准的，例如查询值，但有一个权限突出显示：创建子键。这个权限的通用名称是AppendData/AddSubdirectory，这与脚本报告的内容一致。

用户继续解释，这意味着他们不能直接修改某些值，只能创建新的子键。他们展示了一个尝试修改ImagePath值结果访问被拒绝的错误的例子。

然而，他们澄清这不是一个假阳性，并且这里有一个有趣的机会。他们调查了Windows注册表结构，并发现了一个潜在的方法来利用Performance子键，这个子键对于RpcEptMapper服务来说默认是不存在的。这个子键可能允许DLL注册和性能监控，提供了提权的机会。

他们提到他们发现了与Performance子键相关的文档以及如何用于性能监控。这引导他们创建了一个概念验证DLL，并展示了实现所需功能的代码：OpenPerfData、CollectPerfData和ClosePerfData。他们还导出这些函数以供外部使用。

用户演示了使用rundll32测试DLL以确保其按预期工作，成功记录信息。

接下来，他们解释了挑战是如何欺骗RPC Endpoint Mapper服务加载他们的Performance DLL。他们提到，当在PowerShell中查询与性能数据相关的WMI类时，他们观察到他们的日志文件被创建。这允许他们在WMI服务的上下文中执行任意代码，该服务以LOCAL SYSTEM身份运行。这为他们提供了意外和提升的访问权限。

最后，用户强调了这个漏洞的未解释持久性及其潜在影响，这可能扩展到事后利用、横向移动和防病毒/EDR规避。

他们还提到，虽然他们最初通过他们的脚本无意中公开了这个漏洞，但其影响仅限于不受支持的Windows版本（例如，Windows 7 / Server 2008 R2）且需要本地访问。


<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
