<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


**原始帖子链接** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 摘要

发现当前用户可以写入两个注册表键：

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

建议使用**regedit GUI**检查**RpcEptMapper**服务的权限，特别是**高级安全设置**窗口的**有效权限**选项卡。这种方法可以评估授予特定用户或组的权限，而无需逐个检查每个访问控制项（ACE）。

屏幕截图显示了分配给低权限用户的权限，其中**创建子键**权限引人注目。这个权限，也称为**AppendData/AddSubdirectory**，与脚本的发现相对应。

注意到无法直接修改某些值，但可以创建新的子键。举例说明了尝试更改**ImagePath**值的情况，结果显示为访问被拒绝消息。

尽管存在这些限制，但通过利用**RpcEptMapper**服务的注册表结构中的**Performance**子键的可能性，发现了特权升级的可能性，这是默认情况下不存在的子键。这可以实现DLL注册和性能监控。

查阅关于**Performance**子键及其用于性能监控的文档，导致开发了一个概念验证DLL。通过**rundll32**测试了这个DLL，演示了**OpenPerfData**、**CollectPerfData**和**ClosePerfData**函数的实现，确认其操作成功。

目标是强制**RPC端点映射器服务**加载精心制作的性能DLL。观察表明，通过PowerShell执行与性能数据相关的WMI类查询会创建一个日志文件，从而在**LOCAL SYSTEM**上下文下执行任意代码，从而授予提升的权限。

强调了此漏洞的持久性和潜在影响，突出了它对后期利用策略、横向移动和规避防病毒/EDR系统的相关性。

尽管最初是通过脚本无意中披露了此漏洞，但强调了其利用受限于过时的Windows版本（例如**Windows 7 / Server 2008 R2**）并且需要本地访问。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
