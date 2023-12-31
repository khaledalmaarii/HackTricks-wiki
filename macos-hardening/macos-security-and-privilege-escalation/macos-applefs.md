# macOS AppleFS

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## Apple专有文件系统 (APFS)

APFS，即Apple文件系统，是由苹果公司开发的现代文件系统，旨在取代旧的分层文件系统加强版（HFS+），重点在于**提高性能、安全性和效率**。

APFS的一些显著特点包括：

1. **空间共享**：APFS允许多个卷在单个物理设备上**共享相同的底层可用存储空间**。这使得空间利用更加高效，因为卷可以动态地增长和缩小，无需手动调整大小或重新分区。
2. 这意味着，与传统的文件磁盘分区相比，**在APFS中不同的分区（卷）共享所有磁盘空间**，而常规分区通常具有固定大小。
3. **快照**：APFS支持**创建快照**，这些快照是文件系统的**只读**、时间点实例。快照使得备份高效且系统回滚容易，因为它们消耗的额外存储空间很少，且可以快速创建或还原。
4. **克隆**：APFS可以**创建文件或目录克隆，这些克隆与原始文件共享相同的存储空间**，直到克隆或原始文件被修改。这个特性提供了一种高效的方式来创建文件或目录的副本，而不需要复制存储空间。
5. **加密**：APFS **原生支持全盘加密**，以及按文件和按目录加密，增强了不同使用场景下的数据安全性。
6. **崩溃保护**：APFS使用**写时复制元数据方案确保文件系统的一致性**，即使在突然断电或系统崩溃的情况下，也能减少数据损坏的风险。

总的来说，APFS为苹果设备提供了一个更现代、灵活和高效的文件系统，重点在于提高性能、可靠性和安全性。
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 卷挂载在 **`/System/Volumes/Data`** （您可以通过 `diskutil apfs list` 检查这一点）。

firmlinks 的列表可以在 **`/usr/share/firmlinks`** 文件中找到。
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
在**左边**，是**系统卷**上的目录路径，在**右边**，是它在**数据卷**上映射的目录路径。所以，`/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
