# macOS AppleFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Apple专有文件系统（APFS）

APFS，即Apple文件系统，是由Apple Inc.开发的现代文件系统，旨在取代较旧的分层文件系统Plus（HFS+），并强调**改进性能、安全性和效率**。

APFS的一些显著特点包括：

1. **空间共享**：APFS允许多个卷在单个物理设备上**共享相同的底层可用存储空间**。这使得卷可以动态增长和收缩，无需手动调整大小或重新分区，从而实现更高效的空间利用。
1. 这意味着，与文件磁盘中的传统分区相比，**在APFS中，不同的分区（卷）共享整个磁盘空间**，而常规分区通常具有固定大小。
2. **快照**：APFS支持**创建快照**，这些快照是文件系统的**只读**、时间点实例。快照可以实现高效的备份和简单的系统回滚，因为它们占用的额外存储空间很小，可以快速创建或还原。
3. **克隆**：APFS可以**创建与原始文件或目录共享相同存储空间的文件或目录克隆**，直到克隆或原始文件被修改为止。这个功能提供了一种在不复制存储空间的情况下创建文件或目录副本的高效方式。
4. **加密**：APFS**原生支持全盘加密**以及每个文件和每个目录的加密，增强了不同用例下的数据安全性。
5. **崩溃保护**：APFS使用**写时复制元数据方案**，即使在突然断电或系统崩溃的情况下，也能确保文件系统的一致性，减少数据损坏的风险。

总体而言，APFS为Apple设备提供了一个更现代、灵活和高效的文件系统，注重提高性能、可靠性和安全性。
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 卷被挂载在 **`/System/Volumes/Data`**（您可以使用 `diskutil apfs list` 命令来检查）。

firmlinks 的列表可以在 **`/usr/share/firmlinks`** 文件中找到。
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
在**左侧**是**系统卷**上的目录路径，在**右侧**是它在**数据卷**上映射的目录路径。因此，`/library` --> `/system/Volumes/data/library`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
