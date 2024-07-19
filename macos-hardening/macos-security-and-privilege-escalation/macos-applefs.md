# macOS AppleFS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple 专有文件系统 (APFS)

**Apple 文件系统 (APFS)** 是一种现代文件系统，旨在取代层次文件系统 Plus (HFS+)。其开发是为了满足对 **提高性能、安全性和效率** 的需求。

APFS 的一些显著特性包括：

1. **空间共享**：APFS 允许多个卷 **共享单个物理设备上的相同底层可用存储**。这使得空间利用更加高效，因为卷可以动态增长和缩小，而无需手动调整大小或重新分区。
1. 这意味着，与传统的文件磁盘分区相比，**在 APFS 中不同的分区（卷）共享所有磁盘空间**，而常规分区通常具有固定大小。
2. **快照**：APFS 支持 **创建快照**，这些快照是 **只读的**、时间点的文件系统实例。快照使得高效备份和轻松系统回滚成为可能，因为它们消耗的额外存储极少，并且可以快速创建或恢复。
3. **克隆**：APFS 可以 **创建与原始文件共享相同存储的文件或目录克隆**，直到克隆或原始文件被修改。此功能提供了一种高效的方式来创建文件或目录的副本，而无需重复存储空间。
4. **加密**：APFS **原生支持全盘加密**以及逐文件和逐目录加密，增强了不同用例下的数据安全性。
5. **崩溃保护**：APFS 使用 **写时复制元数据方案，确保文件系统一致性**，即使在突然断电或系统崩溃的情况下，也能减少数据损坏的风险。

总体而言，APFS 为 Apple 设备提供了一种更现代、更灵活和更高效的文件系统，重点在于提高性能、可靠性和安全性。
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 卷挂载在 **`/System/Volumes/Data`**（您可以使用 `diskutil apfs list` 检查这一点）。

firmlinks 的列表可以在 **`/usr/share/firmlinks`** 文件中找到。
```bash
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
