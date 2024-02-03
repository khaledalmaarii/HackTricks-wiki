<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

# 固件完整性

**可以上传自定义固件和/或编译后的二进制文件来利用完整性或签名验证漏洞**。可以按照以下步骤进行后门绑定 shell 编译：

1. 可以使用 firmware-mod-kit (FMK) 提取固件。
2. 应识别目标固件架构和字节序。
3. 可以使用 Buildroot 或其他适合的方法为环境构建交叉编译器。
4. 可以使用交叉编译器构建后门。
5. 可以将后门复制到提取的固件 /usr/bin 目录。
6. 可以将适当的 QEMU 二进制文件复制到提取的固件 rootfs。
7. 可以使用 chroot 和 QEMU 模拟后门。
8. 可以通过 netcat 访问后门。
9. 应从提取的固件 rootfs 中移除 QEMU 二进制文件。
10. 可以使用 FMK 重新打包修改后的固件。
11. 可以通过使用固件分析工具包 (FAT) 模拟后门固件并使用 netcat 连接到目标后门 IP 和端口来测试后门固件。

如果已经通过动态分析、引导程序操作或硬件安全测试获得了 root shell，则可以执行预编译的恶意二进制文件，如植入物或反向 shell。可以使用以下步骤利用 Metasploit 框架和 'msfvenom' 等自动化 payload/植入工具：

1. 应识别目标固件架构和字节序。
2. Msfvenom 可用于指定目标 payload、攻击者主机 IP、监听端口号、文件类型、架构、平台和输出文件。
3. 可以将 payload 传输到受损设备，并确保它具有执行权限。
4. Metasploit 可以通过启动 msfconsole 并根据 payload 配置设置来准备处理传入请求。
5. 可以在受损设备上执行 meterpreter 反向 shell。
6. 可以监控 meterpreter 会话的开启情况。
7. 可以执行后期利用活动。

如果可能，可以利用启动脚本中的漏洞来获得对设备的持久访问权限，跨重启。当启动脚本引用、[符号链接](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)或依赖于位于不受信任的挂载位置（如用于存储根文件系统之外数据的 SD 卡和闪存卷）中的代码时，就会出现这些漏洞。

# 参考资料
* 欲了解更多信息，请查看 [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
