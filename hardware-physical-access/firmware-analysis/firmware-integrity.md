<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 固件完整性

**自定义固件和/或编译的二进制文件可以上传以利用完整性或签名验证漏洞**。可以按照以下步骤进行后门绑定shell编译：

1. 使用固件修改工具包（FMK）提取固件。
2. 应该识别目标固件架构和字节顺序。
3. 可以使用Buildroot或其他适合环境的方法构建交叉编译器。
4. 使用交叉编译器构建后门。
5. 将后门复制到提取的固件的/usr/bin目录。
6. 将适当的QEMU二进制文件复制到提取的固件rootfs。
7. 使用chroot和QEMU模拟后门。
8. 可以通过netcat访问后门。
9. 应该从提取的固件rootfs中删除QEMU二进制文件。
10. 使用FMK重新打包修改后的固件。
11. 可以通过使用固件分析工具包（FAT）模拟它并使用netcat连接到目标后门IP和端口来测试带后门的固件。

如果已经通过动态分析、引导加载程序操纵或硬件安全测试获得了root shell，则可以执行预编译的恶意二进制文件，如植入物或反向shell。可以使用Metasploit框架和'msfvenom'等自动化负载/植入工具，按照以下步骤利用：

1. 应该识别目标固件架构和字节顺序。
2. 可以使用Msfvenom指定目标负载、攻击者主机IP、监听端口号、文件类型、架构、平台和输出文件。
3. 可以将负载传输到受损设备，并确保它具有执行权限。
4. 可以准备Metasploit来处理传入请求，通过启动msfconsole并根据负载配置设置。
5. 可以在受损设备上执行meterpreter反向shell。
6. 可以监视打开的meterpreter会话。
7. 可以执行后渗透活动。

如果可能的话，可以利用启动脚本中的漏洞来获得对设备在重新启动时的持久访问权限。这些漏洞出现在启动脚本引用、[符号链接](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)，或依赖于位于不受信任挂载位置（如用于存储根文件系统之外数据的SD卡和闪存卷）中的代码时。

## 参考资料
* 欲了解更多信息，请查看[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
