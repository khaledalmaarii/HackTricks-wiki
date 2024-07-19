{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 固件完整性

**自定义固件和/或编译的二进制文件可以被上传以利用完整性或签名验证缺陷**。可以按照以下步骤进行后门绑定 shell 编译：

1. 可以使用 firmware-mod-kit (FMK) 提取固件。
2. 应识别目标固件架构和字节序。
3. 可以使用 Buildroot 或其他适合环境的方法构建交叉编译器。
4. 可以使用交叉编译器构建后门。
5. 可以将后门复制到提取的固件 /usr/bin 目录。
6. 可以将适当的 QEMU 二进制文件复制到提取的固件 rootfs。
7. 可以使用 chroot 和 QEMU 模拟后门。
8. 可以通过 netcat 访问后门。
9. 应从提取的固件 rootfs 中删除 QEMU 二进制文件。
10. 可以使用 FMK 重新打包修改后的固件。
11. 可以通过使用固件分析工具包 (FAT) 模拟后门固件，并使用 netcat 连接到目标后门 IP 和端口来测试后门固件。

如果已经通过动态分析、引导加载程序操作或硬件安全测试获得了 root shell，可以执行预编译的恶意二进制文件，如植入物或反向 shell。可以使用以下步骤利用自动化有效载荷/植入工具，如 Metasploit 框架和 'msfvenom'：

1. 应识别目标固件架构和字节序。
2. 可以使用 Msfvenom 指定目标有效载荷、攻击者主机 IP、监听端口号、文件类型、架构、平台和输出文件。
3. 可以将有效载荷传输到被攻陷的设备，并确保其具有执行权限。
4. 可以通过启动 msfconsole 并根据有效载荷配置设置来准备 Metasploit 处理传入请求。
5. 可以在被攻陷的设备上执行 meterpreter 反向 shell。
6. 可以监控 meterpreter 会话的开启情况。
7. 可以执行后期利用活动。

如果可能，可以利用启动脚本中的漏洞以在重启后获得对设备的持久访问。这些漏洞在启动脚本引用、[符号链接](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)或依赖于位于不受信任的挂载位置（如用于存储根文件系统外数据的 SD 卡和闪存卷）中的代码时出现。

## 参考文献
* 有关更多信息，请查看 [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
