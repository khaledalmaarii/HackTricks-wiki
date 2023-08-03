<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


从[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)复制

在修改设备启动和引导加载程序（如U-boot）时，请尝试以下操作：

* 尝试通过在启动过程中按下"0"、空格或其他已识别的“魔术代码”来访问引导加载程序解释器 shell。
* 修改配置以执行shell命令，例如在引导参数的末尾添加"`init=/bin/sh`"。
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* 设置一个tftp服务器，从工作站本地加载图像。确保设备具有网络访问权限。
* `#setenv ipaddr 192.168.2.2 #设备的本地IP`
* `#setenv serverip 192.168.2.1 #tftp服务器的IP`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #检查是否有网络访问权限`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddr接受两个参数：要加载文件的地址和TFTP服务器上图像的文件名`
* 使用`ubootwrite.py`写入uboot镜像并推送修改后的固件以获取root权限
* 检查是否启用了调试功能，例如：
* 详细日志记录
* 加载任意内核
* 从不受信任的来源引导
* \*谨慎使用：将一个引脚接地，观察设备的引导序列，在内核解压缩之前，将接地的引脚短接/连接到SPI闪存芯片上的数据引脚（DO）
* \*谨慎使用：将一个引脚接地，观察设备的引导序列，在内核解压缩之前，将接地的引脚短接/连接到NAND闪存芯片的8号和9号引脚上，此时U-boot正在解压缩UBI镜像
* \*在短接引脚之前，请查阅NAND闪存芯片的数据手册
* 配置一个恶意参数的恶意DHCP服务器，供设备在PXE引导期间摄取
* 使用Metasploit的（MSF）DHCP辅助服务器，并使用命令注入命令修改“`FILENAME`”参数，例如`‘a";/bin/sh;#’`，以测试设备启动过程的输入验证。

\*硬件安全测试
