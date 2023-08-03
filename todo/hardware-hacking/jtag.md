<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者在**推特**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) 是一个可以与 Raspberry PI 或 Arduino 一起使用的工具，用于查找未知芯片的 JTAG 引脚。\
在 **Arduino** 中，将 **2 到 11 号引脚连接到可能属于 JTAG 的 10 个引脚**。将程序加载到 Arduino 中，它将尝试对所有引脚进行暴力破解，以查找哪些引脚属于 JTAG，并确定每个引脚的位置。\
在 **Raspberry PI** 中，您只能使用 **1 到 6 号引脚**（6 个引脚），因此在测试每个潜在的 JTAG 引脚时速度会较慢。

## Arduino

在 Arduino 中，连接电缆（将引脚 2 到 11 连接到 JTAG 引脚，将 Arduino GND 连接到基板 GND），然后在串行监视器中发送一个 **`h`**（帮助命令），您应该看到帮助信息：

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

配置 **"No line ending" 和 115200baud**。\
发送命令 s 开始扫描：

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

如果连接了 JTAG，您将找到一个或多个以 **FOUND!** 开头的行，指示 JTAG 的引脚。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者在**推特**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
