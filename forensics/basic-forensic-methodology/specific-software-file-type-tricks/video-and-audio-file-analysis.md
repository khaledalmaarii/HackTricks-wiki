<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


来自：[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

与图像文件格式一样，音频和视频文件的欺骗在CTF取证挑战中是一个常见的主题，这并不是因为在现实世界中会以这种方式进行黑客攻击或数据隐藏，而只是因为音频和视频很有趣。与图像文件格式一样，可能会使用隐写术将秘密消息嵌入内容数据中，您应该知道要检查文件元数据区域以获取线索。您的第一步应该是使用[mediainfo](https://mediaarea.net/en/MediaInfo)工具（或`exiftool`）查看并识别内容类型，并查看其元数据。

[Audacity](http://www.audacityteam.org/)是首选的开源音频文件和波形查看工具。CTF挑战的作者喜欢将文本编码到音频波形中，您可以使用频谱图视图来查看（尽管专门的工具[Sonic Visualiser](http://www.sonicvisualiser.org/)在这个任务中更好）。Audacity还可以让您放慢、倒放和进行其他操作，如果您怀疑存在隐藏的消息，这些操作可能会揭示出来（如果您听到了杂音、干扰或静音）。[Sox](http://sox.sourceforge.net/)是另一个有用的命令行工具，用于转换和操作音频文件。

检查最低有效位（LSB）以查找秘密消息也很常见。大多数音频和视频媒体格式使用离散（固定大小）的“块”以便进行流式传输；这些块的LSB是一个常见的地方，可以在不明显影响文件的情况下走私一些数据。

有时，消息可能会被编码为音频中的[DTMF音调](http://dialabc.com/sound/detect/index.html)或莫尔斯电码。对于这些情况，尝试使用[multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)来解码它们。

视频文件格式是容器格式，包含了音频和视频的分离流，这些流被复用在一起进行播放。对于分析和操作视频文件格式，推荐使用[FFmpeg](http://ffmpeg.org/)。`ffmpeg -i`可以对文件内容进行初始分析。它还可以解复用或播放内容流。通过使用[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)，可以将FFmpeg的功能暴露给Python。

</details>
