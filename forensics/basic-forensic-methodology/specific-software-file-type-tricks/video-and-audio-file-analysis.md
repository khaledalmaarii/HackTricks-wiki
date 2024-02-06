<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


来自：[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

与图像文件格式一样，音频和视频文件的欺骗在CTF取证挑战中是一个常见主题，不是因为在现实世界中会以这种方式进行黑客活动或隐藏数据，而只是因为音频和视频很有趣。与图像文件格式一样，隐写术可能被用来嵌入内容数据中的秘密消息，您应该知道要检查文件元数据区域以获取线索。您的第一步应该是使用[mediainfo](https://mediaarea.net/en/MediaInfo)工具（或`exiftool`）查看内容类型并查看其元数据。

[Audacity](http://www.audacityteam.org/)是首选的开源音频文件和波形查看工具。CTF挑战的作者喜欢将文本编码到音频波形中，您可以使用频谱图查看（尽管专门工具[Sonic Visualiser](http://www.sonicvisualiser.org/)在这种特定任务中更好）。Audacity还可以让您放慢、倒放和进行其他操作，这可能会揭示隐藏的消息，如果您怀疑存在隐藏消息（如果您听到杂音、干扰或静音）。[Sox](http://sox.sourceforge.net/)是另一个用于转换和操作音频文件的有用的命令行工具。

检查最低有效位（LSB）以查找秘密消息也很常见。大多数音频和视频媒体格式使用离散（固定大小）的“块”，以便可以流式传输；这些块的LSB是一个常见的地方，可以在不明显影响文件的情况下夹带一些数据。

有时，消息可能被编码到音频中作为[DTMF音调](http://dialabc.com/sound/detect/index.html)或莫尔斯电码。对于这些情况，请尝试使用[multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)进行解码。

视频文件格式是容器格式，包含了分别用于回放的音频和视频流。对于分析和操作视频文件格式，建议使用[FFmpeg](http://ffmpeg.org/)。`ffmpeg -i`提供了对文件内容的初始分析。它还可以解复用或回放内容流。通过[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)可以将FFmpeg的功能暴露给Python使用。


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
