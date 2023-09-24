# Stego技巧

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 从所有文件中提取数据

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk是一种用于搜索二进制文件（如图像和音频文件）中嵌入的隐藏文件和数据的工具。\
可以使用`apt`安装，[源代码](https://github.com/ReFirmLabs/binwalk)可以在Github上找到。\
**有用的命令**：\
`binwalk file`：显示给定文件中的嵌入数据\
`binwalk -e file`：显示并提取给定文件中的数据\
`binwalk --dd ".*" file`：显示并提取给定文件中的数据

### Foremost <a href="#foremost" id="foremost"></a>

Foremost是一款根据文件头、文件尾和内部数据结构恢复文件的程序。我发现在处理png图像时特别有用。您可以通过更改**/etc/foremost.conf**中的配置文件来选择Foremost将提取的文件。\
可以使用`apt`安装，[源代码](https://github.com/korczis/foremost)可以在Github上找到。\
**有用的命令**：\
`foremost -i file`：从给定文件中提取数据。

### Exiftool <a href="#exiftool" id="exiftool"></a>

有时，重要的内容隐藏在图像或文件的元数据中；exiftool可以非常有帮助地查看文件的元数据。\
您可以从[这里](https://www.sno.phy.queensu.ca/\~phil/exiftool/)获取它。\
**有用的命令**：\
`exiftool file`：显示给定文件的元数据

### Exiv2 <a href="#exiv2" id="exiv2"></a>

类似于exiftool的工具。\
可以使用`apt`安装，[源代码](https://github.com/Exiv2/exiv2)可以在Github上找到。\
[官方网站](http://www.exiv2.org/)\
**有用的命令**：\
`exiv2 file`：显示给定文件的元数据

### File

查看文件的类型

### Strings

从文件中提取字符串。\
有用的命令：\
`strings -n 6 file`：提取长度至少为6的字符串\
`strings -n 6 file | head -n 20`：提取前20个长度至少为6的字符串\
`strings -n 6 file | tail -n 20`：提取最后20个长度至少为6的字符串\
`strings -e s -n 6 file`：提取7位字符串\
`strings -e S -n 6 file`：提取8位字符串\
`strings -e l -n 6 file`：提取16位字符串（小端）\
`strings -e b -n 6 file`：提取16位字符串（大端）\
`strings -e L -n 6 file`：提取32位字符串（小端）\
`strings -e B -n 6 file`：提取32位字符串（大端）

### cmp - 比较

如果您有一些**修改过的**图像/音频/视频，请检查是否可以在互联网上**找到完全相同的原始文件**，然后使用以下命令**比较两个**文件：
```
cmp original.jpg stego.jpg -b -l
```
## 提取隐藏在文本中的数据

### 空格中的隐藏数据

如果你发现一个**文本行**比它应该的要**大**，那么可能有一些**隐藏信息**被包含在**空格**中，使用了不可见字符。󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
要**提取**数据，你可以使用：[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 从图像中提取数据

### identify

[GraphicMagick](https://imagemagick.org/script/download.php)工具用于检查文件是什么类型的图像。还可以检查图像是否损坏。
```
./magick identify -verbose stego.jpg
```
如果图像损坏了，你可以尝试通过向图像添加元数据注释来恢复它（如果损坏非常严重，这种方法可能无效）：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide是一个隐写术程序，可以将数据隐藏在各种图像和音频文件中。它支持以下文件格式：`JPEG，BMP，WAV和AU`。它还可以从其他文件中提取嵌入和加密的数据。\
可以使用`apt`安装它，[源代码](https://github.com/StefanoDeVuono/steghide)可以在Github上找到。\
**有用的命令：**\
`steghide info file`：显示有关文件是否嵌入了数据的信息。\
`steghide extract -sf file [--passphrase password]`：从文件中提取嵌入的数据\[使用密码]

您还可以使用网络从steghide中提取内容：[https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**暴力破解** Steghide：[stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg是一个可以检测png和bmp文件中隐藏数据的工具。\
要安装它：`gem install zsteg`。源代码也可以在[Github](https://github.com/zed-0xff/zsteg)上找到。\
**有用的命令：**\
`zsteg -a file`：对给定的文件运行每种检测方法。\
`zsteg -E file`：使用给定的有效载荷提取数据（例如：zsteg -E b4,bgr,msb,xy name.png）

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

这个工具可以进行各种简单和高级技巧，可以检查文件元数据，创建转换后的图像，暴力破解LSB等等。查看`stegoveritas.py -h`以了解其全部功能。执行`stegoveritas.py stego.jpg`以运行所有检查。

### Stegsolve

有时图像本身隐藏有消息或文本，为了查看它，必须应用颜色滤镜或更改某些颜色级别。虽然您可以使用像GIMP或Photoshop这样的工具来做到这一点，但Stegsolve使得这一过程更加简单。它是一个小型的Java工具，可以在图像上应用许多有用的颜色滤镜；在CTF挑战中，Stegsolve通常是一个真正的时间节省器。\
您可以从[Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)获取它。\
要使用它，只需打开图像并单击`<` `>`按钮。

### FFT

使用快速傅里叶变换（FFT）查找隐藏内容：

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

这是一个通过隐写术在图像和音频文件中编码信息的程序。它可以将数据存储为明文或加密形式。\
在[Github](https://github.com/dhsdshdhk/stegpy)上找到它。

### Pngcheck

获取PNG文件的详细信息（甚至可以找出它实际上是其他类型的文件！）。\
`apt-get install pngcheck`：安装工具\
`pngcheck stego.png`：获取有关PNG的信息

### 值得一提的其他图像工具

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 从音频中提取数据

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg可以用于检查音频文件的完整性，报告有关文件的各种信息以及发现的任何错误。\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg是一个Python3工具，可以使用最低有效位在wav文件中隐藏数据。它还可以搜索并从wav文件中提取数据。\
您可以从[Github](https://github.com/ragibson/Steganography#WavSteg)获取它。\
有用的命令：\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile`：提取到输出文件（只取1个最低有效位）\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile`：提取到输出文件（只取2个最低有效位）

### Deepsound

在声音文件中隐藏和检查使用AES-265加密的信息。从[官方页面](http://jpinsoft.net/deepsound/download.aspx)下载。\
要搜索隐藏的信息，只需运行程序并打开声音文件。如果DeepSound发现任何隐藏的数据，您需要提供密码来解锁它。

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer是一款用于查看和分析音频文件内容的工具。在面对音频隐写挑战时，它非常有帮助；您可以揭示许多其他工具无法检测到的音频文件中隐藏的形状。\
如果遇到困难，请始终检查音频的频谱图。[官方网站](https://www.sonicvisualiser.org/)

### DTMF音调 - 拨号音

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)
## 其他技巧

### 二进制长度平方根 - 二维码

如果你收到的二进制数据的长度是一个整数的平方根，那可能是某种类型的二维码：
```
import math
math.sqrt(2500) #50
```
将二进制的"1"和"0"转换为正确的图像：[https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
读取QR码：[https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### 盲文

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **参考资料**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，从API到Web应用程序和云系统中查找问题。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的公司广告吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
