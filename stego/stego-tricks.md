# 隐写技巧

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks上看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您能更快修复它们。Intruder追踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到web应用程序和云系统。[**今天就免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 从所有文件中提取数据

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk是一个用于搜索二进制文件（如图像和音频文件）中嵌入的隐藏文件和数据的工具。\
可以使用`apt`安装，[源代码](https://github.com/ReFirmLabs/binwalk)可以在Github上找到。\
**有用的命令**：\
`binwalk file` : 显示给定文件中的嵌入数据\
`binwalk -e file` : 显示并提取给定文件中的数据\
`binwalk --dd ".*" file` : 显示并提取给定文件中的数据

### Foremost <a href="#foremost" id="foremost"></a>

Foremost是一个根据文件头、尾和内部数据结构恢复文件的程序。我发现它在处理png图像时特别有用。您可以通过更改**/etc/foremost.conf**中的配置文件来选择Foremost将提取的文件。\
可以使用`apt`安装，[源代码](https://github.com/korczis/foremost)可以在Github上找到。\
**有用的命令：**\
`foremost -i file` : 从给定文件中提取数据。

### Exiftool <a href="#exiftool" id="exiftool"></a>

有时，重要的东西隐藏在图像或文件的元数据中；exiftool可以非常有助于查看文件元数据。\
您可以从[这里](https://www.sno.phy.queensu.ca/\~phil/exiftool/)获取它\
**有用的命令：**\
`exiftool file` : 显示给定文件的元数据

### Exiv2 <a href="#exiv2" id="exiv2"></a>

一个类似于exiftool的工具。\
可以使用`apt`安装，[源代码](https://github.com/Exiv2/exiv2)可以在Github上找到。\
[官方网站](http://www.exiv2.org/)\
**有用的命令：**\
`exiv2 file` : 显示给定文件的元数据

### File

检查您拥有的文件类型

### Strings

从文件中提取字符串。\
有用的命令：\
`strings -n 6 file`: 提取最小长度为6的字符串\
`strings -n 6 file | head -n 20`: 提取前20个最小长度为6的字符串\
`strings -n 6 file | tail -n 20`: 提取最后20个最小长度为6的字符串\
`strings -e s -n 6 file`: 提取7位字符串\
`strings -e S -n 6 file`: 提取8位字符串\
`strings -e l -n 6 file`: 提取16位字符串（小端序）\
`strings -e b -n 6 file`: 提取16位字符串（大端序）\
`strings -e L -n 6 file`: 提取32位字符串（小端序）\
`strings -e B -n 6 file`: 提取32位字符串（大端序）

### cmp - 比较

如果您有一些**修改过的**图像/音频/视频，请检查您是否可以在互联网上**找到完全原始的版本**，然后使用以下命令**比较**两个文件：
```
cmp original.jpg stego.jpg -b -l
```
## 提取文本中隐藏的数据

### 隐藏在空格中的数据

如果你发现一个**文本行**比它应该的**更大**，那么一些**隐藏信息**可能被包含在使用不可见字符的**空格**中。󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
要**提取**这些**数据**，你可以使用：[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可以轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 从图像中提取数据

### identify

使用 [GraphicMagick](https://imagemagick.org/script/download.php) 工具来检查文件是什么类型的图像。同时检查图像是否已损坏。
```
./magick identify -verbose stego.jpg
```
如果图像受损，您可能可以通过简单地向其添加元数据注释来恢复它（如果损坏非常严重，这将不起作用）：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide 是一个隐写术程序，可以在各种图像和音频文件中隐藏数据。它支持以下文件格式：`JPEG, BMP, WAV 和 AU`。它也适用于从其他文件中提取嵌入和加密的数据。\
可以使用 `apt` 安装，源代码可以在 Github 上找到。\
**有用的命令：**\
`steghide info file` ：显示文件是否含有嵌入数据的信息。\
`steghide extract -sf file [--passphrase password]` ：从文件中提取嵌入数据\[使用密码]

您也可以使用网络从 steghide 中提取内容：[https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**暴力破解** Steghide：[stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg 是一个工具，可以检测 png 和 bmp 文件中隐藏的数据。\
安装方法：`gem install zsteg`。源代码也可以在 [Github](https://github.com/zed-0xff/zsteg) 上找到。\
**有用的命令：**\
`zsteg -a file` ：在给定文件上运行每个检测方法\
`zsteg -E file` ：使用给定的有效载荷提取数据（例如：zsteg -E b4,bgr,msb,xy name.png）

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

这个工具能够执行各种简单和高级技巧，可以检查文件元数据，创建变换图像，暴力破解 LSB 等等。查看 `stegoveritas.py -h` 以了解其全部功能。执行 `stegoveritas.py stego.jpg` 来运行所有检查。

### Stegsolve

有时图像本身隐藏了消息或文本，为了查看它，必须应用颜色过滤器或更改某些颜色级别。虽然您可以使用 GIMP 或 Photoshop 这样的工具来做到这一点，但 Stegsolve 使其变得更容易。它是一个小型 Java 工具，可以在图像上应用许多有用的颜色过滤器；在 CTF 挑战中，Stegsolve 经常能节省大量时间。\
您可以从 [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) 上获取它。\
使用时，只需打开图像并点击 `<` `>` 按钮。

### FFT

使用快速傅里叶变换找到隐藏内容：

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

一个通过隐写术在图像和音频文件中编码信息的程序。它可以将数据存储为明文或加密。\
在 [Github](https://github.com/dhsdshdhk/stegpy) 上找到它。

### Pngcheck

获取 PNG 文件的详细信息（甚至发现它实际上是其他东西！）。\
`apt-get install pngcheck`：安装工具\
`pngcheck stego.png` ：获取 PNG 的信息

### 其他值得一提的图像工具

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [https://github.com/resurrecting-open-source-projects/outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [https://www.openstego.com/](https://www.openstego.com/)
* [https://diit.sourceforge.net/](https://diit.sourceforge.net/)

## 从音频中提取数据

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg 可用于检查音频文件的完整性，报告有关文件的各种信息以及它发现的任何错误。\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg 是一个 Python3 工具，可以使用最不显著位在 wav 文件中隐藏数据。它还可以搜索 wav 文件中的数据，并从中提取数据。\
您可以从 [Github](https://github.com/ragibson/Steganography#WavSteg) 上获取它。\
有用的命令：\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` ：提取到输出文件（只取 1 lsb）\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` ：提取到输出文件（只取 2 lsb）

### Deepsound

在声音文件中隐藏信息，并检查是否有使用 AES-265 加密的信息。从[官方页面](http://jpinsoft.net/deepsound/download.aspx)下载。\
要搜索隐藏的信息，只需运行程序并打开声音文件。如果 DeepSound 发现任何隐藏的数据，您将需要提供密码才能解锁它。

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer 是一个用于查看和分析音频文件内容的工具。在面对音频隐写术挑战时，它可以非常有帮助；您可以揭示许多其他工具无法检测到的音频文件中隐藏的形状。\
如果您遇到困难，始终检查音频的频谱图。[官方网站](https://www.sonicvisualiser.org/)

### DTMF 音调 - 拨号音

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 其他技巧

### 二进制长度 SQRT - 二维码

如果您收到的二进制数据具有整数的 SQRT 长度，它可能是某种二维码：
```
import math
math.sqrt(2500) #50
```
要将二进制的"1"和"0"转换为适当的图像：[https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
要读取QR码：[https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### 盲文

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **参考资料**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便您能更快修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到web应用程序和云系统。今天就[**免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS hacking！</strong></summary>

其他支持HackTricks的方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的hacking技巧。

</details>
