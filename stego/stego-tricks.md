# 隐写术技巧

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **从文件中提取数据**

### **Binwalk**

用于搜索二进制文件中嵌入的隐藏文件和数据的工具。通过`apt`安装，其源代码可在[GitHub](https://github.com/ReFirmLabs/binwalk)上找到。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

根据文件的头部和尾部恢复文件，对于 png 图像非常有用。通过 `apt` 安装，其源代码位于 [GitHub](https://github.com/korczis/foremost)。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

帮助查看文件元数据，可在[这里](https://www.sno.phy.queensu.ca/\~phil/exiftool/)找到。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

类似于exiftool，用于查看元数据。可通过`apt`安装，在[GitHub](https://github.com/Exiv2/exiv2)上找到源代码，并有一个[官方网站](http://www.exiv2.org/)。
```bash
exiv2 file # Shows the metadata
```
### **文件**

确定你正在处理的文件类型。

### **字符串**

从文件中提取可读字符串，使用各种编码设置来过滤输出。
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **比较（cmp）**

用于将修改后的文件与在线找到的原始版本进行比较。
```bash
cmp original.jpg stego.jpg -b -l
```
## **提取文本中的隐藏数据**

### **空格中的隐藏数据**

在看似空白的空格中，可能隐藏着看不见的字符，其中可能包含信息。要提取这些数据，请访问 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)。

## **从图像中提取数据**

### **使用GraphicMagick识别图像细节**

[GraphicMagick](https://imagemagick.org/script/download.php) 用于确定图像文件类型并识别潜在的损坏。执行以下命令来检查一个图像：
```bash
./magick identify -verbose stego.jpg
```
要尝试修复损坏的图像，添加元数据注释可能会有所帮助：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide用于数据隐藏**

Steghide便于在`JPEG、BMP、WAV和AU`文件中隐藏数据，能够嵌入和提取加密数据。使用`apt`进行安装很简单，其[源代码可在GitHub上找到](https://github.com/StefanoDeVuono/steghide)。

**命令:**

* `steghide info file` 用于查看文件是否包含隐藏数据。
* `steghide extract -sf file [--passphrase password]` 用于提取隐藏数据，密码可选。

要进行基于Web的提取，请访问[此网站](https://futureboy.us/stegano/decinput.html)。

**使用Stegcracker进行暴力破解攻击:**

* 若要尝试对Steghide进行密码破解，请使用[stegcracker](https://github.com/Paradoxis/StegCracker.git)如下:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg 用于 PNG 和 BMP 文件**

zsteg 专门用于揭示 PNG 和 BMP 文件中的隐藏数据。通过 `gem install zsteg` 进行安装，其[源代码在 GitHub 上](https://github.com/zed-0xff/zsteg)。

**命令:**

* `zsteg -a file` 在文件上应用所有检测方法。
* `zsteg -E file` 指定用于数据提取的有效载荷。

### **StegoVeritas 和 Stegsolve**

**stegoVeritas** 检查元数据，执行图像转换，并应用 LSB 强制破解等其他功能。使用 `stegoveritas.py -h` 查看所有选项的完整列表，使用 `stegoveritas.py stego.jpg` 执行所有检查。

**Stegsolve** 应用各种颜色滤镜来显示图像中隐藏的文本或消息。可在[GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)上找到。

### **FFT 用于隐藏内容检测**

快速傅里叶变换（FFT）技术可以揭示图像中隐藏的内容。有用的资源包括:

* [EPFL 演示](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [GitHub 上的 FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy 用于音频和图像文件**

Stegpy 允许将信息嵌入图像和音频文件中，支持 PNG、BMP、GIF、WebP 和 WAV 等格式。可在[GitHub](https://github.com/dhsdshdhk/stegpy)上找到。

### **Pngcheck 用于 PNG 文件分析**

要分析 PNG 文件或验证其真实性，请使用:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **图像分析的附加工具**

进一步探索，请访问：

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **从音频中提取数据**

**音频隐写术** 提供了一种在声音文件中隐藏信息的独特方法。不同的工具用于嵌入或检索隐藏内容。

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide 是一个多功能工具，旨在将数据隐藏在 JPEG、BMP、WAV 和 AU 文件中。详细说明请参阅 [stego tricks documentation](stego-tricks.md#steghide)。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

该工具兼容各种格式，包括 PNG、BMP、GIF、WebP 和 WAV。有关更多信息，请参阅 [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)。

### **ffmpeg**

ffmpeg 对于评估音频文件的完整性至关重要，突出显示详细信息并指出任何差异。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg在使用最低有效位策略在WAV文件中隐藏和提取数据方面表现出色。它可在[GitHub](https://github.com/ragibson/Steganography#WavSteg)上找到。命令包括：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound允许使用AES-256在声音文件中加密和检测信息。可以从[官方页面](http://jpinsoft.net/deepsound/download.aspx)下载。

### **Sonic Visualizer**

Sonic Visualizer是一个无价的工具，用于对音频文件进行视觉和分析检查，可以揭示其他方法无法检测到的隐藏元素。访问[官方网站](https://www.sonicvisualiser.org/)了解更多信息。

### **DTMF Tones - 拨号音**

可以通过在线工具如[此DTMF检测器](https://unframework.github.io/dtmf-detect/)和[DialABC](http://dialabc.com/sound/detect/index.html)来检测音频文件中的DTMF音调。

## **其他技术**

### **二进制长度平方根 - QR码**

平方为整数的二进制数据可能代表一个QR码。使用以下代码片段进行检查：
```python
import math
math.sqrt(2500) #50
```
### **盲文翻译**

要进行盲文翻译，请使用[Branah盲文翻译器](https://www.branah.com/braille-translator)这个优秀的资源。

## **参考资料**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**尝试困难安全组**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
