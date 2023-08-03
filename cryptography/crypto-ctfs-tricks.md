# Crypto CTFs 技巧

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧。**

</details>

## 在线哈希数据库

* _**谷歌搜索**_
* [http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240](http://hashtoolkit.com/reverse-hash?hash=4d186321c1a7f0f354b297e8914ab240)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com)
* [https://crackstation.net/](https://crackstation.net)
* [https://md5decrypt.net/](https://md5decrypt.net)
* [https://www.onlinehashcrack.com](https://www.onlinehashcrack.com)
* [https://gpuhash.me/](https://gpuhash.me)
* [https://hashes.org/search.php](https://hashes.org/search.php)
* [https://www.cmd5.org/](https://www.cmd5.org)
* [https://hashkiller.co.uk/Cracker/MD5](https://hashkiller.co.uk/Cracker/MD5)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)

## 魔术自动求解器

* [**https://github.com/Ciphey/Ciphey**](https://github.com/Ciphey/Ciphey)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) (魔术模块)
* [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)
* [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking)

## 编码器

大多数编码数据可以使用以下两个资源进行解码：

* [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### 替换自动求解器

* [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)
* [https://quipqiup.com/](https://quipqiup.com) - 非常好！

#### 凯撒密码 - ROTx 自动求解器

* [https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)

#### Atbash 密码

* [http://rumkin.com/tools/cipher/atbash.php](http://rumkin.com/tools/cipher/atbash.php)

### 基础编码自动求解器

使用以下链接检查所有这些基础编码：[https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)

* **Ascii85**
* `BQ%]q@psCd@rH0l`
* **Base26** \[_A-Z_]
* `BQEKGAHRJKHQMVZGKUXNT`
* **Base32** \[_A-Z2-7=_]
* `NBXWYYLDMFZGCY3PNRQQ====`
* **Zbase32** \[_ybndrfg8ejkmcpqxot1uwisza345h769_]
* `pbzsaamdcf3gna5xptoo====`
* **Base32 Geohash** \[_0-9b-hjkmnp-z_]
* `e1rqssc3d5t62svgejhh====`
* **Base32 Crockford** \[_0-9A-HJKMNP-TV-Z_]
* `D1QPRRB3C5S62RVFDHGG====`
* **Base32 Extended Hexadecimal** \[_0-9A-V_]
* `D1NMOOB3C5P62ORFDHGG====`
* **Base45** \[_0-9A-Z $%\*+-./:_]
* `59DPVDGPCVKEUPCPVD`
* **Base58 (bitcoin)** \[_1-9A-HJ-NP-Za-km-z_]
* `2yJiRg5BF9gmsU6AC`
* **Base58 (flickr)** \[_1-9a-km-zA-HJ-NP-Z_]
* `2YiHqF5bf9FLSt6ac`
* **Base58 (ripple)** \[_rpshnaf39wBUDNEGHJKLM4PQ-T7V-Z2b-eCg65jkm8oFqi1tuvAxyz_]
* `pyJ5RgnBE9gm17awU`
* **Base62** \[_0-9A-Za-z_]
* `g2AextRZpBKRBzQ9`
* **Base64** \[_A-Za-z0-9+/=_]
* `aG9sYWNhcmFjb2xh`
* **Base67** \[_A-Za-z0-9-_.!\~\_]
* `NI9JKX0cSUdqhr!p`
* **Base85 (Ascii85)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `BQ%]q@psCd@rH0l`
* **Base85 (Adobe)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `<~BQ%]q@psCd@rH0l~>`
* **Base85 (IPv6 or RFC1924)** \[_0-9A-Za-z!#$%&()\*+-;<=>?@^_\`{|}\~\_]
* `Xm4y`V\_|Y(V{dF>\`
* **Base85 (xbtoa)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `xbtoa Begin\nBQ%]q@psCd@rH0l\nxbtoa End N 12 c E 1a S 4e6 R 6991d`
* **Base85 (XML)** \[_0-9A-Za-y!#$()\*+,-./:;=?@^\`{|}\~z\__]
* `Xm4y|V{~Y+V}dF?`
* **Base91** \[_A-Za-z0-9!#$%&()\*+,./:;<=>?@\[]^\_\`{|}\~"_]
* `frDg[*jNN!7&BQM`
* **Base100** \[]
* `👟👦👣👘👚👘👩👘👚👦👣👘`
* **Base122** \[]
* `4F ˂r0Xmvc`
* **ATOM-128** \[_/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC_]
* `MIc3KiXa+Ihz+lrXMIc3KbCC`
* **HAZZ15** \[_HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5_]
* `DmPsv8J7qrlKEoY7`
* **MEGAN35** \[_3G-Ub=c-pW-Z/12+406-9Vaq-zA-F5_]
* `kLD8iwKsigSalLJ5`
* **ZONG22** \[_ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2_]
* `ayRiIo1gpO+uUc7g`
* **ESAB46** \[]
* `3sHcL2NR8WrT7mhR`
* **MEGAN45** \[]
* `kLD8igSXm2KZlwrX`
* **TIGO3FX** \[]
* `7AP9mIzdmltYmIP9mWXX`
* **TRIPO5** \[]
* `UE9vSbnBW6psVzxB`
* **FERON74** \[]
* `PbGkNudxCzaKBm0x`
* **GILA7** \[]
* `D+nkv8C1qIKMErY1`
* **Citrix CTX1** \[]
* `MNGIKCAHMOGLKPAKMMGJKNAINPHKLOBLNNHILCBHNOHLLPBK`

[http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html](http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html) - 404 Dead: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### HackerizeXS \[_╫Λ↻├☰┏_]
```
╫☐↑Λ↻Λ┏Λ↻☐↑Λ
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html) - 404 页面不存在: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### 摩尔斯密码
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html](http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html) - 404 页面不存在: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### UU编码器
```
begin 644 webutils_pl
M2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(
M3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/
F3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$$`
`
end
```
* [http://www.webutils.pl/index.php?idx=uu](http://www.webutils.pl/index.php?idx=uu)

### XX编码器
```
begin 644 webutils_pl
hG2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236
5Hol-G2xAEE++
end
```
* [www.webutils.pl/index.php?idx=xx](https://github.com/carlospolop/hacktricks/tree/bf578e4c5a955b4f6cdbe67eb4a543e16a3f848d/crypto/www.webutils.pl/index.php?idx=xx)

### YEncoder

### YEncoder

YEncoder是一种简单的编码技术，用于将二进制数据转换为可打印字符。它通常用于绕过防火墙或过滤器，以便在网络上传输二进制数据。

YEncoder的工作原理如下：

1. 将每个字节拆分为两个4位的字节。
2. 将每个4位的字节转换为可打印字符。
3. 将所有转换后的字符连接起来，形成编码后的字符串。

要解码YEncoder编码的数据，只需按照相反的步骤进行操作即可。

在CTF比赛中，YEncoder常常用于隐藏敏感信息或绕过简单的过滤器。因此，了解如何使用YEncoder进行编码和解码是非常有用的。
```
=ybegin line=128 size=28 name=webutils_pl
ryvkryvkryvkryvkryvkryvkryvk
=yend size=28 crc32=35834c86
```
* [http://www.webutils.pl/index.php?idx=yenc](http://www.webutils.pl/index.php?idx=yenc)

### BinHex

BinHex是一种将二进制数据转换为可打印ASCII字符的编码方法。它通常用于在电子邮件或其他文本传输中传输二进制文件。BinHex编码使用16进制数字和字母来表示二进制数据。要解码BinHex编码的文件，可以使用专门的解码工具或在线解码服务。
```
(This file must be converted with BinHex 4.0)
:#hGPBR9dD@acAh"X!$mr2cmr2cmr!!!!!!!8!!!!!-ka5%p-38K26%&)6da"5%p
-38K26%'d9J!!:
```
* [http://www.webutils.pl/index.php?idx=binhex](http://www.webutils.pl/index.php?idx=binhex)

### ASCII85

ASCII85是一种编码方案，用于将二进制数据转换为可打印的ASCII字符。它类似于Base64编码，但具有更高的密度。在CTF比赛中，你可能会遇到使用ASCII85编码的加密数据。要解码ASCII85编码，你可以使用在线工具或编写自己的解码脚本。
```
<~85DoF85DoF85DoF85DoF85DoF85DoF~>
```
* [http://www.webutils.pl/index.php?idx=ascii85](http://www.webutils.pl/index.php?idx=ascii85)

### Dvorak键盘
```
drnajapajrna
```
* [https://www.geocachingtoolbox.com/index.php?lang=zh\&page=dvorakKeyboard](https://www.geocachingtoolbox.com/index.php?lang=zh\&page=dvorakKeyboard)

### A1Z26

字母对应的数字值
```
8 15 12 1 3 1 18 1 3 15 12 1
```
### 仿射密码编码

将字母转换为数字 `(ax+b)%26`（其中 _a_ 和 _b_ 是密钥，_x_ 是字母），然后将结果转换回字母
```
krodfdudfrod
```
### 短信代码

**多键输入法** [通过对应的按键代码在手机[键盘](https://www.dcode.fr/phone-keypad-cipher)上重复数字来替换字母](https://www.dcode.fr/word-letter-change)（在编写短信时使用此模式）。\
例如：2=A，22=B，222=C，3=D...\
您可以通过看到\*\*多个重复的数字\*\*来识别此代码。

您可以在以下网址解码此代码：[https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher)

### 培根密码

将每个字母替换为4个A或B（或1和0）。
```
00111 01101 01010 00000 00010 00000 10000 00000 00010 01101 01010 00000
AABBB ABBAB ABABA AAAAA AAABA AAAAA BAAAA AAAAA AAABA ABBAB ABABA AAAAA
```
### 符文

![](../.gitbook/assets/runes.jpg)

## 压缩

**Raw Deflate** 和 **Raw Inflate**（你可以在 Cyberchef 中找到）可以在没有头部的情况下压缩和解压数据。

## 简单加密

### 异或 - 自动求解器

* [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### Bifid

需要一个关键词
```
fgaargaamnlunesuneoa
```
### 维吉尼亚密码

需要一个关键字
```
wodsyoidrods
```
* [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)
* [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
* [https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## 强加密

### Fernet

2个base64字符串（令牌和密钥）
```
Token:
gAAAAABWC9P7-9RsxTz_dwxh9-O2VUB7Ih8UCQL1_Zk4suxnkCvb26Ie4i8HSUJ4caHZuiNtjLl3qfmCv_fS3_VpjL7HxCz7_Q==

Key:
-s6eI5hyNh8liH7Gq0urPC-vzPgNnxauKvRO4g03oYI=
```
* [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode)

### Samir秘密分享

一个秘密被分成X个部分，要恢复它，你需要Y个部分（_Y <=X_）。
```
8019f8fa5879aa3e07858d08308dc1a8b45
80223035713295bddf0b0bd1b10a5340b89
803bc8cf294b3f83d88e86d9818792e80cd
```
### OpenSSL暴力破解

* [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
* [https://github.com/carlospolop/easy\_BFopensslCTF](https://github.com/carlospolop/easy\_BFopensslCTF)

## 工具

* [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* [https://github.com/lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom)
* [https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
