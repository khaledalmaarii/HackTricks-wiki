# क्रिप्टो सीटीएफएस ट्रिक्स

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## ऑनलाइन हैश डेटाबेस

* _**गूगल पर खोजें**_
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

## जादू ऑटोसॉल्वर्स

* [**https://github.com/Ciphey/Ciphey**](https://github.com/Ciphey/Ciphey)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) (जादू मॉड्यूल)
* [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)
* [https://www.boxentriq.com/code-breaking](https://www.boxentriq.com/code-breaking)

## एन्कोडर्स

अधिकांश एन्कोडेड डेटा को इन 2 स्रोतों से डीकोड किया जा सकता है:

* [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### सब्स्टीट्यूशन ऑटोसॉल्वर्स

* [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)
* [https://quipqiup.com/](https://quipqiup.com) - बहुत अच्छा !

#### सीज़र - ROTx ऑटोसॉल्वर्स

* [https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)

#### अटबाश साइफर

* [http://rumkin.com/tools/cipher/atbash.php](http://rumkin.com/tools/cipher/atbash.php)

### बेस एन्कोडिंग्स ऑटोसॉल्वर

इन सभी बेस को चेक करें: [https://github.com/dhondta/python-codext](https://github.com/dhondta/python-codext)

* **एस्की85**
* `BQ%]q@psCd@rH0l`
* **बेस26** \[_A-Z_]
* `BQEKGAHRJKHQMVZGKUXNT`
* **बेस32** \[_A-Z2-7=_]
* `NBXWYYLDMFZGCY3PNRQQ====`
* **Zबेस32** \[_ybndrfg8ejkmcpqxot1uwisza345h769_]
* `pbzsaamdcf3gna5xptoo====`
* **बेस32 जियोहैश** \[_0-9b-hjkmnp-z_]
* `e1rqssc3d5t62svgejhh====`
* **बेस32 क्रॉकफोर्ड** \[_0-9A-HJKMNP-TV-Z_]
* `D1QPRRB3C5S62RVFDHGG====`
* **बेस32 विस्तारित हेक्साडेसिमल** \[_0-9A-V_]
* `D1NMOOB3C5P62ORFDHGG====`
* **बेस45** \[_0-9A-Z $%\*+-./:_]
* `59DPVDGPCVKEUPCPVD`
* **बेस58 (बिटकॉइन)** \[_1-9A-HJ-NP-Za-km-z_]
* `2yJiRg5BF9gmsU6AC`
* **बेस58 (फ्लिकर)** \[_1-9a-km-zA-HJ-NP-Z_]
* `2YiHqF5bf9FLSt6ac`
* **बेस58 (रिप्पल)** \[_rpshnaf39wBUDNEGHJKLM4PQ-T7V-Z2b-eCg65jkm8oFqi1tuvAxyz_]
* `pyJ5RgnBE9gm17awU`
* **बेस62** \[_0-9A-Za-z_]
* `g2AextRZpBKRBzQ9`
* **बेस64** \[_A-Za-z0-9+/=_]
* `aG9sYWNhcmFjb2xh`
* **बेस67** \[_A-Za-z0-9-_.!\~\_]
* `NI9JKX0cSUdqhr!p`
* **बेस85 (एस्की85)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `BQ%]q@psCd@rH0l`
* **बेस85 (एडोबी)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `<~BQ%]q@psCd@rH0l~>`
* **बेस85 (IPv6 या RFC1924)** \[_0-9A-Za-z!#$%&()\*+-;<=>?@^_\`{|}\~\_]
* `Xm4y`V\_|Y(V{dF>\`
* **बेस85 (xbtoa)** \[_!"#$%&'()\*+,-./0-9:;<=>?@A-Z\[\\]^\_\`a-u_]
* `xbtoa Begin\nBQ%]q@psCd@rH0l\nxbtoa End N 12 c E 1a S 4e6 R 6991d`
* **बेस85 (XML)** \[_0-9A-Za-y!#$()\*+,-./:;=?@^\`{|}\~z\__]
* `Xm4y|V{~Y+V}dF?`
* **बेस91** \[_A-Za-z0-9!#$%&()\*+,./:;<=>?@\[]^\_\`{|}\~"_]
* `frDg[*jNN!7&BQM`
* **बेस100** \[]
* `👟👦👣👘👚👘👩👘👚👦👣👘`
* **बेस122** \[]
* `4F ˂r0Xmvc`
* **एटम-128** \[_/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC_]
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

[http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html](http://k4.cba.pl/dw/crypo/tools/eng\_atom128c.html) - 404 डेड: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### हैकराइज़ एक्सएस \[_╫Λ↻├☰┏_]
```
╫☐↑Λ↻Λ┏Λ↻☐↑Λ
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html) - 404 मरा हुआ: [https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html](https://web.archive.org/web/20190228181208/http://k4.cba.pl/dw/crypo/tools/eng\_hackerize.html)

### मोर्स
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
* [http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html](http://k4.cba.pl/dw/crypo/tools/eng\_morse-encode.html) - 404 मरा हुआ: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### UUencoder
```
begin 644 webutils_pl
M2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(
M3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/
F3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$%(3TQ!2$],04A/3$$`
`
end
```
* [http://www.webutils.pl/index.php?idx=uu](http://www.webutils.pl/index.php?idx=uu)

### XXEncoder
```
begin 644 webutils_pl
hG2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236Hol-G2xAEIVDH236
5Hol-G2xAEE++
end
```
* [www.webutils.pl/index.php?idx=xx](https://github.com/carlospolop/hacktricks/tree/bf578e4c5a955b4f6cdbe67eb4a543e16a3f848d/crypto/www.webutils.pl/index.php?idx=xx)

### YEncoder
```
=ybegin line=128 size=28 name=webutils_pl
ryvkryvkryvkryvkryvkryvkryvk
=yend size=28 crc32=35834c86
```
* [http://www.webutils.pl/index.php?idx=yenc](http://www.webutils.pl/index.php?idx=yenc)

### बिनहेक्स
```
(This file must be converted with BinHex 4.0)
:#hGPBR9dD@acAh"X!$mr2cmr2cmr!!!!!!!8!!!!!-ka5%p-38K26%&)6da"5%p
-38K26%'d9J!!:
```
* [http://www.webutils.pl/index.php?idx=binhex](http://www.webutils.pl/index.php?idx=binhex)

### ASCII85
```
<~85DoF85DoF85DoF85DoF85DoF85DoF~>
```
* [http://www.webutils.pl/index.php?idx=ascii85](http://www.webutils.pl/index.php?idx=ascii85)

### ड्वोराक कीबोर्ड
```
drnajapajrna
```
* [https://www.geocachingtoolbox.com/index.php?lang=en\&page=dvorakKeyboard](https://www.geocachingtoolbox.com/index.php?lang=en\&page=dvorakKeyboard)

### A1Z26

अक्षरों के उनके संख्यात्मक मूल्य
```
8 15 12 1 3 1 18 1 3 15 12 1
```
### अफाइन गुप्ताक्षर एन्कोड

पत्र को संख्या में बदलें `(ax+b)%26` (_a_ और _b_ कुंजी हैं और _x_ पत्र है) और परिणाम को फिर से पत्र में बदलें
```
krodfdudfrod
```
### एसएमएस कोड

**मल्टीटैप** [एक अक्षर को बदलता है](https://www.dcode.fr/word-letter-change) जिसे मोबाइल [फोन कीपैड](https://www.dcode.fr/phone-keypad-cipher) पर संबंधित कुंजी कोड द्वारा परिभाषित दोहरी अंकों से बदल दिया जाता है (यह मोड एसएमएस लिखते समय प्रयोग किया जाता है)।\
उदाहरण: 2=A, 22=B, 222=C, 3=D...\
आप इस कोड को पहचान सकते हैं क्योंकि आपको\*\* कई बार दोहराए गए अंक\*\* दिखाई देंगे।

आप इस कोड को डीकोड कर सकते हैं: [https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher)

### बेकन कोड

प्रत्येक अक्षर को 4 ए या बी (या 1 और 0) के लिए प्रतिस्थापित करें
```
00111 01101 01010 00000 00010 00000 10000 00000 00010 01101 01010 00000
AABBB ABBAB ABABA AAAAA AAABA AAAAA BAAAA AAAAA AAABA ABBAB ABABA AAAAA
```
### रूण

![](../.gitbook/assets/runes.jpg)

## संक्षेपण

**Raw Deflate** और **Raw Inflate** (आप दोनों को साइबरचेफ में पा सकते हैं) डेटा को हेडर के बिना संक्षेपित और विस्तारित कर सकते हैं।

## सरल क्रिप्टो

### XOR - ऑटोसॉल्वर

* [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### Bifid

एक कीवर्ड की आवश्यकता है
```
fgaargaamnlunesuneoa
```
### वीजेनेर

एक कुंजीशब्द की आवश्यकता है
```
wodsyoidrods
```
* [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)
* [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
* [https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## मजबूत क्रिप्टो

### फेर्नेट

2 base64 स्ट्रिंग्स (टोकन और कुंजी)
```
Token:
gAAAAABWC9P7-9RsxTz_dwxh9-O2VUB7Ih8UCQL1_Zk4suxnkCvb26Ie4i8HSUJ4caHZuiNtjLl3qfmCv_fS3_VpjL7HxCz7_Q==

Key:
-s6eI5hyNh8liH7Gq0urPC-vzPgNnxauKvRO4g03oYI=
```
* [https://asecuritysite.com/encryption/ferdecode](https://asecuritysite.com/encryption/ferdecode)

### समीर सीक्रेट शेयरिंग

एक रहस्य को X भागों में विभाजित किया जाता है और इसे पुनर्प्राप्त करने के लिए आपको Y भागों की आवश्यकता होती है (_Y <=X_).
```
8019f8fa5879aa3e07858d08308dc1a8b45
80223035713295bddf0b0bd1b10a5340b89
803bc8cf294b3f83d88e86d9818792e80cd
```
[http://christian.gen.co/secrets/](http://christian.gen.co/secrets/)

### OpenSSL brute-force

* [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
* [https://github.com/carlospolop/easy\_BFopensslCTF](https://github.com/carlospolop/easy\_BFopensslCTF)

## Tools

* [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* [https://github.com/lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom)
* [https://github.com/nccgroup/featherduster](https://github.com/nccgroup/featherduster)

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

दूसरे तरीके HackTricks का समर्थन करने के लिए:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** HackTricks और HackTricks Cloud github repos में PRs सबमिट करके।

</details>
