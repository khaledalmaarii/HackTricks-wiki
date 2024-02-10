<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


Ping yanıtında TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$ veya $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Bir hizmetin arkasında ne olduğunu bilmiyorsanız, bir HTTP GET isteği yapmayı deneyin.

**UDP Taramaları**\
nc -nv -u -z -w 1 \<IP> 160-16

Belirli bir porta boş bir UDP paketi gönderilir. Eğer UDP portu açıksa, hedef makineden yanıt gönderilmez. Eğer UDP portu kapalıysa, hedef makineden bir ICMP port ulaşılamaz paketi gönderilir.\


UDP port taraması genellikle güvenilmezdir, çünkü güvenlik duvarları ve yönlendiriciler ICMP\
paketlerini düşürebilir. Bu, taramanızda yanlış pozitif sonuçlar almanıza ve düzenli olarak\
taranan bir makinede tüm UDP portlarının açık olduğunu gösteren UDP port taramaları görmeye devam etmenize neden olabilir.\
o Çoğu port tarama aracı tüm mevcut portları taramaz ve genellikle tarama için önceden belirlenmiş bir liste\
"ilginç portlar" vardır.

# CTF - Hileler

**Windows**'da dosya aramak için **Winzip** kullanın.\
**Alternatif veri Akışları**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Kripto

**featherduster**\


**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" ile başlar ve garip karakterler içerir\
**Xxencoding** --> "_begin \<mode> \<filename>_" ile başlar ve B64 içerir\
\
**Vigenere** (frekans analizi) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (karakterlerin ofseti) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Mesajları boşluklar ve sekme karakterleri kullanarak gizleme

# Karakterler

%E2%80%AE => Sağdan sola yazılan RTL karakteri (payload'ları ters yazma)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek için** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) **kontrol edin**!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) **edinin**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **koleksiyonumuzu keşfedin**, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) **katılın** veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) **ve** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github reposuna PR göndererek paylaşın**.

</details>
