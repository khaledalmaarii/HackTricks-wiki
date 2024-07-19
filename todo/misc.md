{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


Bir ping yanıtında TTL:\
127 = Windows\
254 = Cisco\
Diğerleri, bazılinux

$1$- md5\
$2$ veya $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Bir hizmetin arkasında ne olduğunu bilmiyorsanız, bir HTTP GET isteği yapmayı deneyin.

**UDP Taramaları**\
nc -nv -u -z -w 1 \<IP> 160-16

Belirli bir porta boş bir UDP paketi gönderilir. Eğer UDP portu açıksa, hedef makineden geri bir yanıt gönderilmez. Eğer UDP portu kapalıysa, hedef makineden bir ICMP port ulaşılamaz paketi geri gönderilmelidir.\

UDP port taraması genellikle güvenilir değildir, çünkü güvenlik duvarları ve yönlendiriciler ICMP\
paketlerini düşürebilir. Bu, taramanızda yanlış pozitiflere yol açabilir ve taranan bir makinedeki tüm UDP portlarının açık olduğunu gösteren UDP port taramaları görebilirsiniz.\
Çoğu port tarayıcı, mevcut tüm portları taramaz ve genellikle taranan "ilginç portlar" için önceden ayarlanmış bir listeye sahiptir.

# CTF - İpuçları

**Windows**'ta dosyaları aramak için **Winzip** kullanın.\
**Alternatif veri Akışları**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" ile başla ve garip karakterler\
**Xxencoding** --> "_begin \<mode> \<filename>_" ile başla ve B64\
\
**Vigenere** (frekans analizi) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (karakter kaydırması) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Mesajları boşluklar ve sekmeler kullanarak gizle

# Characters

%E2%80%AE => RTL Karakteri (yükleme verilerini ters yazar)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
