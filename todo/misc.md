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


У відповіді ping TTL:\
127 = Windows\
254 = Cisco\
Все інше, якийсь linux

$1$- md5\
$2$or $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Якщо ви не знаєте, що стоїть за сервісом, спробуйте зробити HTTP GET запит.

**UDP Scans**\
nc -nv -u -z -w 1 \<IP> 160-16

Порожній UDP пакет надсилається на конкретний порт. Якщо UDP порт відкритий, відповідь не надсилається з цільової машини. Якщо UDP порт закритий, з цільової машини має бути надіслано пакет ICMP "порт недоступний".\

Сканування UDP портів часто ненадійне, оскільки брандмауери та маршрутизатори можуть відкидати пакети ICMP.\
Це може призвести до хибнопозитивних результатів у вашому скануванні, і ви регулярно будете бачити, що сканування UDP портів показує всі UDP порти відкритими на сканованій машині.\
Більшість сканерів портів не сканують всі доступні порти і зазвичай мають попередньо встановлений список "цікавих портів", які скануються.

# CTF - Tricks

У **Windows** використовуйте **Winzip** для пошуку файлів.\
**Alternate data Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Починається з "_begin \<mode> \<filename>_" та дивних символів\
**Xxencoding** --> Починається з "_begin \<mode> \<filename>_" та B64\
\
**Vigenere** (аналіз частот) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (зсув символів) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Сховати повідомлення, використовуючи пробіли та табуляції

# Characters

%E2%80%AE => RTL Character (пише payloads у зворотному порядку)


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
