{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}


W odpowiedzi ping TTL:\
127 = Windows\
254 = Cisco\
Reszta, jakiś linux

$1$- md5\
$2$lub $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Jeśli nie wiesz, co kryje się za usługą, spróbuj wykonać żądanie HTTP GET.

**Skanowanie UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Pusty pakiet UDP jest wysyłany do konkretnego portu. Jeśli port UDP jest otwarty, nie jest wysyłana żadna odpowiedź z maszyny docelowej. Jeśli port UDP jest zamknięty, z maszyny docelowej powinien być wysłany pakiet ICMP informujący o niedostępności portu.\

Skanowanie portów UDP jest często niewiarygodne, ponieważ zapory ogniowe i routery mogą odrzucać pakiety ICMP.\
Może to prowadzić do fałszywych pozytywów w twoim skanowaniu, a ty regularnie zobaczysz, że skanowanie portów UDP pokazuje wszystkie porty UDP jako otwarte na skanowanej maszynie.\
Większość skanerów portów nie skanuje wszystkich dostępnych portów i zazwyczaj ma wstępnie ustaloną listę „interesujących portów”, które są skanowane.

# CTF - Triki

W **Windows** użyj **Winzip**, aby wyszukać pliki.\
**Alternatywne strumienie danych**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Zacznij od "_begin \<mode> \<filename>_" i dziwnych znaków\
**Xxencoding** --> Zacznij od "_begin \<mode> \<filename>_" i B64\
\
**Vigenere** (analiza częstotliwości) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (przesunięcie znaków) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ukryj wiadomości używając spacji i tabulatorów

# Characters

%E2%80%AE => Znak RTL (pisze ładunki wstecz)


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
