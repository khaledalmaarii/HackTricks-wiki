{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichen.

</details>
{% endhint %}


In einer Ping-Antwort TTL:\
127 = Windows\
254 = Cisco\
Der Rest, irgendein Linux

$1$- md5\
$2$oder $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Wenn Sie nicht wissen, was hinter einem Dienst steckt, versuchen Sie, eine HTTP GET-Anfrage zu stellen.

**UDP-Scans**\
nc -nv -u -z -w 1 \<IP> 160-16

Ein leeres UDP-Paket wird an einen bestimmten Port gesendet. Wenn der UDP-Port offen ist, wird keine Antwort von der Zielmaschine zurückgesendet. Wenn der UDP-Port geschlossen ist, sollte ein ICMP-Port-unreachable-Paket von der Zielmaschine zurückgesendet werden.\

UDP-Port-Scans sind oft unzuverlässig, da Firewalls und Router ICMP-Pakete möglicherweise verwerfen.\
Dies kann zu falsch positiven Ergebnissen in Ihrem Scan führen, und Sie werden regelmäßig sehen, dass\
UDP-Port-Scans alle UDP-Ports auf einer gescannten Maschine als offen anzeigen.\
Die meisten Port-Scanner scannen nicht alle verfügbaren Ports und haben normalerweise eine voreingestellte Liste\
von „interessanten Ports“, die gescannt werden.

# CTF - Tricks

In **Windows** verwenden Sie **Winzip**, um nach Dateien zu suchen.\
**Alternative Datenströme**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Beginne mit "_begin \<mode> \<filename>_" und seltsamen Zeichen\
**Xxencoding** --> Beginne mit "_begin \<mode> \<filename>_" und B64\
\
**Vigenere** (Häufigkeitsanalyse) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (Versatz von Zeichen) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Nachrichten verstecken mit Leerzeichen und Tabs

# Characters

%E2%80%AE => RTL-Zeichen (schreibt Payloads rückwärts)


{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
