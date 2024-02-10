<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


In einer Ping-Antwort TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$ oder $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Wenn Sie nicht wissen, was sich hinter einem Dienst verbirgt, versuchen Sie, eine HTTP GET-Anfrage zu stellen.

**UDP-Scans**\
nc -nv -u -z -w 1 \<IP> 160-16

Ein leeres UDP-Paket wird an einen bestimmten Port gesendet. Wenn der UDP-Port geöffnet ist, wird keine Antwort von der Zielmaschine zurückgesendet. Wenn der UDP-Port geschlossen ist, sollte von der Zielmaschine ein ICMP-Paket mit der Meldung "Port nicht erreichbar" zurückgesendet werden.\


UDP-Portscans sind oft unzuverlässig, da Firewalls und Router ICMP-Pakete verwerfen können. Dies kann zu falsch positiven Ergebnissen in Ihrem Scan führen, und Sie werden regelmäßig UDP-Portscans sehen, die alle UDP-Ports auf einer gescannten Maschine als geöffnet anzeigen.\
o Die meisten Portscanner scannen nicht alle verfügbaren Ports und haben in der Regel eine voreingestellte Liste von "interessanten Ports", die gescannt werden.

# CTF - Tricks

In **Windows** verwenden Sie **Winzip**, um nach Dateien zu suchen.\
**Alternative Datenströme**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Krypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Beginne mit "_begin \<mode> \<filename>_" und seltsamen Zeichen\
**Xxencoding** --> Beginne mit "_begin \<mode> \<filename>_" und B64\
\
**Vigenere** (Frequenzanalyse) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (Verschiebung der Zeichen) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Verstecke Nachrichten mit Leerzeichen und Tabs

# Zeichen

%E2%80%AE => RTL-Zeichen (schreibt Payloads rückwärts)


<details>

<summary><strong>Lerne AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn du deine **Firma in HackTricks bewerben möchtest** oder **HackTricks als PDF herunterladen möchtest**, schau dir die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Hol dir das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* Entdecke [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folge** uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teile deine Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repos sendest.**

</details>
