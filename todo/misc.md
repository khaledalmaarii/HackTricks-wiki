<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


In 'n ping-respons TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$of $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

As jy nie weet wat agter 'n diens is nie, probeer om 'n HTTP GET-versoek te maak.

**UDP-skanderings**\
nc -nv -u -z -w 1 \<IP> 160-16

'n Leë UDP-pakket word gestuur na 'n spesifieke poort. As die UDP-poort oop is, word geen antwoord teruggestuur vanaf die teikermasjien nie. As die UDP-poort gesluit is, moet 'n ICMP-poort onbereikbaar-pakket teruggestuur word vanaf die teikermasjien.\


UDP-poortskandering is dikwels onbetroubaar, aangesien brandmuure en roetingsapparate ICMP-pakette kan laat val. Dit kan lei tot vals positiewe resultate in jou skandering, en jy sal gereeld sien dat UDP-poortskanderings wys dat alle UDP-poorte oop is op 'n gescande masjien.\
o Die meeste poortskanners skandeer nie alle beskikbare poorte nie, en het gewoonlik 'n vooraf ingestelde lys van "interessante poorte" wat geskandeer word.

# CTF - Truuks

In **Windows** gebruik **Winzip** om vir lêers te soek.\
**Alternatiewe datastrome**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Kriptografie

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Begin met "_begin \<mode> \<filename>_" en vreemde karakters\
**Xxencoding** --> Begin met "_begin \<mode> \<filename>_" en B64\
\
**Vigenere** (frekwensie analise) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (verskuiwing van karakters) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Versteek boodskappe deur gebruik te maak van spasies en tabs

# Karakters

%E2%80%AE => RTL Karakter (skryf payloads agteruit)


<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
