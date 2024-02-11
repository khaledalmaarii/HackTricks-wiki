<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Katika jibu la ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$au $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Ikiwa haujui ni nini kipo nyuma ya huduma, jaribu kufanya ombi la HTTP GET.

**Uchunguzi wa UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Pakiti tupu ya UDP inatumwa kwenye bandari maalum. Ikiwa bandari ya UDP iko wazi, hakuna jibu linalotumwa kutoka kwenye kompyuta ya lengo. Ikiwa bandari ya UDP imefungwa, pakiti ya ICMP isiyoweza kufikiwa kwa bandari inapaswa kutumwa kutoka kwenye kompyuta ya lengo.\


Uchunguzi wa bandari za UDP mara nyingi hauna uhakika, kwani firewalls na rutuba zinaweza kudondosha pakiti za ICMP. Hii inaweza kusababisha matokeo sahihi ya uwongo katika uchunguzi wako, na mara kwa mara utaona uchunguzi wa bandari za UDP ukionyesha bandari zote za UDP zimefunguliwa kwenye kompyuta iliyochunguzwa.\
o Wachunguzi wengi wa bandari hawachunguzi bandari zote zinazopatikana, na kawaida wana orodha iliyowekwa mapema ya "bandari za kuvutia" ambazo zinachunguzwa.

# CTF - Mbinu

Katika **Windows** tumia **Winzip** kutafuta faili.\
**Data Streams Zingine**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Anza na "_begin \<mode> \<filename>_" na herufi za ajabu\
**Xxencoding** --> Anza na "_begin \<mode> \<filename>_" na B64\
\
**Vigenere** (uchambuzi wa marudio) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (kielelezo cha kusogeza herufi) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ficha ujumbe kwa kutumia nafasi na tabo

# Characters

%E2%80%AE => RTL Character (andika mizigo kwa nyuma)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
