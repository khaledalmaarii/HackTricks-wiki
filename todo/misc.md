{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


U ping odgovoru TTL:\
127 = Windows\
254 = Cisco\
Ostalo, neki linux

$1$- md5\
$2$ili $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Ako ne znate šta se nalazi iza usluge, pokušajte da napravite HTTP GET zahtev.

**UDP skeniranja**\
nc -nv -u -z -w 1 \<IP> 160-16

Prazan UDP paket se šalje na određeni port. Ako je UDP port otvoren, nema odgovora sa ciljne mašine. Ako je UDP port zatvoren, ICMP paket o nedostupnom portu treba da se vrati sa ciljne mašine.\

UDP skeniranje portova je često nepouzdano, jer vatrozidi i ruteri mogu odbaciti ICMP\
pakete. To može dovesti do lažnih pozitivnih rezultata u vašem skeniranju, i redovno ćete videti\
UDP skeniranja portova koja pokazuju sve UDP portove otvorene na skeniranoj mašini.\
Većina skeneri portova ne skeniraju sve dostupne portove, i obično imaju unapred postavljenu listu\
“zanimljivih portova” koji se skeniraju.

# CTF - Trikovi

U **Windows** koristite **Winzip** za pretragu datoteka.\
**Alternativni podaci**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Počnite sa "_begin \<mode> \<filename>_" i čudnim karakterima\
**Xxencoding** --> Počnite sa "_begin \<mode> \<filename>_" i B64\
\
**Vigenere** (analiza frekvencije) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (pomak karaktera) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Sakrijte poruke koristeći razmake i tabove

# Characters

%E2%80%AE => RTL karakter (piše payload-ove unazad)


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
