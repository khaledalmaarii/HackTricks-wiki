{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}


In una risposta ping TTL:\
127 = Windows\
254 = Cisco\
Il resto, qualche linux

$1$- md5\
$2$o $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Se non sai cosa c'è dietro un servizio, prova a fare una richiesta HTTP GET.

**Scansioni UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Un pacchetto UDP vuoto viene inviato a una porta specifica. Se la porta UDP è aperta, non viene inviata alcuna risposta dalla macchina target. Se la porta UDP è chiusa, un pacchetto ICMP porta irraggiungibile dovrebbe essere inviato indietro dalla macchina target.\

La scansione delle porte UDP è spesso inaffidabile, poiché i firewall e i router possono scartare i pacchetti ICMP.\
Questo può portare a falsi positivi nella tua scansione, e vedrai regolarmente scansioni di porte UDP che mostrano tutte le porte UDP aperte su una macchina scansionata.\
La maggior parte degli scanner di porte non scansiona tutte le porte disponibili e di solito ha un elenco preimpostato di “porte interessanti” che vengono scansionate.

# CTF - Trucchi

In **Windows** usa **Winzip** per cercare file.\
**Stream di dati alternativi**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Inizia con "_begin \<mode> \<filename>_" e caratteri strani\
**Xxencoding** --> Inizia con "_begin \<mode> \<filename>_" e B64\
\
**Vigenere** (analisi della frequenza) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset dei caratteri) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Nascondi messaggi usando spazi e tabulazioni

# Characters

%E2%80%AE => Carattere RTL (scrive i payload all'indietro)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
