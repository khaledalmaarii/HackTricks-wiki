<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>


In una risposta ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$ o $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Se non sai cosa c'è dietro un servizio, prova a fare una richiesta HTTP GET.

**Scansioni UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Viene inviato un pacchetto UDP vuoto a una porta specifica. Se la porta UDP è aperta, la macchina di destinazione non invia alcuna risposta. Se la porta UDP è chiusa, la macchina di destinazione dovrebbe inviare un pacchetto ICMP di porta irraggiungibile.\


La scansione delle porte UDP è spesso poco affidabile, poiché i firewall e i router possono eliminare i pacchetti ICMP. Ciò può portare a falsi positivi nella scansione e si vedranno regolarmente scansioni delle porte UDP che mostrano tutte le porte UDP aperte su una macchina scansionata.\
o La maggior parte degli scanner di porte non scansiona tutte le porte disponibili e di solito ha un elenco predefinito di "porte interessanti" che vengono scansionate.

# CTF - Trucchi

In **Windows** usa **Winzip** per cercare file.\
**Flussi di dati alternativi**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Inizia con "_begin \<mode> \<filename>_" e caratteri strani\
**Xxencoding** --> Inizia con "_begin \<mode> \<filename>_" e B64\
\
**Vigenere** (analisi di frequenza) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset dei caratteri) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Nascondi messaggi usando spazi e tabulazioni

# Caratteri

%E2%80%AE => Carattere RTL (scrive payload al contrario)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
