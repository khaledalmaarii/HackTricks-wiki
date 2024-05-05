# JTAG

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la **tua azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)è uno strumento che può essere utilizzato con un Raspberry PI o un Arduino per trovare e provare i pin JTAG di un chip sconosciuto.\
Nell'**Arduino**, collega i **pin da 2 a 11 ai 10 pin potenzialmente appartenenti a un JTAG**. Carica il programma nell'Arduino e proverà a forzare tutti i pin per trovare se qualche pin appartiene a JTAG e quale sia ciascuno.\
Nel **Raspberry PI** è possibile utilizzare solo i **pin da 1 a 6** (6 pin, quindi si procederà più lentamente testando ciascun pin JTAG potenziale).

### Arduino

In Arduino, dopo aver collegato i cavi (pin da 2 a 11 ai pin JTAG e Arduino GND al GND della scheda madre), **carica il programma JTAGenum in Arduino** e nel Monitor Seriale invia un **`h`** (comando per l'aiuto) e dovresti vedere l'aiuto:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Configura **"Nessun terminatore di riga" e 115200baud**.\
Invia il comando s per avviare la scansione:

![](<../../.gitbook/assets/image (774).png>)

Se stai contattando un JTAG, troverai una o più **linee che iniziano con TROVATO!** indicando i pin del JTAG.

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la **tua azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
