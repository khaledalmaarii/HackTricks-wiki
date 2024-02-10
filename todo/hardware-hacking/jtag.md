<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** repository [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>


# JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)è uno strumento che può essere utilizzato con una Raspberry PI o un Arduino per cercare i pin JTAG di un chip sconosciuto.\
Nell'**Arduino**, collega i **pin da 2 a 11 ai 10 pin potenzialmente appartenenti a un JTAG**. Carica il programma nell'Arduino e proverà a forzare tutti i pin per scoprire se qualche pin appartiene a un JTAG e quale sia ciascuno.\
Nella **Raspberry PI** puoi utilizzare solo i **pin da 1 a 6** (6 pin, quindi andrai più lentamente testando ogni potenziale pin JTAG).

## Arduino

Nell'Arduino, dopo aver collegato i cavi (pin 2 a 11 ai pin JTAG e GND dell'Arduino alla baseboard GND), **carica il programma JTAGenum nell'Arduino** e nella Serial Monitor invia un **`h`** (comando per l'aiuto) e dovresti vedere l'aiuto:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configura **"No line ending" e 115200baud**.\
Invia il comando s per avviare la scansione:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Se stai contattando un JTAG, troverai una o più **righe che iniziano con FOUND!** che indicano i pin del JTAG.


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** repository [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
