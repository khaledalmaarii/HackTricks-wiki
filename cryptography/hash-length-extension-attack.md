<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** repository di [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>


# Riassunto dell'attacco

Immagina un server che sta **firmare** dei **dati** aggiungendo un **segreto** a dei dati noti in chiaro e poi facendo l'hash di quei dati. Se conosci:

* **La lunghezza del segreto** (questo può essere anche forzato da un intervallo di lunghezza dato)
* **I dati in chiaro**
* **L'algoritmo (e che è vulnerabile a questo attacco)**
* **Il padding è noto**
* Di solito ne viene utilizzato uno predefinito, quindi se sono soddisfatte anche le altre 3 condizioni, questo lo è anche
* Il padding varia a seconda della lunghezza del segreto+dati, ecco perché è necessaria la lunghezza del segreto

Allora, è possibile per un **attaccante** **aggiungere** dei **dati** e **generare** una firma valida per i **dati precedenti + dati aggiunti**.

## Come?

Fondamentalmente gli algoritmi vulnerabili generano gli hash **hashando prima un blocco di dati**, e poi, **dal** precedente **hash** (stato), **aggiungono il blocco successivo di dati** e **lo hashano**.

Quindi, immagina che il segreto sia "segreto" e i dati siano "dati", l'MD5 di "segretodati" è 6036708eba0d11f6ef52ad44e8b74d5b.\
Se un attaccante vuole aggiungere la stringa "aggiungi" può:

* Generare un MD5 di 64 "A"
* Cambiare lo stato dell'hash precedentemente inizializzato a 6036708eba0d11f6ef52ad44e8b74d5b
* Aggiungere la stringa "aggiungi"
* Concludere l'hash e l'hash risultante sarà un **valido per "segreto" + "dati" + "padding" + "aggiungi"**

## **Strumento**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Riferimenti

Puoi trovare questa attacco ben spiegato in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** repository di [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
