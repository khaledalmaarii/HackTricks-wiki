# Numero di serie di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>


## Informazioni di base

I dispositivi Apple post-2010 hanno numeri di serie composti da **12 caratteri alfanumerici**, ciascun segmento che trasmette informazioni specifiche:

- **Primi 3 caratteri**: Indicano la **posizione di produzione**.
- **Caratteri 4 e 5**: Indicano l'**anno e la settimana di produzione**.
- **Caratteri 6-8**: Servono come **identificatore unico** per ogni dispositivo.
- **Ultimi 4 caratteri**: Specificano il **numero di modello**.

Ad esempio, il numero di serie **C02L13ECF8J2** segue questa struttura.

### **Posizioni di produzione (Primi 3 caratteri)**
Determinati codici rappresentano fabbriche specifiche:
- **FC, F, XA/XB/QP/G8**: Diverse posizioni negli Stati Uniti.
- **RN**: Messico.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, Repubblica Ceca.
- **SG/E**: Singapore.
- **MB**: Malesia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diverse posizioni in Cina.
- **C0, C3, C7**: Città specifiche in Cina.
- **RM**: Dispositivi ricondizionati.

### **Anno di produzione (4° carattere)**
Questo carattere varia da 'C' (che rappresenta la prima metà del 2010) a 'Z' (seconda metà del 2019), con diverse lettere che indicano diversi semestri.

### **Settimana di produzione (5° carattere)**
I numeri da 1 a 9 corrispondono alle settimane da 1 a 9. Le lettere C-Y (escludendo le vocali e la lettera 'S') rappresentano le settimane da 10 a 27. Per la seconda metà dell'anno, a questo numero viene aggiunto 26.

### **Identificatore unico (Caratteri 6-8)**
Queste tre cifre garantiscono che ogni dispositivo, anche dello stesso modello e lotto, abbia un numero di serie distinto.

### **Numero di modello (Ultimi 4 caratteri)**
Queste cifre identificano il modello specifico del dispositivo.

### Riferimento

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
