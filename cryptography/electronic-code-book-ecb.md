<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>


# ECB

(ECB) Electronic Code Book - schema di crittografia simmetrica che **sostituisce ogni blocco di testo in chiaro** con il **blocco di testo cifrato**. È lo schema di crittografia **più semplice**. L'idea principale è **dividere** il testo in chiaro in **blocchi di N bit** (a seconda della dimensione del blocco di dati di input, dell'algoritmo di crittografia) e quindi cifrare (decifrare) ogni blocco di testo in chiaro utilizzando l'unico chiave.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

L'utilizzo di ECB ha diverse implicazioni sulla sicurezza:

* **Blocchi del messaggio cifrato possono essere rimossi**
* **Blocchi del messaggio cifrato possono essere spostati**

# Rilevamento della vulnerabilità

Immagina di accedere a un'applicazione diverse volte e di ottenere **sempre lo stesso cookie**. Questo perché il cookie dell'applicazione è **`<username>|<password>`**.\
Quindi, generi due nuovi utenti, entrambi con la **stessa password lunga** e **quasi** lo **stesso** **username**.\
Scopri che i **blocchi di 8B** in cui le **informazioni di entrambi gli utenti** sono uguali sono **identici**. Quindi, immagini che ciò possa essere dovuto all'uso di **ECB**.

Come nell'esempio seguente. Osserva come questi **2 cookie decodificati** hanno diverse volte il blocco **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Questo perché il **nome utente e la password di quei cookie contenevano più volte la lettera "a"** (ad esempio). I **blocchi** che sono **diversi** sono blocchi che contenevano **almeno 1 carattere diverso** (forse il delimitatore "|" o qualche differenza necessaria nel nome utente).

Ora, l'attaccante deve solo scoprire se il formato è `<nome utente><delimitatore><password>` o `<password><delimitatore><nome utente>`. Per farlo, può semplicemente **generare diversi nomi utente** con nomi utente e password **simili e lunghi** fino a trovare il formato e la lunghezza del delimitatore:

| Lunghezza nome utente: | Lunghezza password: | Lunghezza nome utente+password: | Lunghezza cookie (dopo la decodifica): |
| --------------------- | ------------------- | ------------------------------ | ------------------------------------- |
| 2                     | 2                   | 4                              | 8                                     |
| 3                     | 3                   | 6                              | 8                                     |
| 3                     | 4                   | 7                              | 8                                     |
| 4                     | 4                   | 8                              | 16                                    |
| 7                     | 7                   | 14                             | 16                                    |

# Sfruttamento della vulnerabilità

## Rimozione di interi blocchi

Conoscendo il formato del cookie (`<nome utente>|<password>`), per impersonare il nome utente `admin` crea un nuovo utente chiamato `aaaaaaaaadmin` e ottieni il cookie e decodificalo:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Possiamo vedere il pattern `\x23U\xE45K\xCB\x21\xC8` creato in precedenza con lo username che conteneva solo `a`.\
Successivamente, puoi rimuovere il primo blocco di 8B e otterrai un cookie valido per lo username `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Spostare i blocchi

In molti database è la stessa cosa cercare `WHERE username='admin';` o `WHERE username='admin    ';` _(Nota gli spazi extra)_

Quindi, un altro modo per impersonare l'utente `admin` sarebbe:

* Generare un nome utente che: `len(<username>) + len(<delimiter>) % len(block)`. Con una dimensione del blocco di `8B` puoi generare un nome utente chiamato: `username       `, con il delimitatore `|` il chunk `<username><delimiter>` genererà 2 blocchi di 8B.
* Quindi, generare una password che riempirà un numero esatto di blocchi contenenti il nome utente che vogliamo impersonare e spazi, come: `admin   `

Il cookie di questo utente sarà composto da 3 blocchi: i primi 2 sono i blocchi del nome utente + delimitatore e il terzo è quello della password (che sta fingendo il nome utente): `username       |admin   `

**Quindi, basta sostituire il primo blocco con l'ultimo e impersoneremo l'utente `admin`: `admin          |username`**

## Riferimenti

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
