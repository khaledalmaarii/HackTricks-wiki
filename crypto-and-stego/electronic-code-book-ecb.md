{% hint style="success" %}
Impara e pratica l'hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}


# ECB

(ECB) Electronic Code Book - schema di crittografia simmetrica che **sostituisce ogni blocco del testo in chiaro** con il **blocco di testo crittografato**. È lo schema di crittografia **più semplice**. L'idea principale è **dividere** il testo in chiaro in **blocchi di N bit** (dipende dalla dimensione del blocco dei dati di input, algoritmo di crittografia) e quindi crittografare (decrittografare) ogni blocco di testo in chiaro usando l'unico chiave.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

L'utilizzo di ECB ha molteplici implicazioni sulla sicurezza:

* **I blocchi del messaggio crittografato possono essere rimossi**
* **I blocchi del messaggio crittografato possono essere spostati**

# Rilevamento della vulnerabilità

Immagina di accedere a un'applicazione diverse volte e di **ricevere sempre lo stesso cookie**. Questo perché il cookie dell'applicazione è **`<username>|<password>`**.\
Successivamente, crei due nuovi utenti, entrambi con la **stessa password lunga** e **quasi** lo **stesso** **username**.\
Scopri che i **blocchi di 8B** in cui l'**informazione di entrambi gli utenti** è la stessa sono **uguali**. Quindi, immagini che ciò potrebbe essere dovuto all'uso di **ECB**.

Come nell'esempio seguente. Osserva come questi **2 cookie decodificati** hanno diverse volte il blocco **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Questo perché **il nome utente e la password di quei cookie contenevano più volte la lettera "a"** (ad esempio). I **blocchi** che sono **diversi** sono blocchi che contenevano **almeno 1 carattere diverso** (forse il delimitatore "|" o qualche differenza necessaria nel nome utente).

Ora, l'attaccante deve solo scoprire se il formato è `<nome utente><delimitatore><password>` o `<password><delimitatore><nome utente>`. Per farlo, può semplicemente **generare diversi nomi utente** con **nomi utente e password simili e lunghi** finché non trova il formato e la lunghezza del delimitatore:

| Lunghezza nome utente: | Lunghezza password: | Lunghezza nome utente+password: | Lunghezza cookie (dopo decodifica): |
| ---------------------- | ------------------- | ------------------------------ | ---------------------------------- |
| 2                      | 2                   | 4                              | 8                                  |
| 3                      | 3                   | 6                              | 8                                  |
| 3                      | 4                   | 7                              | 8                                  |
| 4                      | 4                   | 8                              | 16                                 |
| 7                      | 7                   | 14                             | 16                                 |

# Sfruttamento della vulnerabilità

## Rimozione di interi blocchi

Conoscendo il formato del cookie (`<nome utente>|<password>`), per impersonare il nome utente `admin` crea un nuovo utente chiamato `aaaaaaaaadmin` e ottieni il cookie e decodificalo:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Possiamo vedere il modello `\x23U\xE45K\xCB\x21\xC8` creato in precedenza con il nome utente che conteneva solo `a`.\
Quindi, puoi rimuovere il primo blocco di 8B e otterrai un cookie valido per il nome utente `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Spostamento dei blocchi

In molti database è la stessa cosa cercare `WHERE username='admin';` o `WHERE username='admin    ';` _(Nota gli spazi extra)_

Quindi, un altro modo per impersonare l'utente `admin` sarebbe:

* Generare un username tale che: `len(<username>) + len(<delimitatore) % len(blocco)`. Con una dimensione del blocco di `8B` puoi generare un username chiamato: `username       `, con il delimitatore `|` il chunk `<username><delimitatore>` genererà 2 blocchi di 8B.
* Successivamente, generare una password che riempirà un numero esatto di blocchi contenenti lo username che vogliamo impersonare e spazi, come: `admin   `

Il cookie di questo utente sarà composto da 3 blocchi: i primi 2 sono i blocchi dello username + delimitatore e il terzo della password (che sta fingendo lo username): `username       |admin   `

**Quindi, basta sostituire il primo blocco con l'ultimo e si impersonerà l'utente `admin`: `admin          |username`**

## Riferimenti

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
