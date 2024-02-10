<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>


# CBC

Se il **cookie** è **solo** l'**username** (o la prima parte del cookie è l'username) e vuoi impersonare l'username "**admin**". Allora, puoi creare l'username **"bdmin"** e **forzare** il **primo byte** del cookie.

# CBC-MAC

Il **cipher block chaining message authentication code** (**CBC-MAC**) è un metodo utilizzato in crittografia. Funziona prendendo un messaggio e crittografandolo blocco per blocco, dove la crittografia di ogni blocco è collegata a quella precedente. Questo processo crea una **catena di blocchi**, garantendo che anche una singola modifica di un bit del messaggio originale porti a una modifica imprevedibile nell'ultimo blocco dei dati crittografati. Per effettuare o invertire tale modifica, è necessaria la chiave di crittografia, garantendo la sicurezza.

Per calcolare il CBC-MAC del messaggio m, si crittografa m in modalità CBC con un vettore di inizializzazione zero e si conserva l'ultimo blocco. La figura seguente illustra il calcolo del CBC-MAC di un messaggio composto da blocchi![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) utilizzando una chiave segreta k e un cifrario a blocchi E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilità

Con CBC-MAC di solito l'**IV utilizzato è 0**.\
Questo è un problema perché 2 messaggi noti (`m1` e `m2`) genereranno indipendentemente 2 firme (`s1` e `s2`). Quindi:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Quindi un messaggio composto da m1 e m2 concatenati (m3) genererà 2 firme (s31 e s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**È possibile calcolare ciò senza conoscere la chiave della crittografia.**

Immagina di crittografare il nome **Administrator** in blocchi di **8 byte**:

* `Administ`
* `rator\00\00\00`

Puoi creare un username chiamato **Administ** (m1) e recuperare la firma (s1).\
Quindi, puoi creare un username chiamato il risultato di `rator\00\00\00 XOR s1`. Questo genererà `E(m2 XOR s1 XOR 0)` che è s32.\
Ora, puoi utilizzare s32 come firma del nome completo **Administrator**.

### Riassunto

1. Ottieni la firma dell'username **Administ** (m1) che è s1
2. Ottieni la firma dell'username **rator\x00\x00\x00 XOR s1 XOR 0** che è s32**.**
3. Imposta il cookie su s32 e sarà un cookie valido per l'utente **Administrator**.

# Attacco al controllo dell'IV

Se puoi controllare l'IV utilizzato, l'attacco potrebbe essere molto facile.\
Se i cookie sono solo l'username criptato, per impersonare l'utente "**administrator**" puoi creare l'utente "**Administrator**" e otterrai il suo cookie.\
Ora, se puoi controllare l'IV, puoi cambiare il primo byte dell'IV in modo che **IV\[0] XOR "A" == IV'\[0] XOR "a"** e rigenerare il cookie per l'utente **Administrator**. Questo cookie sarà valido per **impersonare** l'utente **administrator** con l'IV iniziale.

## Riferimenti

Ulteriori informazioni su [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
