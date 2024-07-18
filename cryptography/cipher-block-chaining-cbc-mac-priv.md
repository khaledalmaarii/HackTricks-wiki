{% hint style="success" %}
**Impara e pratica l'hacking su AWS:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**Impara e pratica l'hacking su GCP:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}


# CBC

Se il **cookie** è **solo** lo **username** (o la prima parte del cookie è lo username) e vuoi impersonare lo username "**admin**". Allora, puoi creare lo username **"bdmin"** e **forzare** il **primo byte** del cookie.

# CBC-MAC

Il **cipher block chaining message authentication code** (**CBC-MAC**) è un metodo utilizzato in crittografia. Funziona prendendo un messaggio e crittografandolo blocco per blocco, dove la crittografia di ciascun blocco è collegata a quello precedente. Questo processo crea una **catena di blocchi**, garantendo che anche cambiare un singolo bit del messaggio originale porterà a un cambiamento imprevedibile nell'ultimo blocco dei dati crittografati. Per apportare o invertire tale cambiamento, è necessaria la chiave di crittografia, garantendo la sicurezza.

Per calcolare il CBC-MAC del messaggio m, si crittografa m in modalità CBC con vettore di inizializzazione zero e si conserva l'ultimo blocco. La figura seguente schematizza il calcolo del CBC-MAC di un messaggio composto da blocchi ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) utilizzando una chiave segreta k e un cifrario a blocchi E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilità

Con il CBC-MAC di solito l'**IV utilizzato è 0**.\
Questo è un problema perché 2 messaggi noti (`m1` e `m2`) genereranno indipendentemente 2 firme (`s1` e `s2`). Quindi:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Quindi un messaggio composto da m1 e m2 concatenati (m3) genererà 2 firme (s31 e s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**È possibile calcolarlo senza conoscere la chiave della crittografia.**

Immagina di crittografare il nome **Amministratore** in blocchi di **8 byte**:

* `Administ`
* `rator\00\00\00`

Puoi creare uno username chiamato **Administ** (m1) e recuperare la firma (s1).\
Poi, puoi creare uno username chiamato il risultato di `rator\00\00\00 XOR s1`. Questo genererà `E(m2 XOR s1 XOR 0)` che è s32.\
ora, puoi usare s32 come firma del nome completo **Amministratore**.

### Riassunto

1. Ottieni la firma dell'username **Administ** (m1) che è s1
2. Ottieni la firma dell'username **rator\x00\x00\x00 XOR s1 XOR 0** che è s32**.**
3. Imposta il cookie su s32 e sarà un cookie valido per l'utente **Amministratore**.

# Attacco al Controllo dell'IV

Se puoi controllare l'IV utilizzato, l'attacco potrebbe essere molto facile.\
Se i cookie sono solo lo username criptato, per impersonare l'utente "**amministratore**" puoi creare l'utente "**Amministratore**" e otterrai il suo cookie.\
Ora, se puoi controllare l'IV, puoi cambiare il primo byte dell'IV in modo che **IV\[0] XOR "A" == IV'\[0] XOR "a"** e rigenerare il cookie per l'utente **Amministratore**. Questo cookie sarà valido per **impersonare** l'utente **amministratore** con l'IV iniziale.

## Riferimenti

Maggiori informazioni su [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
**Impara e pratica l'hacking su AWS:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**Impara e pratica l'hacking su GCP:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
