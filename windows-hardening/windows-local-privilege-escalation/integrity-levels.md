# Livelli di integrità

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è contrastare le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

## Livelli di integrità

In Windows Vista e nelle versioni successive, tutti gli elementi protetti sono contrassegnati da un livello di **integrità**. Questa configurazione assegna principalmente un livello di integrità "medio" ai file e alle chiavi di registro, ad eccezione di determinate cartelle e file a cui Internet Explorer 7 può scrivere a un livello di integrità basso. Il comportamento predefinito prevede che i processi avviati dagli utenti standard abbiano un livello di integrità medio, mentre i servizi operano tipicamente a un livello di integrità di sistema. Una etichetta di alta integrità protegge la directory radice.

Una regola chiave è che gli oggetti non possono essere modificati da processi con un livello di integrità inferiore rispetto al livello dell'oggetto. I livelli di integrità sono:

* **Non attendibile**: Questo livello è per i processi con accessi anonimi. %%%Esempio: Chrome%%%
* **Basso**: Principalmente per interazioni su Internet, specialmente nella Modalità protetta di Internet Explorer, che influisce su file e processi associati e su determinate cartelle come la **Cartella Internet Temporanea**. I processi a bassa integrità affrontano significative restrizioni, tra cui nessun accesso in scrittura al registro e limitato accesso in scrittura al profilo utente.
* **Medio**: Il livello predefinito per la maggior parte delle attività, assegnato agli utenti standard e agli oggetti senza livelli di integrità specifici. Anche i membri del gruppo Amministratori operano a questo livello per impostazione predefinita.
* **Alto**: Riservato agli amministratori, consentendo loro di modificare oggetti a livelli di integrità inferiori, compresi quelli a livello alto stesso.
* **Sistema**: Il livello operativo più alto per il kernel di Windows e i servizi di base, fuori dalla portata persino degli amministratori, garantendo la protezione delle funzioni vitali del sistema.
* **Installatore**: Un livello unico che si trova al di sopra di tutti gli altri, consentendo agli oggetti a questo livello di disinstallare qualsiasi altro oggetto.

Puoi ottenere il livello di integrità di un processo utilizzando **Process Explorer** di **Sysinternals**, accedendo alle **proprietà** del processo e visualizzando la scheda "**Sicurezza**":

![](<../../.gitbook/assets/image (821).png>)

Puoi anche ottenere il tuo **livello di integrità attuale** utilizzando `whoami /groups`

![](<../../.gitbook/assets/image (322).png>)

### Livelli di integrità nel file-system

Un oggetto all'interno del file-system può richiedere un **requisito minimo di livello di integrità** e se un processo non ha questo livello di integrità, non sarà in grado di interagire con esso.\
Ad esempio, vediamo **creare un file regolare da una console utente regolare e controllare le autorizzazioni**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Ora, assegniamo un livello di integrità minimo di **Alto** al file. Questo **deve essere fatto da una console** in esecuzione come **amministratore** poiché una **console regolare** funzionerà a livello di integrità Medio e **non sarà autorizzata** ad assegnare il livello di integrità Alto a un oggetto:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Questo è il punto in cui le cose diventano interessanti. Puoi vedere che l'utente `DESKTOP-IDJHTKP\user` ha **privilegi COMPLETI** sul file (infatti è stato l'utente che ha creato il file), tuttavia, a causa del livello di integrità minimo implementato, non sarà in grado di modificare il file a meno che non stia eseguendo all'interno di un Livello di Integrità Elevato (nota che sarà in grado di leggerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Pertanto, quando un file ha un livello di integrità minimo, per modificarlo è necessario eseguire almeno a quel livello di integrità.**
{% endhint %}

### Livelli di integrità nei file binari

Ho creato una copia di `cmd.exe` in `C:\Windows\System32\cmd-low.exe` e ho impostato un **livello di integrità basso da una console amministrativa:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ora, quando eseguo `cmd-low.exe` **verrà eseguito con un livello di integrità basso** invece che medio:

![](<../../.gitbook/assets/image (310).png>)

Per le persone curiose, se si assegna un livello di integrità alto a un file eseguibile (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) non verrà eseguito automaticamente con un livello di integrità alto (se lo si invoca da un livello di integrità medio --per impostazione predefinita-- verrà eseguito con un livello di integrità medio).

### Livelli di Integrità nei Processi

Non tutti i file e le cartelle hanno un livello di integrità minimo, **ma tutti i processi vengono eseguiti con un livello di integrità**. E simile a quanto accade con il file-system, **se un processo vuole scrivere all'interno di un altro processo deve avere almeno lo stesso livello di integrità**. Ciò significa che un processo con livello di integrità basso non può aprire un handle con accesso completo a un processo con livello di integrità medio.

A causa delle restrizioni commentate in questa e nella sezione precedente, da un punto di vista della sicurezza, è sempre **consigliabile eseguire un processo con il livello di integrità più basso possibile**.


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
