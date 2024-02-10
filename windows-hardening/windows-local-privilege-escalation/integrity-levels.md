<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub.**

</details>


# Livelli di integrità

In Windows Vista e nelle versioni successive, tutti gli elementi protetti sono contrassegnati da un **livello di integrità**. Questa configurazione assegna principalmente un livello di integrità "medio" ai file e alle chiavi di registro, ad eccezione di determinate cartelle e file su cui Internet Explorer 7 può scrivere a un livello di integrità basso. Il comportamento predefinito prevede che i processi avviati dagli utenti standard abbiano un livello di integrità medio, mentre i servizi operano tipicamente a un livello di integrità di sistema. Una etichetta di alta integrità protegge la directory radice.

Una regola chiave è che gli oggetti non possono essere modificati da processi con un livello di integrità inferiore rispetto al livello dell'oggetto. I livelli di integrità sono:

- **Non attendibile**: Questo livello è per i processi con accessi anonimi. %%%Esempio: Chrome%%%
- **Basso**: Principalmente per le interazioni su Internet, specialmente nella modalità protetta di Internet Explorer, che influisce su file e processi associati e su determinate cartelle come la **Cartella Internet Temporanea**. I processi a bassa integrità sono soggetti a restrizioni significative, tra cui l'accesso in scrittura al registro e l'accesso limitato alla scrittura del profilo utente.
- **Medio**: Il livello predefinito per la maggior parte delle attività, assegnato agli utenti standard e agli oggetti senza livelli di integrità specifici. Anche i membri del gruppo Amministratori operano a questo livello per impostazione predefinita.
- **Alto**: Riservato agli amministratori, consente loro di modificare oggetti a livelli di integrità inferiori, compresi quelli a livello alto stesso.
- **Sistema**: Il livello operativo più elevato per il kernel di Windows e i servizi di base, fuori dalla portata anche degli amministratori, garantendo la protezione delle funzioni vitali del sistema.
- **Installatore**: Un livello unico che si trova al di sopra di tutti gli altri, consente agli oggetti a questo livello di disinstallare qualsiasi altro oggetto.

È possibile ottenere il livello di integrità di un processo utilizzando **Process Explorer** di **Sysinternals**, accedendo alle **proprietà** del processo e visualizzando la scheda "**Sicurezza**":

![](<../../.gitbook/assets/image (318).png>)

È anche possibile ottenere il **livello di integrità corrente** utilizzando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Livelli di integrità nel file system

Un oggetto all'interno del file system può richiedere un **requisito minimo di livello di integrità** e se un processo non ha questo livello di integrità non sarà in grado di interagire con esso.\
Ad esempio, creiamo un **file regolare da una console utente regolare e verifichiamo i permessi**:
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
Ora, assegniamo un livello di integrità minimo di **Alto** al file. Questo **deve essere fatto da una console** in esecuzione come **amministratore**, poiché una **console normale** viene eseguita con un livello di integrità Medio e **non sarà consentito** assegnare un livello di integrità Alto a un oggetto:
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
Qui le cose si fanno interessanti. Puoi vedere che l'utente `DESKTOP-IDJHTKP\user` ha **privilegi COMPLETI** sul file (infatti è stato l'utente che ha creato il file), tuttavia, a causa del livello di integrità minimo implementato, non sarà in grado di modificare il file a meno che non stia eseguendo con un livello di integrità elevato (nota che sarà comunque in grado di leggerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Pertanto, quando un file ha un livello di integrità minimo, per modificarlo è necessario eseguirlo almeno a quel livello di integrità.**
{% endhint %}

## Livelli di integrità nei binari

Ho creato una copia di `cmd.exe` in `C:\Windows\System32\cmd-low.exe` e ho impostato un **livello di integrità basso da una console di amministratore:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ora, quando eseguo `cmd-low.exe`, verrà **eseguito con un livello di integrità basso** invece di uno medio:

![](<../../.gitbook/assets/image (320).png>)

Per le persone curiose, se si assegna un livello di integrità elevato a un file binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), non verrà eseguito automaticamente con un livello di integrità elevato (se viene richiamato da un livello di integrità medio - per impostazione predefinita - verrà eseguito con un livello di integrità medio).

## Livelli di integrità nei processi

Non tutti i file e le cartelle hanno un livello di integrità minimo, **ma tutti i processi vengono eseguiti con un livello di integrità**. E simile a quanto accade con il file system, **se un processo vuole scrivere all'interno di un altro processo, deve avere almeno lo stesso livello di integrità**. Ciò significa che un processo con un livello di integrità basso non può aprire un handle con accesso completo a un processo con un livello di integrità medio.

A causa delle restrizioni commentate in questa e nella sezione precedente, dal punto di vista della sicurezza, è sempre **consigliato eseguire un processo con il livello di integrità più basso possibile**.


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
