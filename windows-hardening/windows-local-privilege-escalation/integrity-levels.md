# Livelli di Integrità

{% hint style="success" %}
Impara e pratica il Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

## Livelli di Integrità

In Windows Vista e versioni successive, tutti gli elementi protetti hanno un tag di **livello di integrità**. Questa configurazione assegna principalmente un livello di integrità "medio" a file e chiavi di registro, tranne per alcune cartelle e file a cui Internet Explorer 7 può scrivere a un livello di integrità basso. Il comportamento predefinito è che i processi avviati da utenti standard abbiano un livello di integrità medio, mentre i servizi operano tipicamente a un livello di integrità di sistema. Un'etichetta di alta integrità protegge la directory radice.

Una regola fondamentale è che gli oggetti non possono essere modificati da processi con un livello di integrità inferiore a quello dell'oggetto. I livelli di integrità sono:

* **Non attendibile**: Questo livello è per processi con accessi anonimi. %%%Esempio: Chrome%%%
* **Basso**: Principalmente per interazioni internet, specialmente nella Modalità Protetta di Internet Explorer, che influisce su file e processi associati, e su alcune cartelle come la **Cartella Temporanea di Internet**. I processi a bassa integrità affrontano restrizioni significative, inclusa l'assenza di accesso in scrittura al registro e accesso limitato in scrittura al profilo utente.
* **Medio**: Il livello predefinito per la maggior parte delle attività, assegnato a utenti standard e oggetti senza livelli di integrità specifici. Anche i membri del gruppo Amministratori operano a questo livello per impostazione predefinita.
* **Alto**: Riservato agli amministratori, consentendo loro di modificare oggetti a livelli di integrità inferiori, inclusi quelli allo stesso livello alto.
* **Sistema**: Il livello operativo più alto per il kernel di Windows e i servizi core, fuori portata anche per gli amministratori, garantendo la protezione delle funzioni vitali del sistema.
* **Installer**: Un livello unico che si trova al di sopra di tutti gli altri, consentendo agli oggetti a questo livello di disinstallare qualsiasi altro oggetto.

Puoi ottenere il livello di integrità di un processo utilizzando **Process Explorer** di **Sysinternals**, accedendo alle **proprietà** del processo e visualizzando la scheda "**Sicurezza**":

![](<../../.gitbook/assets/image (824).png>)

Puoi anche ottenere il tuo **livello di integrità attuale** usando `whoami /groups`

![](<../../.gitbook/assets/image (325).png>)

### Livelli di Integrità nel File-system

Un oggetto all'interno del file-system potrebbe avere un **requisito minimo di livello di integrità** e se un processo non ha questo livello di integrità non sarà in grado di interagire con esso.\
Ad esempio, creiamo **un file regolare da una console di utente regolare e controlliamo i permessi**:
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
Ora, assegniamo un livello di integrità minimo di **High** al file. Questo **deve essere fatto da una console** eseguita come **amministratore** poiché una **console regolare** funzionerà a livello di integrità Medio e **non sarà autorizzata** ad assegnare un livello di integrità Alto a un oggetto:
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
Questo è il punto in cui le cose diventano interessanti. Puoi vedere che l'utente `DESKTOP-IDJHTKP\user` ha **privilegi COMPLETI** sul file (infatti, questo era l'utente che ha creato il file), tuttavia, a causa del livello di integrità minimo implementato, non sarà in grado di modificare il file a meno che non stia eseguendo all'interno di un High Integrity Level (nota che sarà in grado di leggerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Pertanto, quando un file ha un livello di integrità minimo, per modificarlo è necessario essere in esecuzione almeno a quel livello di integrità.**
{% endhint %}

### Livelli di Integrità nei Binaries

Ho fatto una copia di `cmd.exe` in `C:\Windows\System32\cmd-low.exe` e gli ho impostato un **livello di integrità basso da una console di amministratore:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ora, quando eseguo `cmd-low.exe`, esso **verrà eseguito con un livello di integrità basso** invece di uno medio:

![](<../../.gitbook/assets/image (313).png>)

Per le persone curiose, se assegni un alto livello di integrità a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), non verrà eseguito automaticamente con un alto livello di integrità (se lo invochi da un livello di integrità medio --per impostazione predefinita-- verrà eseguito con un livello di integrità medio).

### Livelli di Integrità nei Processi

Non tutti i file e le cartelle hanno un livello di integrità minimo, **ma tutti i processi vengono eseguiti con un livello di integrità**. E simile a quanto accaduto con il file system, **se un processo vuole scrivere all'interno di un altro processo deve avere almeno lo stesso livello di integrità**. Questo significa che un processo con un livello di integrità basso non può aprire un handle con accesso completo a un processo con livello di integrità medio.

A causa delle restrizioni commentate in questa e nella sezione precedente, da un punto di vista della sicurezza, è sempre **raccomandato eseguire un processo al livello di integrità più basso possibile**.
