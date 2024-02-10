# AppArmor

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub.**

</details>

## Informazioni di base

AppArmor è un **miglioramento del kernel progettato per limitare le risorse disponibili ai programmi attraverso profili specifici per ogni programma**, implementando efficacemente il Controllo di Accesso Obbligatorio (MAC) collegando direttamente gli attributi di controllo degli accessi ai programmi anziché agli utenti. Questo sistema opera **caricando i profili nel kernel**, di solito durante l'avvio, e questi profili indicano quali risorse un programma può accedere, come connessioni di rete, accesso a socket raw e autorizzazioni dei file.

Ci sono due modalità operative per i profili di AppArmor:

- **Modalità di applicazione**: questa modalità applica attivamente le politiche definite all'interno del profilo, bloccando le azioni che violano queste politiche e registrando qualsiasi tentativo di violarle tramite sistemi come syslog o auditd.
- **Modalità di lamentela**: a differenza della modalità di applicazione, la modalità di lamentela non blocca le azioni che vanno contro le politiche del profilo. Invece, registra questi tentativi come violazioni delle politiche senza imporre restrizioni.

### Componenti di AppArmor

- **Modulo del kernel**: responsabile dell'applicazione delle politiche.
- **Politiche**: specificano le regole e le restrizioni per il comportamento del programma e l'accesso alle risorse.
- **Parser**: carica le politiche nel kernel per l'applicazione o la segnalazione.
- **Utility**: sono programmi in modalità utente che forniscono un'interfaccia per interagire e gestire AppArmor.

### Percorso dei profili

I profili di AppArmor di solito vengono salvati in _**/etc/apparmor.d/**_\
Con `sudo aa-status` sarai in grado di elencare i binari che sono limitati da qualche profilo. Se puoi cambiare il carattere "/" con un punto del percorso di ogni binario elencato, otterrai il nome del profilo di apparmor all'interno della cartella menzionata.

Ad esempio, un profilo **apparmor** per _/usr/bin/man_ sarà situato in _/etc/apparmor.d/usr.bin.man_

### Comandi
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Creazione di un profilo

* Per indicare l'eseguibile interessato, sono consentiti **percorsi assoluti e caratteri jolly** (per la ricerca di file) per specificare i file.
* Per indicare l'accesso che il binario avrà sui **file**, possono essere utilizzati i seguenti **controlli di accesso**:
* **r** (lettura)
* **w** (scrittura)
* **m** (mappatura in memoria come eseguibile)
* **k** (blocco file)
* **l** (creazione di collegamenti rigidi)
* **ix** (per eseguire un altro programma con il nuovo programma che eredita la politica)
* **Px** (eseguire sotto un altro profilo, dopo aver pulito l'ambiente)
* **Cx** (eseguire sotto un profilo figlio, dopo aver pulito l'ambiente)
* **Ux** (eseguire senza restrizioni, dopo aver pulito l'ambiente)
* È possibile definire **variabili** nei profili e possono essere manipolate dall'esterno del profilo. Ad esempio: @{PROC} e @{HOME} (aggiungere #include \<tunables/global> al file del profilo)
* **Le regole di negazione sono supportate per sovrascrivere le regole di autorizzazione**.

### aa-genprof

Per iniziare facilmente a creare un profilo, apparmor può aiutarti. È possibile fare in modo che **apparmor ispezioni le azioni eseguite da un binario e quindi ti consenta di decidere quali azioni desideri consentire o negare**.\
Basta eseguire:
```bash
sudo aa-genprof /path/to/binary
```
Quindi, in una console diversa, esegui tutte le azioni che di solito il binario eseguirà:
```bash
/path/to/binary -a dosomething
```
Quindi, nella prima console premi "**s**" e poi indica le azioni registrate se vuoi ignorarle, consentirle o altro. Quando hai finito premi "**f**" e il nuovo profilo verrà creato in _/etc/apparmor.d/percorso.del.binario_

{% hint style="info" %}
Utilizzando i tasti freccia puoi selezionare ciò che desideri consentire/negare/altro
{% endhint %}

### aa-easyprof

Puoi anche creare un modello di un profilo apparmor di un binario con:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Nota che per impostazione predefinita in un profilo creato nulla è consentito, quindi tutto è negato. Dovrai aggiungere righe come `/etc/passwd r,` per consentire la lettura del file binario `/etc/passwd`, ad esempio.
{% endhint %}

Puoi quindi **applicare** il nuovo profilo con
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modifica di un profilo dai log

Lo strumento seguente leggerà i log e chiederà all'utente se desidera consentire alcune delle azioni vietate rilevate:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Utilizzando i tasti freccia puoi selezionare ciò che desideri consentire/negare/qualsiasi cosa
{% endhint %}

### Gestione di un profilo
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Registri

Esempio di registri **AUDIT** e **DENIED** dal file _/var/log/audit/audit.log_ dell'eseguibile **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Puoi ottenere queste informazioni anche utilizzando:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

Nota come il profilo **docker-profile** di Docker venga caricato di default:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Di default, il profilo **Apparmor docker-default** viene generato da [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Sommario del profilo docker-default**:

* **Accesso** a tutte le **connessioni di rete**
* **Nessuna capacità** è definita (Tuttavia, alcune capacità verranno incluse dalle regole di base di base, ad esempio #include \<abstractions/base>)
* **Non è consentito scrivere** su qualsiasi file **/proc**
* Altre **sottodirectory**/**file** di /**proc** e /**sys** sono **negati** l'accesso in lettura/scrittura/blocco/link/esecuzione
* **Montaggio** non è consentito
* **Ptrace** può essere eseguito solo su un processo confinato dallo stesso profilo apparmor

Una volta che **avvii un container docker**, dovresti vedere il seguente output:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Si noti che **apparmor bloccherà anche i privilegi delle capacità** concessi al contenitore per impostazione predefinita. Ad esempio, sarà in grado di **bloccare il permesso di scrivere all'interno di /proc anche se è concessa la capacità SYS\_ADMIN**, perché il profilo apparmor di Docker nega questo accesso per impostazione predefinita:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Devi **disabilitare apparmor** per eludere le sue restrizioni:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Nota che di default **AppArmor** vieta anche al container di montare cartelle dall'interno anche con la capacità SYS_ADMIN.

Nota che puoi **aggiungere/rimuovere** **capacità** al container Docker (questo sarà comunque limitato da metodi di protezione come **AppArmor** e **Seccomp**):

* `--cap-add=SYS_ADMIN` dà la capacità `SYS_ADMIN`
* `--cap-add=ALL` dà tutte le capacità
* `--cap-drop=ALL --cap-add=SYS_PTRACE` rimuove tutte le capacità e dà solo `SYS_PTRACE`

{% hint style="info" %}
Di solito, quando **trovi** che hai una **capacità privilegiata** disponibile **all'interno** di un **container docker ma** una parte dell'**exploit non funziona**, questo sarà perché **AppArmor di docker lo sta impedendo**.
{% endhint %}

### Esempio

(Esempio da [**qui**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Per illustrare la funzionalità di AppArmor, ho creato un nuovo profilo Docker "mydocker" con la seguente riga aggiunta:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Per attivare il profilo, è necessario seguire i seguenti passaggi:
```
sudo apparmor_parser -r -W mydocker
```
Per elencare i profili, possiamo eseguire il seguente comando. Il comando qui sotto sta elencando il mio nuovo profilo AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Come mostrato di seguito, otteniamo un errore quando cerchiamo di modificare "/etc/" poiché il profilo di AppArmor impedisce l'accesso in scrittura a "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

È possibile trovare quale **profilo AppArmor sta eseguendo un container** utilizzando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Quindi, puoi eseguire la seguente linea per **trovare il profilo esatto in uso**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Nel caso strano in cui è possibile **modificare il profilo apparmor di Docker e ricaricarlo**, è possibile rimuovere le restrizioni e "bypassarle".

### Bypass di AppArmor Docker 2

**AppArmor è basato sul percorso**, ciò significa che anche se potrebbe **proteggere** i file all'interno di una directory come **`/proc`**, se è possibile **configurare come verrà eseguito il contenitore**, è possibile **montare** la directory proc dell'host all'interno di **`/host/proc`** e non sarà più protetta da AppArmor.

### Bypass di AppArmor Shebang

In [**questo bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) puoi vedere un esempio di come **anche se stai impedendo l'esecuzione di perl con determinate risorse**, se crei semplicemente uno script shell **specificando** nella prima riga **`#!/usr/bin/perl`** e **esegui direttamente il file**, sarai in grado di eseguire ciò che desideri. Ad esempio:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
