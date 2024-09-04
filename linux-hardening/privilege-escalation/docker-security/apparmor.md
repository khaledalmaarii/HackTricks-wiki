# AppArmor

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

AppArmor è un **miglioramento del kernel progettato per limitare le risorse disponibili ai programmi attraverso profili per programma**, implementando efficacemente il Controllo di Accesso Obbligatorio (MAC) legando gli attributi di controllo accesso direttamente ai programmi invece che agli utenti. Questo sistema opera **caricando profili nel kernel**, di solito durante l'avvio, e questi profili determinano quali risorse un programma può accedere, come connessioni di rete, accesso a socket raw e permessi di file.

Ci sono due modalità operative per i profili di AppArmor:

* **Modalità di Enforcement**: Questa modalità applica attivamente le politiche definite all'interno del profilo, bloccando le azioni che violano queste politiche e registrando eventuali tentativi di violarle attraverso sistemi come syslog o auditd.
* **Modalità di Complain**: A differenza della modalità di enforcement, la modalità di complain non blocca le azioni che vanno contro le politiche del profilo. Invece, registra questi tentativi come violazioni delle politiche senza applicare restrizioni.

### Components of AppArmor

* **Modulo del Kernel**: Responsabile dell'applicazione delle politiche.
* **Politiche**: Specificano le regole e le restrizioni per il comportamento dei programmi e l'accesso alle risorse.
* **Parser**: Carica le politiche nel kernel per l'applicazione o la segnalazione.
* **Utilità**: Questi sono programmi in modalità utente che forniscono un'interfaccia per interagire e gestire AppArmor.

### Profiles path

I profili di AppArmor sono solitamente salvati in _**/etc/apparmor.d/**_\
Con `sudo aa-status` sarai in grado di elencare i binari che sono limitati da qualche profilo. Se puoi cambiare il carattere "/" con un punto nel percorso di ciascun binario elencato, otterrai il nome del profilo di AppArmor all'interno della cartella menzionata.

Ad esempio, un **profilo di apparmor** per _/usr/bin/man_ si troverà in _/etc/apparmor.d/usr.bin.man_

### Commands
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

* Per indicare l'eseguibile interessato, **sono consentiti percorsi assoluti e caratteri jolly** per specificare i file.
* Per indicare l'accesso che il binario avrà su **file**, possono essere utilizzati i seguenti **controlli di accesso**:
* **r** (lettura)
* **w** (scrittura)
* **m** (mappatura della memoria come eseguibile)
* **k** (blocco file)
* **l** (creazione di hard link)
* **ix** (eseguire un altro programma con la nuova politica ereditata)
* **Px** (eseguire sotto un altro profilo, dopo aver ripulito l'ambiente)
* **Cx** (eseguire sotto un profilo figlio, dopo aver ripulito l'ambiente)
* **Ux** (eseguire senza restrizioni, dopo aver ripulito l'ambiente)
* **Le variabili** possono essere definite nei profili e possono essere manipolate dall'esterno del profilo. Ad esempio: @{PROC} e @{HOME} (aggiungere #include \<tunables/global> al file del profilo)
* **Le regole di negazione sono supportate per sovrascrivere le regole di autorizzazione**.

### aa-genprof

Per iniziare facilmente a creare un profilo, apparmor può aiutarti. È possibile far sì che **apparmor ispezioni le azioni eseguite da un binario e poi ti consenta di decidere quali azioni vuoi consentire o negare**.\
Devi solo eseguire:
```bash
sudo aa-genprof /path/to/binary
```
Poi, in una console diversa, esegui tutte le azioni che il binario eseguirà di solito:
```bash
/path/to/binary -a dosomething
```
Poi, nella prima console premi "**s**" e poi nelle azioni registrate indica se vuoi ignorare, consentire o altro. Quando hai finito premi "**f**" e il nuovo profilo sarà creato in _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Utilizzando i tasti freccia puoi selezionare cosa vuoi consentire/negare/altro
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
Nota che per impostazione predefinita in un profilo creato nulla è consentito, quindi tutto è negato. Dovrai aggiungere righe come `/etc/passwd r,` per consentire la lettura binaria di `/etc/passwd`, ad esempio.
{% endhint %}

Puoi quindi **applicare** il nuovo profilo con
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modifica di un profilo dai log

Il seguente strumento leggerà i log e chiederà all'utente se desidera consentire alcune delle azioni vietate rilevate:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Utilizzando i tasti freccia puoi selezionare cosa vuoi consentire/negare/qualunque cosa
{% endhint %}

### Gestire un Profilo
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Esempio di log **AUDIT** e **DENIED** da _/var/log/audit/audit.log_ dell'eseguibile **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Puoi anche ottenere queste informazioni utilizzando:
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

Nota come il profilo **docker-profile** di docker venga caricato per impostazione predefinita:
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
Di default, il **profilo docker-default di Apparmor** è generato da [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Riepilogo del profilo docker-default**:

* **Accesso** a tutte le **reti**
* **Nessuna capacità** è definita (Tuttavia, alcune capacità deriveranno dall'inclusione di regole di base, ad es. #include \<abstractions/base>)
* **Scrivere** in qualsiasi file di **/proc** **non è consentito**
* Altre **sottodirectory**/**file** di /**proc** e /**sys** hanno accesso in lettura/scrittura/blocco/link/esecuzione **negato**
* **Montaggio** **non è consentito**
* **Ptrace** può essere eseguito solo su un processo che è confinato dallo **stesso profilo apparmor**

Una volta che **esegui un container docker**, dovresti vedere il seguente output:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Nota che **apparmor bloccherà anche i privilegi delle capacità** concessi al container per impostazione predefinita. Ad esempio, sarà in grado di **bloccare il permesso di scrivere all'interno di /proc anche se la capacità SYS\_ADMIN è concessa** perché per impostazione predefinita il profilo apparmor di docker nega questo accesso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Devi **disabilitare apparmor** per bypassare le sue restrizioni:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Nota che per impostazione predefinita **AppArmor** **vietera' anche al container di montare** cartelle dall'interno anche con la capacità SYS\_ADMIN.

Nota che puoi **aggiungere/rimuovere** **capacità** al container docker (questo sarà comunque limitato da metodi di protezione come **AppArmor** e **Seccomp**):

* `--cap-add=SYS_ADMIN` dà la capacità `SYS_ADMIN`
* `--cap-add=ALL` dà tutte le capacità
* `--cap-drop=ALL --cap-add=SYS_PTRACE` rimuove tutte le capacità e dà solo `SYS_PTRACE`

{% hint style="info" %}
Di solito, quando **scopri** di avere una **capacità privilegiata** disponibile **all'interno** di un **container** **docker** **ma** che alcune parti dell'**exploit non funzionano**, questo sarà perché **apparmor di docker lo impedirà**.
{% endhint %}

### Esempio

(Esempio da [**qui**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Per illustrare la funzionalità di AppArmor, ho creato un nuovo profilo Docker “mydocker” con la seguente riga aggiunta:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Per attivare il profilo, dobbiamo fare quanto segue:
```
sudo apparmor_parser -r -W mydocker
```
Per elencare i profili, possiamo eseguire il seguente comando. Il comando qui sotto sta elencando il mio nuovo profilo AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Come mostrato di seguito, otteniamo un errore quando cerchiamo di modificare “/etc/” poiché il profilo AppArmor impedisce l'accesso in scrittura a “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Puoi scoprire quale **profilo apparmor sta eseguendo un container** usando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Poi, puoi eseguire la seguente riga per **trovare il profilo esatto in uso**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In the weird case you can **modificare il profilo docker di apparmor e ricaricarlo.** Potresti rimuovere le restrizioni e "bypassarle".

### AppArmor Docker Bypass2

**AppArmor è basato su percorso**, questo significa che anche se potrebbe **proteggere** file all'interno di una directory come **`/proc`**, se puoi **configurare come verrà eseguito il container**, potresti **montare** la directory proc dell'host all'interno di **`/host/proc`** e non **sarà più protetta da AppArmor**.

### AppArmor Shebang Bypass

In [**questo bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) puoi vedere un esempio di come **anche se stai impedendo l'esecuzione di perl con determinate risorse**, se crei semplicemente uno script shell **specificando** nella prima riga **`#!/usr/bin/perl`** e **esegui il file direttamente**, sarai in grado di eseguire qualsiasi cosa tu voglia. E.g.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository github.

</details>
{% endhint %}
