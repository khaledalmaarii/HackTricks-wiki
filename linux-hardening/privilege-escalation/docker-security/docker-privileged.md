# Docker --privileged

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Τι Επηρεάζει

Όταν εκτελείτε ένα container με τα δικαιώματα privileged, απενεργοποιείτε τις παρακάτω προστασίες:

### Προσάρτηση /dev

Σε ένα privileged container, όλες οι **συσκευές μπορούν να προσπελαστούν στο `/dev/`**. Επομένως, μπορείτε να **δραπετεύσετε** προσαρτώντας το δίσκο του host.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Μέσα σε ένα Προνομιούχο Εμπορευματοκιβώτιο" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
{% endtab %}
{% endtabs %}

### Ανάγνωση μόνο των αρχείων συστήματος του πυρήνα

Τα αρχεία συστήματος του πυρήνα παρέχουν ένα μηχανισμό για ένα διεργασία να τροποποιήσει τη συμπεριφορά του πυρήνα. Ωστόσο, όσον αφορά τις διεργασίες ενός εμπορεύματος, θέλουμε να τους εμποδίσουμε από το να κάνουν οποιεσδήποτε αλλαγές στον πυρήνα. Για τον λόγο αυτό, προσαρτούμε τα αρχεία συστήματος του πυρήνα ως **μόνο για ανάγνωση** μέσα στο εμπόρευμα, εξασφαλίζοντας ότι οι διεργασίες του εμπορεύματος δεν μπορούν να τροποποιήσουν τον πυρήνα.

```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```

```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```

### Μάσκαρε τα αρχεία συστήματος πυρήνα

Το σύστημα αρχείων **/proc** είναι εκλεκτικά εγγράψιμο, αλλά για λόγους ασφαλείας, ορισμένα μέρη προστατεύονται από εγγραφή και ανάγνωση με την επικάλυψή τους με το **tmpfs**, εξασφαλίζοντας ότι οι διεργασίες του εμπορεύματος δεν μπορούν να έχουν πρόσβαση σε ευαίσθητες περιοχές.

{% hint style="info" %}
Το **tmpfs** είναι ένα σύστημα αρχείων που αποθηκεύει όλα τα αρχεία στην εικονική μνήμη. Το tmpfs δεν δημιουργεί κανένα αρχείο στον σκληρό σας δίσκο. Έτσι, αν αποσυναρμολογήσετε ένα σύστημα αρχείων tmpfs, όλα τα αρχεία που βρίσκονται σε αυτό χάνονται για πάντα.
{% endhint %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Μέσα σε ένα Προνομιούχο Εμπορευματοκιβώτιο" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Δυνατότητες Linux

Οι μηχανές εκτέλεσης εμφυτεύουν τα containers με έναν **περιορισμένο αριθμό δυνατοτήτων** για να ελέγχουν τι συμβαίνει μέσα στο container από προεπιλογή. Τα **προνομιούχα** έχουν **πρόσβαση σε όλες** τις **δυνατότητες**. Για να μάθετε περισσότερα για τις δυνατότητες, διαβάστε:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Μέσα σε ένα Προνομιούχο Εμπορευματοκιβώτιο" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

Μπορείτε να παραμετροποιήσετε τις δυνατότητες που είναι διαθέσιμες σε ένα container χωρίς να τρέχει σε κατάσταση `--privileged` χρησιμοποιώντας τις σημαίες `--cap-add` και `--cap-drop`.

### Seccomp

Το **Seccomp** είναι χρήσιμο για να **περιορίσει** τις **κλήσεις συστήματος** που μπορεί να κάνει ένα container. Ένα προεπιλεγμένο προφίλ Seccomp είναι ενεργοποιημένο από προεπιλογή όταν τρέχουν τα containers του Docker, αλλά σε προνομιούχο καθεστώς είναι απενεργοποιημένο. Μάθετε περισσότερα για το Seccomp εδώ:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Μέσα σε ένα Προνομιούχο Εμπορευματοκιβώτιο" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}

```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```

Επίσης, σημειώστε ότι όταν το Docker (ή άλλα CRIs) χρησιμοποιούνται σε ένα **Kubernetes** cluster, ο **φίλτρος seccomp είναι απενεργοποιημένος από προεπιλογή**.

### AppArmor

Το **AppArmor** είναι μια ενίσχυση του πυρήνα για τον περιορισμό των **containers** σε ένα **περιορισμένο** σύνολο **πόρων** με **προφίλ ανά πρόγραμμα**. Όταν εκτελείτε με τη σημαία `--privileged`, αυτή η προστασία απενεργοποιείται.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```

### SELinux

Η εκτέλεση ενός container με την σημαία `--privileged` απενεργοποιεί τις **ετικέτες SELinux**, προκαλώντας την κληρονομική λήψη της ετικέτας της μηχανής του container, συνήθως `unconfined`, παρέχοντας πλήρη πρόσβαση παρόμοια με τη μηχανή του container. Στη λειτουργία χωρίς ρίζες, χρησιμοποιείται το `container_runtime_t`, ενώ στη λειτουργία ρίζας εφαρμόζεται το `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```

## Τι δεν επηρεάζεται

### Ονοματοχώροι

Οι ονοματοχώροι **ΔΕΝ επηρεάζονται** από την σημαία `--privileged`. Αν και δεν έχουν ενεργοποιημένους περιορισμούς ασφαλείας, **δεν βλέπουν όλες τις διεργασίες στο σύστημα ή το δίκτυο του οικοδεσπότη, για παράδειγμα**. Οι χρήστες μπορούν να απενεργοποιήσουν μεμονωμένους ονοματοχώρους χρησιμοποιώντας τις σημαίες `--pid=host`, `--net=host`, `--ipc=host`, `--uts=host` των μηχανισμών εκτέλεσης των εμπορευματοκιβωτίων.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Μέσα στον επιλεγμένο --pid=host Container" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### Ονοματοχώρηση χρήστη

**Από προεπιλογή, οι μηχανές εκτέλεσης εμπορευματοκιβωτίων δεν χρησιμοποιούν ονοματοχώρηση χρήστη, εκτός από τα εμπορευματοκιβώτια χωρίς ρίζα**, τα οποία την απαιτούν για την προσάρτηση του συστήματος αρχείων και τη χρήση πολλαπλών UID. Η ονοματοχώρηση χρήστη, η οποία είναι απαραίτητη για τα εμπορευματοκιβώτια χωρίς ρίζα, δεν μπορεί να απενεργοποιηθεί και βελτιώνει σημαντικά την ασφάλεια περιορίζοντας τα προνόμια.

## Αναφορές

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
