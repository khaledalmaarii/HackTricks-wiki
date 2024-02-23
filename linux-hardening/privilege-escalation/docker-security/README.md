# Ασφάλεια Docker

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Βασική Ασφάλεια του Docker Engine**

Το **Docker engine** χρησιμοποιεί τα **Namespaces** και **Cgroups** του πυρήνα του Linux για την απομόνωση των containers, προσφέροντας ένα βασικό επίπεδο ασφάλειας. Επιπλέον προστασία παρέχεται μέσω της **απόρριψης δυνατοτήτων (Capabilities dropping)**, του **Seccomp**, και του **SELinux/AppArmor**, ενισχύοντας την απομόνωση των containers. Ένα **πρόσθετο πιστοποίησης (auth plugin)** μπορεί να περιορίσει περαιτέρω τις ενέργειες του χρήστη.

![Ασφάλεια Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Ασφαλής Πρόσβαση στο Docker Engine

Το Docker engine μπορεί να προσπελαστεί είτε τοπικά μέσω ενός Unix socket είτε απομακρυσμένα χρησιμοποιώντας HTTP. Για την απομακρυσμένη πρόσβαση, είναι απαραίτητο να χρησιμοποιηθεί το HTTPS και το **TLS** για να διασφαλιστεί η εμπιστευτικότητα, η ακεραιότητα και η ταυτοποίηση.

Το Docker engine, από προεπιλογή, ακούει στο Unix socket στη διεύθυνση `unix:///var/run/docker.sock`. Στα συστήματα Ubuntu, οι επιλογές εκκίνησης του Docker ορίζονται στο `/etc/default/docker`. Για να επιτρέψετε την απομακρυσμένη πρόσβαση στο API και τον πελάτη του Docker, εκθέστε τον δαίμονα του Docker μέσω ενός socket HTTP προσθέτοντας τις παρακάτω ρυθμίσεις:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Ωστόσο, δεν συνιστάται η εκθεση του Docker daemon μέσω HTTP λόγω ανησυχιών ασφαλείας. Συνιστάται να ασφαλίσετε τις συνδέσεις χρησιμοποιώντας HTTPS. Υπάρχουν δύο κύριες προσεγγίσεις για την ασφάλεια της σύνδεσης:

1. Ο πελάτης επαληθεύει την ταυτότητα του διακομιστή.
2. Τόσο ο πελάτης όσο και ο διακομιστής αυθεντικοποιούν αμοιβαία την ταυτότητα τους.

Τα πιστοποιητικά χρησιμοποιούνται για την επιβεβαίωση της ταυτότητας του διακομιστή. Για λεπτομερείς παραδείγματα και των δύο μεθόδων, ανατρέξτε στο [**αυτό τον οδηγό**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Ασφάλεια των Εικόνων Εμφυτευμάτων

Οι εικόνες εμφυτευμάτων μπορούν να αποθηκευτούν είτε σε ιδιωτικούς είτε σε δημόσιους αποθηκευτικούς χώρους. Το Docker προσφέρει αρκετές επιλογές αποθήκευσης για τις εικόνες εμφυτευμάτων:

* [**Docker Hub**](https://hub.docker.com): Ένα δημόσιο υπηρεσία αποθετηρίου από το Docker.
* [**Docker Registry**](https://github.com/docker/distribution): Ένα έργο ανοικτού κώδικα που επιτρέπει στους χρήστες να φιλοξενούν το δικό τους αποθετήριο.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Η εμπορική προσφορά αποθετηρίου του Docker, που περιλαμβάνει αυθεντικοποίηση χρηστών με βάση τον ρόλο και ολοκλήρωση με υπηρεσίες καταλόγου LDAP.

### Σάρωση Εικόνων

Οι εμφυτευμένες εικόνες μπορεί να έχουν **ευπάθειες ασφάλειας** είτε λόγω της βασικής εικόνας είτε λόγω του λογισμικού που είναι εγκατεστημένο πάνω στη βασική εικόνα. Το Docker εργάζεται σε ένα έργο που ονομάζεται **Nautilus** που κάνει σάρωση ασφάλειας των Εμφυτευμάτων και καταγράφει τις ευπάθειες. Το Nautilus λειτουργεί συγκρίνοντας κάθε επίπεδο εικόνας Εμφυτεύματος με το αποθετήριο ευπαθειών για την αναγνώριση των κενών ασφαλείας.

Για περισσότερες [**πληροφορίες διαβάστε αυτό**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Η εντολή **`docker scan`** σάρωσης σάς επιτρέπει να σαρώσετε υπάρχουσες εικόνες Docker χρησιμοποιώντας το όνομα ή το ID της εικόνας. Για παράδειγμα, εκτελέστε την ακόλουθη εντολή για να σαρώσετε την εικόνα hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Υπογραφή Εικόνων Docker

Η υπογραφή εικόνων Docker εξασφαλίζει την ασφάλεια και ακεραιότητα των εικόνων που χρησιμοποιούνται σε containers. Εδώ υπάρχει μια συνοπτική εξήγηση:

- **Εμπιστοσύνη Περιεχομένου Docker** χρησιμοποιεί το έργο Notary, βασισμένο στο The Update Framework (TUF), για τη διαχείριση της υπογραφής των εικόνων. Για περισσότερες πληροφορίες, δείτε [Notary](https://github.com/docker/notary) και [TUF](https://theupdateframework.github.io).
- Για να ενεργοποιήσετε την εμπιστοσύνη περιεχομένου Docker, ορίστε `export DOCKER_CONTENT_TRUST=1`. Αυτή η λειτουργία είναι απενεργοποιημένη από προεπιλογή στην έκδοση Docker 1.10 και μετά.
- Με αυτήν τη λειτουργία ενεργοποιημένη, μόνο υπογεγραμμένες εικόνες μπορούν να ληφθούν. Η πρώτη αποστολή εικόνας απαιτεί την ορισμό κωδικών πρόσβασης για τα κλειδιά ρίζας και ετικέτας, με το Docker να υποστηρίζει επίσης το Yubikey για ενισχυμένη ασφάλεια. Περισσότερες λεπτομέρειες μπορούν να βρεθούν [εδώ](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Η προσπάθεια να γίνει λήψη μιας μη υπογεγραμμένης εικόνας με την εμπιστοσύνη περιεχομένου ενεργοποιημένη οδηγεί σε σφάλμα "Δεν υπάρχουν δεδομένα εμπιστοσύνης για το τελευταίο".
- Για αποστολές εικόνων μετά την πρώτη, το Docker ζητά τον κωδικό πρόσβασης του κλειδιού αποθετηρίου για να υπογράψει την εικόνα.

Για να δημιουργήσετε αντίγραφο ασφαλείας των ιδιωτικών κλειδιών σας, χρησιμοποιήστε την εντολή:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Κατά τη μετάβαση σε νέους hosts του Docker, είναι απαραίτητο να μεταφερθούν τα root και repository keys για τη διατήρηση της λειτουργικότητας.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για εύκολη δημιουργία και **αυτοματοποίηση workflows** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Χαρακτηριστικά Ασφάλειας Εμπορευμάτων

<details>

<summary>Σύνοψη των Χαρακτηριστικών Ασφάλειας Εμπορευμάτων</summary>

#### Κύρια Χαρακτηριστικά Απομόνωσης Κύριων Διεργασιών

Σε περιβάλλοντα με εφαρμογές σε containers, η απομόνωση των έργων και των διεργασιών τους είναι ζωτικής σημασίας για την ασφάλεια και τη διαχείριση πόρων. Εδώ υπάρχει μια απλοποιημένη εξήγηση των βασικών έννοιων:

**Χώροι Ονομάτων (Namespaces)**

* **Σκοπός**: Βεβαιώνει την απομόνωση πόρων όπως διεργασίες, δίκτυο και συστήματα αρχείων. Ειδικά στο Docker, οι χώροι ονομάτων διατηρούν τις διεργασίες ενός container χωριστές από τον host και άλλα containers.
* **Χρήση της `unshare`**: Η εντολή `unshare` (ή η υποκείμενη κλήση συστήματος) χρησιμοποιείται για τη δημιουργία νέων χώρων ονομάτων, παρέχοντας ένα επιπλέον επίπεδο απομόνωσης. Ωστόσο, ενώ το Kubernetes δεν αποκλείει αυτό από μόνο του, το Docker το κάνει.
* **Περιορισμός**: Η δημιουργία νέων χώρων ονομάτων δεν επιτρέπει σε μια διεργασία να επανέλθει στους προεπιλεγμένους χώρους ονομάτων του host. Για να διεισδύσει στους χώρους ονομάτων του host, συνήθως απαιτείται πρόσβαση στον κατάλογο `/proc` του host, χρησιμοποιώντας το `nsenter` για είσοδο.

**Ομάδες Ελέγχου (CGroups)**

* **Λειτουργία**: Χρησιμοποιείται κυρίως για την κατανομή πόρων μεταξύ διεργασιών.
* **Ασφάλεια**: Οι CGroups από μόνες τους δεν προσφέρουν ασφάλεια απομόνωσης, εκτός από το χαρακτηριστικό `release_agent`, το οποίο, αν διαμορφωθεί εσφαλμένα, θα μπορούσε πιθανόν να εκμεταλλευτείται για μη εξουσιοδοτημένη πρόσβαση.

**Απόρριψη Δυνατοτήτων (Capability Drop)**

* **Σημασία**: Είναι ένα κρίσιμο χαρακτηριστικό ασφάλειας για την απομόνωση διεργασιών.
* **Λειτουργικότητα**: Περιορίζει τις ενέργειες που μπορεί να εκτελέσει μια διεργασία root απορρίπτοντας συγκεκριμένες δυνατότητες. Ακόμα κι αν μια διεργασία λειτουργεί με δικαιώματα root, η έλλειψη των απαραίτητων δυνατοτήτων την εμποδίζει από την εκτέλεση προνομιούχων ενεργειών, καθώς οι κλήσεις συστήματος θα αποτύχουν λόγω έλλειψης δικαιωμάτων.

Αυτές είναι οι **υπόλοιπες δυνατότητες** μετά την απόρριψη των υπολοίπων δυνατοτήτων από τη διεργασία:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Είναι ενεργοποιημένο από προεπιλογή στο Docker. Βοηθά στο **περιορισμό ακόμα περισσότερων syscalls** που μπορεί να καλέσει η διαδικασία.\
Το **προφίλ προεπιλεγμένου Seccomp του Docker** μπορεί να βρεθεί στο [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Το Docker έχει ένα πρότυπο που μπορείτε να ενεργοποιήσετε: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Αυτό θα επιτρέψει τη μείωση των δυνατοτήτων, των syscalls, την πρόσβαση σε αρχεία και φακέλους...

</details>

### Namespaces

Τα **Namespaces** είναι μια λειτουργία του πυρήνα του Linux που **διαχωρίζει τους πόρους του πυρήνα** έτσι ώστε ένα σύνολο **διεργασιών** να **βλέπει** ένα σύνολο **πόρων** ενώ **άλλο** σύνολο **διεργασιών** βλέπει ένα **διαφορετικό** σύνολο πόρων. Η λειτουργία λειτουργεί με το να έχει το ίδιο namespace για ένα σύνολο πόρων και διεργασιών, αλλά αυτά τα namespaces αναφέρονται σε διακριτούς πόρους. Οι πόροι μπορεί να υπάρχουν σε πολλούς χώρους.

Το Docker χρησιμοποιεί τα ακόλουθα Namespaces του πυρήνα του Linux για να επιτύχει την απομόνωση των Containers:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

Για **περισσότερες πληροφορίες σχετικά με τα namespaces** ελέγξτε την ακόλουθη σελίδα:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Η δυνατότητα του πυρήνα του Linux με τα **cgroups** παρέχει τη δυνατότητα να **περιορίζει πόρους όπως cpu, μνήμη, io, εύρος ζώνης δικτύου μεταξύ** ενός συνόλου διεργασιών. Το Docker επιτρέπει τη δημιουργία Containers χρησιμοποιώντας το χαρακτηριστικό cgroup που επιτρέπει τον έλεγχο πόρων για το συγκεκριμένο Container.\
Ακολουθεί ένα Container που δημιουργήθηκε με περιορισμό μνήμης χώρου χρήστη σε 500m, περιορισμό μνήμης πυρήνα σε 50m, μοιρασμό cpu σε 512, blkioweight σε 400. Ο μοιρασμός CPU είναι ένας λόγος που ελέγχει τη χρήση CPU του Container. Έχει προεπιλεγμένη τιμή 1024 και εύρος μεταξύ 0 και 1024. Αν τρία Containers έχουν τον ίδιο μοιρασμό CPU των 1024, κάθε Container μπορεί να πάρει μέχρι 33% της CPU σε περίπτωση ανταγωνισμού πόρων CPU. Το blkio-weight είναι ένας λόγος που ελέγχει το IO του Container. Έχει προεπιλεγμένη τιμή 500 και εύρος μεταξύ 10 και 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Για να πάρετε το cgroup ενός container μπορείτε να κάνετε:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Για περισσότερες πληροφορίες ελέγξτε:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Δυνατότητες

Οι δυνατότητες επιτρέπουν **πιο λεπτό έλεγχο για τις δυνατότητες που μπορούν να επιτραπούν** για το χρήστη root. Το Docker χρησιμοποιεί το χαρακτηριστικό δυνατοτήτων του πυρήνα Linux για να **περιορίσει τις λειτουργίες που μπορούν να γίνουν μέσα σε ένα Εμπορευματοκιβώτιο** ανεξαρτήτως του τύπου του χρήστη.

Όταν τρέχει ένα εμπορευματοκιβώτιο Docker, η **διαδικασία απορρίπτει ευαίσθητες δυνατότητες που θα μπορούσε να χρησιμοποιήσει η διαδικασία για να δραπετεύσει από την απομόνωση**. Αυτό προσπαθεί να διασφαλίσει ότι η διαδικασία δεν θα μπορεί να εκτελέσει ευαίσθητες ενέργειες και να δραπετεύσει:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp στο Docker

Αυτό είναι ένα χαρακτηριστικό ασφαλείας που επιτρέπει στο Docker να **περιορίσει τις κλήσεις συστήματος** που μπορούν να χρησιμοποιηθούν μέσα στο εμπορευματοκιβώτιο:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor στο Docker

**AppArmor** είναι μια βελτίωση πυρήνα για να περιορίσει τα **εμπορευματοκιβώτια** σε ένα **περιορισμένο** σύνολο **πόρων** με **προφίλ ανά πρόγραμμα**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux στο Docker

* **Σύστημα Ετικετών**: Το SELinux αναθέτει μια μοναδική ετικέτα σε κάθε διεργασία και αντικείμενο συστήματος αρχείων.
* **Επιβολή Πολιτικής**: Επιβάλλει πολιτικές ασφαλείας που ορίζουν ποιες ενέργειες μπορεί να εκτελέσει μια ετικέτα διεργασίας σε άλλες ετικέτες εντός του συστήματος.
* **Ετικέτες Διεργασίας Εμπορευματοκιβωτίων**: Όταν οι μηχανές εμπορευματοκιβωτίων εκκινούν διεργασίες εμπορευματοκιβωτίων, συνήθως τους ανατίθεται μια περιορισμένη ετικέτα SELinux, συνήθως `container_t`.
* **Ετικέτες Αρχείων εντός Εμπορευματοκιβωτίων**: Τα αρχεία μέσα στο εμπορευματοκιβώτιο συνήθως επισημαίνονται ως `container_file_t`.
* **Κανόνες Πολιτικής**: Η πολιτική SELinux κυρίως εξασφαλίζει ότι οι διεργασίες με ετικέτα `container_t` μπορούν να αλληλεπιδρούν μόνο (ανάγνωση, εγγραφή, εκτέλεση) με αρχεία που έχουν επισημανθεί ως `container_file_t`.

Αυτός ο μηχανισμός εξασφαλίζει ότι ακόμη και αν μια διαδικασία μέσα σε ένα εμπορευματοκιβώτιο είναι υπό κατάληψη, περιορίζεται στην αλληλεπίδραση μόνο με αντικείμενα που έχουν τις αντίστοιχες ετικέτες, περιορίζοντας σημαντικά την πιθανή ζημιά από τέτοιες καταστροφές.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Στο Docker, ένα πρόσθετο εξουσιοδότησης παίζει έναν κρίσιμο ρόλο στην ασφάλεια αποφασίζοντας εάν θα επιτρέψει ή θα αποκλείσει αιτήσεις προς τον δαίμονα του Docker. Αυτή η απόφαση λαμβάνεται εξετάζοντας δύο βασικά πλαίσια:

* **Πλαίσιο Ταυτοποίησης**: Αυτό περιλαμβάνει πλήρεις πληροφορίες σχετικά με τον χρήστη, όπως ποιος είναι και πώς έχει ταυτοποιηθεί.
* **Πλαίσιο Εντολής**: Αυτό περιλαμβάνει όλα τα σχετικά δεδομένα που σχετίζονται με το αίτημα που γίνεται.

Αυτά τα πλαίσια βοηθούν στη διασφάλιση ότι επεξεργάζονται μόνο νόμιμα αιτήματα από τους ταυτοποιημένους χρήστες, ενισχύοντας την ασφάλεια των λειτουργιών του Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS από ένα εμπορευματοκιβώτιο

Αν δεν περιορίζετε σωστά τους πόρους που μπορεί να χρησιμοποιήσει ένα εμπορευματοκιβώτιο, ένα εμπορευματοκιβώτιο που έχει υποστεί παραβίαση μπορεί να προκαλέσει DoS στον υπολογιστή όπου τρέχει.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandwidth DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Ενδιαφέροντα Σημαιάκια του Docker

### Σημαία --privileged

Στην παρακάτω σελίδα μπορείτε να μάθετε **τι σημαίνει η σημαία `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Εάν εκτελείτε ένα container όπου ένας επιτιθέμενος καταφέρνει να αποκτήσει πρόσβαση ως χρήστης με χαμηλά προνόμια. Εάν έχετε ένα **κακώς διαμορφωμένο suid binary**, ο επιτιθέμενος μπορεί να το εκμεταλλευτεί και **να αναβαθμίσει τα προνόμιά του μέσα** στο container. Αυτό, μπορεί να του επιτρέψει να δραπετεύσει από αυτό.

Η εκτέλεση του container με την επιλογή **`no-new-privileges`** ενεργοποιημένη θα **εμποδίσει αυτήν τη μορφή αναβάθμισης προνομίων**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Άλλα
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Για περισσότερες επιλογές **`--security-opt`** ελέγξτε: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Άλλες Αναλύσεις Ασφαλείας

### Διαχείριση Μυστικών: Καλύτερες Πρακτικές

Είναι κρίσιμο να αποφεύγετε την ενσωμάτωση μυστικών απευθείας στις εικόνες Docker ή τη χρήση μεταβλητών περιβάλλοντος, καθώς αυτές οι μέθοδοι εκθέτουν τις ευαίσθητες πληροφορίες σας σε οποιονδήποτε έχει πρόσβαση στο container μέσω εντολών όπως `docker inspect` ή `exec`.

Τα **Docker volumes** αποτελούν μια ασφαλέστερη εναλλακτική λύση, συνιστώμενη για την πρόσβαση σε ευαίσθητες πληροφορίες. Μπορούν να χρησιμοποιηθούν ως προσωρινό σύστημα αρχείων στη μνήμη, μειώνοντας τους κινδύνους που σχετίζονται με το `docker inspect` και την καταγραφή. Ωστόσο, οι χρήστες ριζικού επιπέδου και εκείνοι με πρόσβαση `exec` στο container ενδέχεται να έχουν πρόσβαση στα μυστικά.

Τα **Docker secrets** προσφέρουν μια ακόμα πιο ασφαλή μέθοδο για τη χειρισμό ευαίσθητων πληροφοριών. Για περιπτώσεις που απαιτούν μυστικά κατά τη φάση κατασκευής της εικόνας, το **BuildKit** παρουσιάζει μια αποτελεσματική λύση με υποστήριξη για μυστικά κατά την κατασκευή, βελτιώνοντας την ταχύτητα κατασκευής και παρέχοντας επιπλέον χαρακτηριστικά.

Για να εκμεταλλευτείτε το BuildKit, μπορεί να ενεργοποιηθεί με τρεις τρόπους:

1. Μέσω μεταβλητής περιβάλλοντος: `export DOCKER_BUILDKIT=1`
2. Με προθέματα εντολών: `DOCKER_BUILDKIT=1 docker build .`
3. Ενεργοποιώντας το από προεπιλογή στη διαμόρφωση του Docker: `{ "features": { "buildkit": true } }`, ακολουθούμενο από επανεκκίνηση του Docker.

Το BuildKit επιτρέπει τη χρήση μυστικών κατά την κατασκευή με την επιλογή `--secret`, εξασφαλίζοντας ότι αυτά τα μυστικά δεν περιλαμβάνονται στην προσωρινή μνήμη κατασκευής της εικόνας ή στην τελική εικόνα, χρησιμοποιώντας μια εντολή όπως:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Για τα μυστικά που χρειάζονται σε ένα τρέχον container, το **Docker Compose και το Kubernetes** προσφέρουν αξιόπιστες λύσεις. Το Docker Compose χρησιμοποιεί ένα κλειδί `secrets` στον ορισμό της υπηρεσίας για την καθορισμό μυστικών αρχείων, όπως φαίνεται σε ένα παράδειγμα `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Αυτή η διαμόρφωση επιτρέπει τη χρήση μυστικών κατά την εκκίνηση υπηρεσιών με το Docker Compose.

Σε περιβάλλοντα Kubernetes, τα μυστικά υποστηρίζονται φυσικά και μπορούν να διαχειριστούν περαιτέρω με εργαλεία όπως το [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Τα Role Based Access Controls (RBAC) του Kubernetes βελτιώνουν την ασφάλεια διαχείρισης μυστικών, παρόμοια με το Docker Enterprise.

### gVisor

Το **gVisor** είναι ένα πυρήνας εφαρμογής, γραμμένος σε Go, που υλοποιεί ένα σημαντικό μέρος της επιφάνειας συστήματος Linux. Περιλαμβάνει ένα [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime με το όνομα `runsc` που παρέχει μια **οριοθετημένη περιοχή μεταξύ της εφαρμογής και του πυρήνα του υπολογιστή**. Το runtime `runsc` ενσωματώνεται με το Docker και το Kubernetes, κάνοντας εύκολη την εκτέλεση απομονωμένων containers.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

Τα **Kata Containers** είναι μια κοινότητα ανοιχτού κώδικα που εργάζεται για τη δημιουργία ενός ασφαλούς runtime container με ελαφριές εικονικές μηχανές που αισθάνονται και λειτουργούν όπως τα containers, αλλά παρέχουν **ισχυρότερη απομόνωση φορτίου εργασίας χρησιμοποιώντας τεχνολογία εικονικοποίησης υλικού** ως δεύτερο επίπεδο άμυνας.

{% embed url="https://katacontainers.io/" %}

### Συμβουλές Περίληψης

* **Μην χρησιμοποιείτε τη σημαία `--privileged` ή προσαρτήστε ένα** [**Docker socket μέσα στο container**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Το docker socket επιτρέπει τη δημιουργία containers, είναι ένα εύκολο τρόπος να αναλάβετε πλήρη έλεγχο του υπολογιστή φιλοξενίας, για παράδειγμα, με την εκτέλεση ενός άλλου container με τη σημαία `--privileged`.
* Μην εκτελείτε ως root μέσα στο container. Χρησιμοποιήστε έναν [διαφορετικό χρήστη](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) και [user namespaces](https://docs.docker.com/engine/security/userns-remap/). Το root στο container είναι το ίδιο με αυτόν στον υπολογιστή φιλοξενίας εκτός εάν γίνει αντιστοίχιση με user namespaces. Περιορίζεται ελαφρά κυρίως από Linux namespaces, δυνατότητες και cgroups.
* [Απορρίψτε όλες τις δυνατότητες](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) και ενεργοποιήστε μόνο αυτές που απαιτούνται** (`--cap-add=...`). Πολλά φορτία εργασίας δεν χρειάζονται καμία δυνατότητα και η προσθήκη τους αυξάνει το πεδίο μιας πιθανής επίθεσης.
* [Χρησιμοποιήστε την επιλογή ασφαλείας “no-new-privileges”](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) για να εμποδίσετε τις διεργασίες από το να αποκτήσουν περισσότερα προνόμια, για παράδειγμα μέσω suid δυαδικών.
* [Περιορίστε τους διαθέσιμους πόρους στο container](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Οι περιορισμοί πόρων μπορούν να προστατεύσουν τον υπολογιστή από επιθέσεις αρνησης υπηρεσίας.
* **Προσαρμόστε τα προφίλ** [**seccomp**](https://docs.docker.com/engine/security/seccomp/), [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ή SELinux)** για να περιορίσετε τις ενέργειες και τις κλήσεις συστήματος που είναι διαθέσιμες για το container στο ελάχιστο απαιτούμενο.
* **Χρησιμοποιήστε** [**επίσημες εικόνες docker**](https://docs.docker.com/docker-hub/official_images/) **και απαιτήστε υπογραφές** ή δημιουργήστε τις δικές σας βασισμένες σε αυτές. Μην κληρονομείτε ή χρησιμοποιείτε [προσβεβλημένες](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) εικόνες. Αποθηκεύστε επίσης τα ριζικά κλειδιά, τον κωδικό πρόσβασης σε ασφαλές μέρος. Το Docker έχει σχέδια για τη διαχείριση των κλειδιών με το UCP.
* **Αναδημιουργήστε τακτικά** τις εικόνες σας για να **εφαρμόσετε πάτσες ασφαλείας στον υπολογιστή και τις εικόνες.**
* Διαχειριστείτε τα **μυστικά σας με σύνεση** ώστε να είναι δύσκολο για τον επιτιθέμενο να τα αποκτήσει.
* Εάν **εκθέτετε τον δαίμονα του docker χρησιμοποιήστε HTTPS** με πιστοποίηση πελάτη και εξυπηρετητή.
* Στο Dockerfile σας, **προτιμήστε την ΑΝΤΙΓΡΑΦΗ αντί του ΠΡΟΣΘΗΚΗ**. Η ΠΡΟΣΘΗΚΗ εξάγει αυτόματα συμπιεσμένα αρχεία και μπορεί να αντιγράψει αρχεία από διευθύνσεις URL. Η ΑΝΤΙΓΡΑΦΗ δεν έχει αυτές τις δυνατότητες. Όποτε είναι δυνατόν, αποφύγετε τη χρήση της ΠΡΟΣΘΗΚΗ για να μην είστε ευάλωτοι σε επιθέσεις μέσω απομακρυσμένων διευθύνσεων URL και αρχείων Zip.
* Έχετε **ξεχωριστά containers για κάθε μικρο-υπηρεσία**
* **Μην τοποθετείτε ssh** μέσα στο container, το “docker exec” μπορεί να χρησιμοποιηθεί για να συνδεθείτε με ssh στο Container.
* Έχετε **μικρότερες** εικόνες **containers**
Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.
