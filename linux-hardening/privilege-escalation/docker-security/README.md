# Ασφάλεια του Docker

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Βασική Ασφάλεια του Docker Engine**

Το **Docker engine** χρησιμοποιεί τα **Namespaces** και **Cgroups** του πυρήνα του Linux για να απομονώσει τα containers, προσφέροντας ένα βασικό επίπεδο ασφάλειας. Πρόσθετη προστασία παρέχεται μέσω της **απόρριψης δυνατοτήτων (Capabilities dropping)**, του **Seccomp** και του **SELinux/AppArmor**, ενισχύοντας την απομόνωση των containers. Ένα πρόσθετο **auth plugin** μπορεί να περιορίσει περαιτέρω τις ενέργειες του χρήστη.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Ασφαλής Πρόσβαση στο Docker Engine

Το Docker engine μπορεί να προσπελαστεί είτε τοπικά μέσω ενός Unix socket είτε απομακρυσμένα χρησιμοποιώντας HTTP. Για απομακρυσμένη πρόσβαση, είναι απαραίτητο να χρησιμοποιηθεί το HTTPS και το **TLS** για να εξασφαλιστεί η εμπιστευτικότητα, η ακεραιότητα και η αυθεντικοποίηση.

Το Docker engine, από προεπιλογή, ακούει στο Unix socket στη διεύθυνση `unix:///var/run/docker.sock`. Στα συστήματα Ubuntu, οι επιλογές εκκίνησης του Docker καθορίζονται στο αρχείο `/etc/default/docker`. Για να επιτραπεί η απομακρυσμένη πρόσβαση στο API και τον πελάτη του Docker, εκθέστε τον δαίμονα του Docker μέσω ενός HTTP socket προσθέτοντας τις παρακάτω ρυθμίσεις:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Ωστόσο, δεν συνιστάται να αποκαλύπτετε τον Docker daemon μέσω HTTP λόγω ανησυχιών ασφαλείας. Είναι συνιστώμενο να ασφαλίζετε τις συνδέσεις χρησιμοποιώντας HTTPS. Υπάρχουν δύο κύριες προσεγγίσεις για την ασφάλεια της σύνδεσης:
1. Ο πελάτης επαληθεύει την ταυτότητα του διακομιστή.
2. Τόσο ο πελάτης όσο και ο διακομιστής αυθεντικοποιούν αμοιβαία την ταυτότητα τους.

Χρησιμοποιούνται πιστοποιητικά για την επιβεβαίωση της ταυτότητας ενός διακομιστή. Για λεπτομερείς παραδείγματα και των δύο μεθόδων, ανατρέξτε σε [**αυτόν τον οδηγό**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Ασφάλεια των εικόνων των εμπορευμάτων

Οι εικόνες των εμπορευμάτων μπορούν να αποθηκευτούν είτε σε ιδιωτικούς είτε σε δημόσιους αποθετήριους. Ο Docker προσφέρει αρκετές επιλογές αποθήκευσης για τις εικόνες των εμπορευμάτων:

* **[Docker Hub](https://hub.docker.com)**: Ένα δημόσιο υπηρεσία αποθετηρίου από το Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: Ένα ανοιχτού κώδικα έργο που επιτρέπει στους χρήστες να φιλοξενούν το δικό τους αποθετήριο.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Η εμπορική προσφορά αποθετηρίου του Docker, που περιλαμβάνει αυθεντικοποίηση χρηστών με βάση τον ρόλο και ενσωμάτωση με υπηρεσίες καταλόγου LDAP.

### Σάρωση εικόνων

Οι εικόνες των εμπορευμάτων μπορεί να έχουν **ευπάθειες ασφαλείας** είτε λόγω της βασικής εικόνας είτε λόγω του λογισμικού που είναι εγκατεστημένο πάνω στη βασική εικόνα. Ο Docker εργάζεται πάνω σε ένα έργο που ονομάζεται **Nautilus**, το οποίο πραγματοποιεί ανάλυση ασφαλείας των εικόνων των εμπορευμάτων και καταγράφει τις ευπάθειες. Το Nautilus λειτουργεί συγκρίνοντας κάθε επίπεδο εικόνας του εμπορεύματος με το αποθετήριο ευπαθειών για την εντοπισμό των ασφαλειακών κενών.

Για περισσότερες [**πληροφορίες διαβάστε αυτό**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Η εντολή **`docker scan`** σας επιτρέπει να σαρώσετε υπάρχουσες εικόνες Docker χρησιμοποιώντας το όνομα ή το ID της εικόνας. Για παράδειγμα, εκτελέστε την παρακάτω εντολή για να σαρώσετε την εικόνα hello-world:
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
### Υπογραφή Docker Image

Η υπογραφή των Docker εικόνων εξασφαλίζει την ασφάλεια και ακεραιότητα των εικόνων που χρησιμοποιούνται σε containers. Εδώ έχουμε μια συνοπτική εξήγηση:

- Το **Docker Content Trust** χρησιμοποιεί το έργο Notary, βασισμένο στο The Update Framework (TUF), για τη διαχείριση της υπογραφής των εικόνων. Για περισσότερες πληροφορίες, δείτε [Notary](https://github.com/docker/notary) και [TUF](https://theupdateframework.github.io).
- Για να ενεργοποιήσετε το Docker content trust, ορίστε `export DOCKER_CONTENT_TRUST=1`. Αυτή η λειτουργία είναι απενεργοποιημένη από προεπιλογή στην έκδοση 1.10 και μεταγενέστερες του Docker.
- Με αυτήν τη λειτουργία ενεργοποιημένη, μόνο υπογεγραμμένες εικόνες μπορούν να ληφθούν. Η αρχική αποστολή της εικόνας απαιτεί την ορισμό κωδικών πρόσβασης για τα κλειδιά ρίζας και ετικετών, με το Docker να υποστηρίζει επίσης το Yubikey για ενισχυμένη ασφάλεια. Περισσότερες λεπτομέρειες μπορούν να βρεθούν [εδώ](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Η προσπάθεια να ληφθεί μια μη υπογεγραμμένη εικόνα με ενεργοποιημένο το content trust οδηγεί σε σφάλμα "No trust data for latest".
- Για την αποστολή εικόνων μετά την πρώτη, το Docker ζητά τον κωδικό πρόσβασης του κλειδιού αποθετηρίου για να υπογράψει την εικόνα.

Για να δημιουργήσετε αντίγραφο ασφαλείας των ιδιωτικών κλειδιών σας, χρησιμοποιήστε την εντολή:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Όταν αλλάζετε τους hosts του Docker, είναι απαραίτητο να μεταφέρετε τα κλειδιά του root και του αποθετηρίου για να διατηρήσετε τις λειτουργίες.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να αυτοματοποιήσετε τις ροές εργασίας με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Χαρακτηριστικά Ασφάλειας Εμπορευματοκιβωτίων

<details>

<summary>Περίληψη των Χαρακτηριστικών Ασφάλειας Εμπορευματοκιβωτίων</summary>

### Κύρια Χαρακτηριστικά Απομόνωσης Κύριας Διεργασίας

Σε περιβάλλοντα εμπορευματοκιβωτίων, η απομόνωση των έργων και των διεργασιών τους είναι ζωτικής σημασίας για την ασφάλεια και τη διαχείριση των πόρων. Εδώ παρέχεται μια απλοποιημένη εξήγηση των βασικών έννοιων:

#### **Ονοματοχώροι (Namespaces)**
- **Σκοπός**: Εξασφαλίζουν την απομόνωση των πόρων, όπως οι διεργασίες, οι δίκτυα και τα συστήματα αρχείων. Ειδικά στο Docker, οι ονοματοχώροι διατηρούν τις διεργασίες ενός εμπορευματοκιβωτίου χωριστές από τον host και άλλα εμπορευματοκιβώτια.
- **Χρήση της εντολής `unshare`**: Η εντολή `unshare` (ή η υποκείμενη κλήση συστήματος) χρησιμοποιείται για τη δημιουργία νέων ονοματοχώρων, παρέχοντας ένα επιπλέον επίπεδο απομόνωσης. Ωστόσο, ενώ το Kubernetes δεν αποκλείει αυτό από μόνο του, το Docker το αποκλείει.
- **Περιορισμός**: Η δημιουργία νέων ονοματοχώρων δεν επιτρέπει σε μια διεργασία να επανέλθει στους προεπιλεγμένους ονοματοχώρους του host. Για να διεισδύσει στους ονοματοχώρους του host, συνήθως απαιτείται πρόσβαση στον κατάλογο `/proc` του host, χρησιμοποιώντας την εντολή `nsenter` για είσοδο.

#### **Ομάδες Ελέγχου (CGroups)**
- **Λειτουργία**: Χρησιμοποιούνται κυρίως για την κατανομή πόρων μεταξύ των διεργασιών.
- **Ασφάλεια**: Οι ομάδες ελέγχου από μόνες τους δεν προσφέρουν ασφάλεια απομόνωσης, εκτός από το χαρακτηριστικό `release_agent`, το οποίο, αν διαμορφωθεί εσφαλμένα, μπορεί να εκμεταλλευτεί για μη εξουσιοδοτημένη πρόσβαση.

#### **Πτώση Δυνατοτήτων (Capability Drop)**
- **Σημασία**: Είναι ένα κρίσιμο χαρακτηριστικό ασφάλειας για την απομόνωση των διεργασιών.
- **Λειτουργικότητα**: Περιορίζει τις ενέργειες που μπορεί να εκτελέσει μια διεργασία root απορρίπτοντας ορισμένες δυνατότητες. Ακόμα κι αν μια διεργασία λειτουργεί με δικαιώματα root, η έλλειψη των απαραίτητων δυνατοτήτων την εμποδίζει να εκτελέσει προνομιούχες ενέργειες, καθώς οι κλήσεις συστήματος θα αποτύχουν λόγω έλλειψης αρμοδιοτήτων.

Αυτές είναι οι **υπόλοιπες δυνατότητες** μετά την απόρριψη των υπολοίπων δυνατοτήτων από τη διεργασία:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Είναι ενεργοποιημένο από προεπιλογή στο Docker. Βοηθά να **περιορίσει ακόμα περισσότερο τις κλήσεις συστήματος** που μπορεί να κάνει η διεργασία.\
Το **προφίλ Seccomp του Docker προεπιλογής** μπορεί να βρεθεί στο [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Το Docker έχει ένα πρότυπο που μπορείτε να ενεργοποιήσετε: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Αυτό θα επιτρέψει τη μείωση των δυνατοτήτων, των κλήσεων συστήματος, της πρόσβασης σε αρχεία και φακέλους...

</details>

### Namespaces

Τα **Namespaces** είναι μια δυνατότητα του πυρήνα του Linux που **διαχωρίζει τους πόρους του πυρήνα** έτσι ώστε ένα σύνολο **διεργασιών** να βλέπει ένα σύνολο **πόρων**, ενώ ένα άλλο σύνολο **διεργασιών** βλέπει ένα **διαφορετικό** σύνολο πόρων. Η δυνατότητα λειτουργεί έχοντας το ίδιο namespace για ένα σύνολο πόρων και διεργασιών, αλλά αυτά τα namespaces αναφέρονται σε διακριτούς πόρους. Οι πόροι μπορεί να υπάρχουν σε πολλούς χώρους.

Το Docker χρησιμοποιεί τα ακόλουθα Namespaces του πυρήνα του Linux για να επιτύχει την απομόνωση των Containers:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

Για **περισσότερες πληροφορίες σχετικά με τα namespaces** ανατρέξτε στην ακόλουθη σελίδα:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Η δυνατότητα **cgroups** του πυρήνα του Linux παρέχει τη δυνατότητα να **περιορίσει πόρους όπως η CPU, η μνήμη, η είσοδος/έξοδος, η εύρος ζώνης του δικτύου μεταξύ** ενός συνόλου διεργασιών. Το Docker επιτρέπει τη δημιουργία Containers χρησιμοποιώντας τη δυνατότητα cgroup που επιτρέπει τον έλεγχο των πόρων για το συγκεκριμένο Container.\
Παρακάτω παρουσιάζεται ένα Container που δημιουργήθηκε με περιορισμένη μνήμη χώρου χρήστη στα 500m, περιορισμένη μνήμη πυρήνα στα 50m, κοινή χρήση CPU στα 512, βάρος blkio στα 400. Η κοινή χρήση CPU είναι ένας λόγος που ελέγχει τη χρήση της CPU από το Container. Έχει μια προεπιλεγμένη τιμή 1024 και κυμαίνεται από 0 έως 1024. Αν τρία Containers έχουν την ίδια κοινή χρήση CPU 1024, κάθε Container μπορεί να χρησιμοποιήσει έως και 33% της CPU σε περίπτωση ανταγωνισμού για πόρους CPU. Το blkio-weight είναι ένας λόγος που ελέγχει την IO του Container. Έχει μια προεπιλεγμένη τιμή 500 και κυμαίνεται από 10 έως 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Για να πάρετε το cgroup ενός container μπορείτε να κάνετε:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Για περισσότερες πληροφορίες, ελέγξτε:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Δυνατότητες

Οι δυνατότητες επιτρέπουν **πιο λεπτό έλεγχο για τις δυνατότητες που μπορούν να επιτραπούν** για τον χρήστη root. Το Docker χρησιμοποιεί τη δυνατότητα του πυρήνα του Linux για να **περιορίσει τις λειτουργίες που μπορούν να γίνουν μέσα σε ένα Container** ανεξάρτητα από τον τύπο του χρήστη.

Όταν εκτελείται ένας docker container, η διαδικασία απορρίπτει ευαίσθητες δυνατότητες που η διαδικασία θα μπορούσε να χρησιμοποιήσει για να δραπετεύσει από την απομόνωση. Αυτό προσπαθεί να διασφαλίσει ότι η διαδικασία δεν θα μπορεί να εκτελέσει ευαίσθητες ενέργειες και να δραπετεύσει:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp στο Docker

Αυτή είναι μια λειτουργία ασφαλείας που επιτρέπει στο Docker να **περιορίσει τις κλήσεις συστήματος** που μπορούν να χρησιμοποιηθούν μέσα στο container:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor στο Docker

Το **AppArmor** είναι μια βελτίωση του πυρήνα για να περιορίσει τα **containers** σε ένα **περιορισμένο** σύνολο **πόρων** με **προφίλ ανά πρόγραμμα**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux στο Docker

- **Σύστημα επισήμανσης**: Το SELinux αναθέτει ένα μοναδικό ετικέτα σε κάθε διεργασία και αντικείμενο του συστήματος αρχείων.
- **Επιβολή πολιτικής**: Επιβάλλει πολιτικές ασφαλείας που καθορίζουν ποιες ενέργειες μπορεί να εκτελέσει μια ετικέτα διεργασίας σε άλλες ετικέτες εντός του συστήματος.
- **Ετικέτες διεργασίας εντός των Containers**: Όταν οι μηχανές των containers εκκινούν διεργασίες των containers, συνήθως τους ανατίθεται μια περιορισμένη ετικέτα SELinux, συνήθως `container_t`.
- **Επισήμανση αρχείων εντός των Containers**: Τα αρχεία εντός του container συνήθως επισημαίνονται ως `container_file_t`.
- **Κανόνες πολιτικής**: Η πολιτική SELinux καθορίζει κυρίως ότι οι διεργασίες με ετικέτα `container_t` μπορούν να αλληλεπιδρούν (ανάγνωση, εγγραφή, εκτέλεση) με αρχεία που έχουν ετικέτα `container_file_t`.

Αυτός ο μηχανισμός εξασφαλίζει ότι ακόμη και αν μια διεργασία εντός ενός container παραβιαστεί, περιορίζεται να αλληλεπιδρά μόνο με αντικείμενα που έχουν τις αντίστοιχες ετικέτες, περιορίζοντας σημαντικά την πιθανή ζημιά από τέτοιες παραβιάσεις.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Στο Docker, ένα πρόσθετο εξουσιοδότησης παίζει κρίσιμο ρόλο στην ασφάλεια αποφασίζοντας εάν θα επιτρέψει ή θα αποκλείσει αιτήματα προς τον δαίμονα του Docker. Αυτή η απόφαση λαμβάνεται εξετάζοντας δύο βασικά πλαίσια:

- **Πλαίσιο Πιστοποίησης**: Αυτό περιλαμβάνει πλήρεις πληροφορίες για τον χρήστη, όπως ποιος είναι και πώς έχει πιστοποιηθεί.
- **Πλαίσιο Εντολής**: Αυτό περιλαμβάνει όλα τα σχετικά δεδομένα που αφορούν το αίτημα που γίνεται.

Αυτά τα πλαίσια βοηθούν να διασφαλιστεί ότι επεξεργάζονται μόνο νόμιμα αιτήματα από πιστοποιημένους χρήστες, ενισχύοντας την ασφάλεια των λειτουργιών του Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS από ένα container

Εάν δεν περιορίζετε σωστά τους πόρους που μπορεί να χρησιμοποιήσει ένα container, ένας παραβιασμένος container μπορεί να προκαλέσει DoS στον υπολογιστή όπου εκτελείται.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Διακοπή λειτουργίας εύρους ζώνης

Η διακοπή λειτουργίας εύρους ζώνης (Bandwidth DoS) είναι μια τεχνική επίθεσης που στοχεύει στην απόρριψη της υπηρεσίας μιας συσκευής ή ενός δικτύου περιορίζοντας το εύρος ζώνης που είναι διαθέσιμο για την ανταλλαγή δεδομένων. Αυτό επιτυγχάνεται με την κατανάλωση όλου ή μεγάλου μέρους του διαθέσιμου εύρους ζώνης με κακόβουλη κίνηση δεδομένων, καθιστώντας την υπηρεσία μη λειτουργική για τους νόμιμους χρήστες. Αυτή η επίθεση μπορεί να προκαλέσει σοβαρές δυσκολίες στη λειτουργία του δικτύου και να προκαλέσει απώλεια υπηρεσιών.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Ενδιαφέροντα Σημαία Docker

### Σημαία --privileged

Στην παρακάτω σελίδα μπορείτε να μάθετε **τι σημαίνει η σημαία `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Εάν εκτελείτε ένα container όπου ένας επιτιθέμενος καταφέρνει να αποκτήσει πρόσβαση ως χρήστης με χαμηλά προνόμια. Εάν έχετε ένα **κακώς διαμορφωμένο suid binary**, ο επιτιθέμενος μπορεί να το καταχραστεί και να **αναβαθμίσει τα προνόμια μέσα** στο container. Αυτό, μπορεί να του επιτρέψει να δραπετεύσει από αυτό.

Η εκτέλεση του container με την επιλογή **`no-new-privileges`** ενεργοποιημένη θα **αποτρέψει αυτήν την ανέλιξη προνομίων**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Άλλα

---

##### Docker Security

---

##### Ασφάλεια Docker

---

Docker is a popular containerization platform that allows you to package applications and their dependencies into lightweight, portable containers. However, like any other software, Docker can have security vulnerabilities that can be exploited by attackers. In this section, we will explore some best practices for securing Docker containers and preventing privilege escalation attacks.

Το Docker είναι μια δημοφιλής πλατφόρμα εμπλουτισμού που σας επιτρέπει να συσκευάζετε εφαρμογές και τις εξαρτήσεις τους σε ελαφριές, φορητές ενότητες. Ωστόσο, όπως και οποιοδήποτε άλλο λογισμικό, το Docker μπορεί να έχει ευπάθειες ασφαλείας που μπορούν να εκμεταλλευτούν οι επιτιθέμενοι. Σε αυτήν την ενότητα, θα εξετάσουμε μερικές βέλτιστες πρακτικές για την ασφάλεια των ενοτήτων Docker και την πρόληψη επιθέσεων απόκτησης προνομίων.

---

##### Docker Security Best Practices

---

##### Βέλτιστες πρακτικές ασφάλειας Docker

---

Here are some best practices to enhance the security of your Docker containers:

Παρακάτω παρουσιάζονται μερικές βέλτιστες πρακτικές για την ενίσχυση της ασφάλειας των ενοτήτων Docker σας:

1. Use Official Images: Official Docker images are regularly updated and maintained by the Docker community. They are more secure and less likely to contain vulnerabilities compared to unofficial or outdated images.

1. Χρησιμοποιήστε Επίσημες Εικόνες: Οι επίσημες εικόνες Docker ενημερώνονται και διατηρούνται τακτικά από την κοινότητα του Docker. Είναι πιο ασφαλείς και λιγότερο πιθανό να περιέχουν ευπάθειες σε σύγκριση με μη επίσημες ή παλαιές εικόνες.

2. Enable Content Trust: Docker Content Trust ensures the integrity and authenticity of images by verifying their digital signatures. Enable this feature to prevent the use of tampered or malicious images.

2. Ενεργοποιήστε την Εμπιστοσύνη Περιεχομένου: Η Εμπιστοσύνη Περιεχομένου του Docker εξασφαλίζει την ακεραιότητα και την αυθεντικότητα των εικόνων επαληθεύοντας τις ψηφιακές τους υπογραφές. Ενεργοποιήστε αυτήν τη λειτουργία για να αποτρέψετε τη χρήση παραποιημένων ή κακόβουλων εικόνων.

3. Limit Container Capabilities: By default, Docker containers have access to a wide range of system capabilities. Limit the capabilities of your containers to only what is necessary for their intended functionality.

3. Περιορίστε τις Δυνατότητες των Ενοτήτων: Από προεπιλογή, οι ενότητες Docker έχουν πρόσβαση σε μια ευρεία γκάμα δυνατοτήτων του συστήματος. Περιορίστε τις δυνατότητες των ενοτήτων σας μόνο σε αυτές που είναι απαραίτητες για την επιθυμητή λειτουργικότητά τους.

4. Use User Namespaces: User namespaces provide an additional layer of isolation by mapping container user IDs to host user IDs. This prevents privilege escalation attacks by restricting the container's access to host resources.

4. Χρησιμοποιήστε Χώρους Ονομάτων Χρηστών: Οι χώροι ονομάτων χρηστών παρέχουν ένα επιπλέον επίπεδο απομόνωσης με την αντιστοίχιση των αναγνωριστικών χρηστών των ενοτήτων στα αναγνωριστικά χρηστών του κεντρικού συστήματος. Αυτό αποτρέπει τις επιθέσεις απόκτησης προνομίων περιορίζοντας την πρόσβαση της ενότητας στους πόρους του κεντρικού συστήματος.

5. Monitor Container Activity: Implement container monitoring tools to detect any suspicious or malicious activity within your Docker environment. This can help you identify and respond to potential security breaches.

5. Παρακολουθήστε τη Δραστηριότητα των Ενοτήτων: Εφαρμόστε εργαλεία παρακολούθησης ενοτήτων για να ανιχνεύσετε οποιαδήποτε ύποπτη ή κακόβουλη δραστηριότητα εντός του περιβάλλοντος Docker σας. Αυτό μπορεί να σας βοηθήσει να αναγνωρίσετε και να αντιδράσετε σε πιθανές παραβιάσεις ασφαλείας.

---

By following these best practices, you can significantly improve the security of your Docker containers and reduce the risk of privilege escalation attacks.

Ακολουθώντας αυτές τις βέλτιστες πρακτικές, μπορείτε να βελτιώσετε σημαντικά την ασφάλεια των ενοτήτων Docker σας και να μειώσετε τον κίνδυνο επιθέσεων απόκτησης προνομίων.
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

## Άλλες Ασφαλείς Σκέψεις

### Διαχείριση Μυστικών: Καλές Πρακτικές

Είναι κρίσιμο να αποφεύγετε την ενσωμάτωση μυστικών απευθείας στις εικόνες Docker ή τη χρήση μεταβλητών περιβάλλοντος, καθώς αυτές οι μέθοδοι εκθέτουν τις ευαίσθητες πληροφορίες σας σε οποιονδήποτε έχει πρόσβαση στον εμπορευματοκιβώτιο μέσω εντολών όπως `docker inspect` ή `exec`.

Τα **Docker volumes** είναι μια ασφαλέστερη εναλλακτική λύση, προτεινόμενη για την πρόσβαση σε ευαίσθητες πληροφορίες. Μπορούν να χρησιμοποιηθούν ως ένα προσωρινό σύστημα αρχείων στη μνήμη, μειώνοντας τους κινδύνους που συνδέονται με το `docker inspect` και την καταγραφή. Ωστόσο, οι χρήστες με δικαιώματα root και εκείνοι με πρόσβαση `exec` στον εμπορευματοκιβώτιο εξακολουθούν να έχουν πρόσβαση στα μυστικά.

Τα **Docker secrets** προσφέρουν μια ακόμα πιο ασφαλή μέθοδο για την χειρισμό ευαίσθητων πληροφοριών. Για περιπτώσεις που απαιτούν μυστικά κατά τη φάση κατασκευής της εικόνας, το **BuildKit** παρουσιάζει μια αποτελεσματική λύση με υποστήριξη για μυστικά κατά την ώρα κατασκευής, βελτιώνοντας την ταχύτητα κατασκευής και παρέχοντας επιπλέον χαρακτηριστικά.

Για να αξιοποιήσετε το BuildKit, μπορεί να ενεργοποιηθεί με τρεις τρόπους:

1. Μέσω μιας μεταβλητής περιβάλλοντος: `export DOCKER_BUILDKIT=1`
2. Προσθέτοντας πρόθεμα στις εντολές: `DOCKER_BUILDKIT=1 docker build .`
3. Ενεργοποιώντας το από προεπιλογή στη διαμόρφωση του Docker: `{ "features": { "buildkit": true } }`, ακολουθούμενο από επανεκκίνηση του Docker.

Το BuildKit επιτρέπει τη χρήση μυστικών κατά την ώρα κατασκευής με την επιλογή `--secret`, εξασφαλίζοντας ότι αυτά τα μυστικά δεν περιλαμβάνονται στην προσωρινή μνήμη κατασκευής της εικόνας ή στην τελική εικόνα, χρησιμοποιώντας μια εντολή όπως:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Για τα μυστικά που χρειάζονται σε ένα εκτελούμενο container, το **Docker Compose και το Kubernetes** προσφέρουν αξιόπιστες λύσεις. Το Docker Compose χρησιμοποιεί το κλειδί `secrets` στον ορισμό της υπηρεσίας για τον καθορισμό αρχείων μυστικών, όπως φαίνεται σε ένα παράδειγμα `docker-compose.yml`:
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

Σε περιβάλλοντα Kubernetes, τα μυστικά υποστηρίζονται φυσικά και μπορούν να διαχειριστούν περαιτέρω με εργαλεία όπως το [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Οι Ρόλοι Βασισμένοι στην Πρόσβαση (RBAC) του Kubernetes ενισχύουν την ασφάλεια διαχείρισης μυστικών, παρόμοια με το Docker Enterprise.

### gVisor

Το **gVisor** είναι ένα πυρήνας εφαρμογής, γραμμένος σε Go, που υλοποιεί ένα μεγάλο μέρος της επιφάνειας του συστήματος Linux. Περιλαμβάνει ένα [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime με το όνομα `runsc` που παρέχει μια **οριοθετημένη απομόνωση μεταξύ της εφαρμογής και του πυρήνα του οικοδεσπότη**. Το runtime `runsc` ενσωματώνεται με το Docker και το Kubernetes, καθιστώντας απλή την εκτέλεση εφαρμογών σε αμμοδοχεία.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

Το **Kata Containers** είναι μια κοινότητα ανοιχτού κώδικα που εργάζεται για τη δημιουργία ενός ασφαλούς runtime για εμπορεύματα με ελαφριές εικονικές μηχανές που αισθάνονται και λειτουργούν όπως τα εμπορεύματα, αλλά παρέχουν **ισχυρότερη απομόνωση του φορτίου εργασίας χρησιμοποιώντας τεχνολογία εικονικοποίησης υλικού** ως δεύτερο επίπεδο άμυνας.

{% embed url="https://katacontainers.io/" %}

### Συμβουλές Περίληψης

* **Μην χρησιμοποιείτε τη σημαία `--privileged` ή προσαρτήστε ένα** [**Docker socket μέσα στο container**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Το docker socket επιτρέπει τη δημιουργία εμπορευμάτων, οπότε είναι ένας εύκολος τρόπος να αποκτήσετε πλήρη έλεγχο του οικοδεσπότη, για παράδειγμα, εκτελώντας ένα άλλο εμπόρευμα με τη σημαία `--privileged`.
* Μην **εκτελείτε ως root μέσα στο container. Χρησιμοποιήστε έναν** [**διαφορετικό χρήστη**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **και** [**χώρους ονομάτων χρηστών**](https://docs.docker.com/engine/security/userns-remap/)**.** Το root στο container είναι το ίδιο με αυτό στον οικοδεσπότη, εκτός αν έχει ανατεθεί εκ νέου με χώρους ονομάτων χρηστών. Είναι ελαφρώς περιορισμένο από, κυρίως, τους χώρους ονομάτων Linux, τις δυνατότητες και τα cgroups.
* [**Απορρίψτε όλες τις δυνατότητες**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) και ενεργοποιήστε μόνο αυτές που απαιτούνται** (`--cap-add=...`). Πολλοί φορτία εργασίας δεν χρειάζονται καμία δυνατότητα και η προσθήκη τους αυξάνει το πεδίο ενός πιθανού επιθέματος.
* [**Χρησιμοποιήστε την επιλογή ασφαλείας "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) για να αποτρέψετε τις διεργασίες από το να αποκτήσουν περισσότερα προνόμια, για παράδειγμα μέσω suid δυαδικών αρχείων.
* [**Περιορίστε τους διαθέσιμους πόρους για το container**](https://docs.docker.com/engine/reference/run
Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
