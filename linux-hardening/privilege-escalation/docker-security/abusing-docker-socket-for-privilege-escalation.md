# Κατάχρηση του Docker Socket για Ανέλιξη Προνομίων

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>

Υπάρχουν κάποιες περιπτώσεις όπου έχετε απλώς **πρόσβαση στο Docker Socket** και θέλετε να το χρησιμοποιήσετε για να **αναβαθμίσετε τα προνόμια**. Ορισμένες ενέργειες μπορεί να είναι πολύ ύποπτες και μπορεί να θέλετε να τις αποφύγετε, γι 'αυτό εδώ μπορείτε να βρείτε διάφορες σημαίες που μπορούν να είναι χρήσιμες για την ανέλιξη προνομίων:

### Μέσω της σύνδεσης

Μπορείτε να **συνδέσετε** διάφορα μέρη του **αρχείου συστήματος** σε ένα container που εκτελείται ως root και να τα **προσπελάσετε**.\
Μπορείτε επίσης να **καταχραστείτε μια σύνδεση για να αναβαθμίσετε τα προνόμια** μέσα στο container.

* **`-v /:/host`** -> Συνδέστε το αρχείο συστήματος του host στο container, έτσι ώστε να μπορείτε να **διαβάσετε το αρχείο συστήματος του host**.
* Εάν θέλετε να **νιώσετε ότι βρίσκεστε στον host** αλλά να είστε στο container, μπορείτε να απενεργοποιήσετε άλλα μηχανισμούς άμυνας χρησιμοποιώντας σημαίες όπως:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Αυτό είναι παρόμοιο με την προηγούμενη μέθοδο, αλλά εδώ **συνδέουμε το δίσκο της συσκευής**. Στη συνέχεια, μέσα στο container εκτελέστε `mount /dev/sda1 /mnt` και μπορείτε να **προσπελάσετε** το **αρχείο συστήματος του host** στο `/mnt`
* Εκτελέστε την εντολή `fdisk -l` στον host για να βρείτε τη συσκευή `</dev/sda1>` που θα συνδέσετε
* **`-v /tmp:/host`** -> Εάν για κάποιο λόγο μπορείτε να **συνδέσετε απλώς έναν κατάλογο** από τον host και έχετε πρόσβαση μέσα στον host. Συνδέστε τον και δημιουργήστε ένα **`/bin/bash`** με **suid** στον συνδεδεμένο κατάλογο, έτσι ώστε να μπορείτε να το **εκτελέσετε από τον host και να αναβαθμίσετε σε root**.

{% hint style="info" %}
Να σημειωθεί ότι ίσως δεν μπορείτε να συνδέσετε τον φάκελο `/tmp` αλλά μπορείτε να συνδέσετε έναν **διαφορετικό εγγράψιμο φάκελο**. Μπορείτε να βρείτε εγγράψιμους καταλόγους χρησιμοποιώντας: `find / -writable -type d 2>/dev/null`

**Να σημειωθεί ότι όχι όλοι οι κατάλογοι σε ένα μηχάνημα Linux θα υποστηρίζουν το suid bit!** Για να ελέγξετε ποιοι κατάλογοι υποστηρίζουν το suid bit, εκτελέστε την εντολή `mount | grep -v "nosuid"`. Για παράδειγμα, συνήθως οι `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` και `/var/lib/lxcfs` δεν υποστηρίζουν το suid bit.

Να σημειωθεί επίσης ότι εάν μπορεί
