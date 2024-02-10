<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


## Logstash

Το Logstash χρησιμοποιείται για να **συγκεντρώνει, μετασχηματίζει και αποστέλλει καταγραφές** μέσω ενός συστήματος που ονομάζεται **pipelines**. Αυτά τα pipelines αποτελούνται από στάδια **εισόδου**, **φίλτρου** και **εξόδου**. Ένα ενδιαφέρον στοιχείο προκύπτει όταν το Logstash λειτουργεί σε ένα μηχάνημα που έχει παραβιαστεί.

### Ρύθμιση του Pipeline

Τα pipelines ρυθμίζονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο αναφέρει τις τοποθεσίες των ρυθμίσεων του pipeline:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf**, που περιέχουν τις ρυθμίσεις των αγωγών, του **Logstash**. Όταν χρησιμοποιείται ένα **εξαρτήματος εξόδου Elasticsearch**, είναι συνηθισμένο για τις **αγωγές** να περιλαμβάνουν **διαπιστευτήρια Elasticsearch**, τα οποία συχνά έχουν εκτεταμένα προνόμια λόγω της ανάγκης του Logstash να γράφει δεδομένα στο Elasticsearch. Οι μπαλαντέρ στις διαδρομές ρυθμίσεων επιτρέπουν στο Logstash να εκτελεί όλες τις αντίστοιχες αγωγές στον καθορισμένο φάκελο.

### Ανέβασμα Προνομίων μέσω Εγγράψιμων Αγωγών

Για να προσπαθήσετε να ανεβάσετε προνόμια, πρώτα εντοπίστε τον χρήστη κάτω από τον οποίο λειτουργεί η υπηρεσία Logstash, συνήθως ο χρήστης **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από τα παρακάτω κριτήρια:

- Διαθέτετε **δικαιώματα εγγραφής** σε ένα αρχείο αγωγής **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί μια μπαλαντέρ, και μπορείτε να γράψετε στον κατάλογο προορισμού

Επιπλέον, πρέπει να πληρούνται **ένα** από τα παρακάτω συνθήματα:

- Δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει την επιλογή **config.reload.automatic: true** ορισμένη

Δεδομένης μιας μπαλαντέρ στη διαμόρφωση, η δημιουργία ενός αρχείου που ταιριάζει με αυτήν τη μπαλαντέρ επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Εδώ, το **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο παράδειγμα που δίνεται, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα, με την έξοδό της να κατευθύνεται στο **/tmp/output.log**.

Με την επιλογή **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash θα ανιχνεύει αυτόματα και θα εφαρμόζει νέες ή τροποποιημένες ρυθμίσεις αγωγού χωρίς να χρειάζεται επανεκκίνηση. Αν δεν υπάρχει μπαλαντέρ, εξακολουθεί να είναι δυνατή η τροποποίηση υπαρχουσών ρυθμίσεων, αλλά συνιστάται προσοχή για να αποφευχθούν διακοπές.

## Αναφορές

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
