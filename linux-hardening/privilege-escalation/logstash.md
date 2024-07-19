{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Logstash

Το Logstash χρησιμοποιείται για **να συγκεντρώνει, να μετασχηματίζει και να αποστέλλει αρχεία καταγραφής** μέσω ενός συστήματος που ονομάζεται **pipelines**. Αυτές οι pipelines αποτελούνται από στάδια **input**, **filter** και **output**. Ένα ενδιαφέρον στοιχείο προκύπτει όταν το Logstash λειτουργεί σε μια συμβιβασμένη μηχανή.

### Pipeline Configuration

Οι pipelines ρυθμίζονται στο αρχείο **/etc/logstash/pipelines.yml**, το οποίο απαριθμεί τις τοποθεσίες των ρυθμίσεων των pipelines:
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
Αυτό το αρχείο αποκαλύπτει πού βρίσκονται τα αρχεία **.conf**, που περιέχουν ρυθμίσεις pipeline. Όταν χρησιμοποιείται ένα **Elasticsearch output module**, είναι συνηθισμένο τα **pipelines** να περιλαμβάνουν **Elasticsearch credentials**, οι οποίες συχνά διαθέτουν εκτενή δικαιώματα λόγω της ανάγκης του Logstash να γράφει δεδομένα στο Elasticsearch. Οι χαρακτήρες μπαλαντέρ σε διαδρομές ρύθμισης επιτρέπουν στο Logstash να εκτελεί όλα τα αντίστοιχα pipelines στον καθορισμένο φάκελο.

### Privilege Escalation via Writable Pipelines

Για να προσπαθήσετε να αποκτήσετε δικαιώματα, πρώτα προσδιορίστε τον χρήστη υπό τον οποίο εκτελείται η υπηρεσία Logstash, συνήθως ο χρήστης **logstash**. Βεβαιωθείτε ότι πληροίτε **ένα** από αυτά τα κριτήρια:

- Έχετε **δικαίωμα εγγραφής** σε ένα αρχείο pipeline **.conf** **ή**
- Το αρχείο **/etc/logstash/pipelines.yml** χρησιμοποιεί έναν χαρακτήρα μπαλαντέρ και μπορείτε να γράψετε στον στόχο φάκελο

Επιπλέον, **μία** από αυτές τις συνθήκες πρέπει να πληρούται:

- Δυνατότητα επανεκκίνησης της υπηρεσίας Logstash **ή**
- Το αρχείο **/etc/logstash/logstash.yml** έχει ρυθμιστεί σε **config.reload.automatic: true**

Δεδομένου ενός χαρακτήρα μπαλαντέρ στη ρύθμιση, η δημιουργία ενός αρχείου που ταιριάζει με αυτόν τον χαρακτήρα μπαλαντέρ επιτρέπει την εκτέλεση εντολών. Για παράδειγμα:
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
Εδώ, το **interval** καθορίζει τη συχνότητα εκτέλεσης σε δευτερόλεπτα. Στο δοθέν παράδειγμα, η εντολή **whoami** εκτελείται κάθε 120 δευτερόλεπτα, με την έξοδό της να κατευθύνεται στο **/tmp/output.log**.

Με το **config.reload.automatic: true** στο **/etc/logstash/logstash.yml**, το Logstash θα ανιχνεύει και θα εφαρμόζει αυτόματα νέες ή τροποποιημένες ρυθμίσεις pipeline χωρίς να απαιτείται επανεκκίνηση. Εάν δεν υπάρχει wildcard, οι τροποποιήσεις μπορούν να γίνουν σε υπάρχουσες ρυθμίσεις, αλλά συνιστάται προσοχή για να αποφευχθούν διαταραχές.

## References
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
