# Ερευνητική μεθοδολογία Docker

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Τροποποίηση εμφυτευμάτων

Υπάρχουν υποψίες ότι κάποιο εμφυτευμένο εμφυτευμένο στον Docker container:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Μπορείτε εύκολα **να βρείτε τις τροποποιήσεις που έχουν γίνει σε αυτό το container όσον αφορά την εικόνα** με:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Στην προηγούμενη εντολή το **C** σημαίνει **Αλλαγή** και το **A,** **Προστέθηκε**.\
Αν ανακαλύψετε ότι κάποιο ενδιαφέρον αρχείο όπως το `/etc/shadow` τροποποιήθηκε, μπορείτε να το κατεβάσετε από το container για να ελέγξετε για κακόβουλη δραστηριότητα με:
```bash
docker cp wordpress:/etc/shadow.
```
Μπορείτε επίσης **να το συγκρίνετε με το αρχικό αρχείο** εκτελώντας ένα νέο container και εξάγοντας το αρχείο από αυτό:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Αν ανακαλύψετε ότι **προστέθηκε ένα ύποπτο αρχείο**, μπορείτε να έχετε πρόσβαση στο container και να το ελέγξετε:
```bash
docker exec -it wordpress bash
```
## Τροποποιήσεις εικόνων

Όταν σας δίνεται μια εξαγόμενη εικόνα docker (πιθανότατα σε μορφή `.tar`), μπορείτε να χρησιμοποιήσετε το [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) για **εξαγωγή ενός περιλήψεως των τροποποιήσεων**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Στη συνέχεια, μπορείτε **να αποσυμπιέσετε** την εικόνα και **να έχετε πρόσβαση στα blobs** για να αναζητήσετε ύποπτα αρχεία που ενδέχεται να έχετε βρει στο ιστορικό αλλαγών:
```bash
tar -xf image.tar
```
### Βασική Ανάλυση

Μπορείτε να λάβετε **βασικές πληροφορίες** από την εικόνα που τρέχει:
```bash
docker inspect <image>
```
Μπορείτε επίσης να λάβετε ένα σύνοψη **ιστορικό αλλαγών** με:
```bash
docker history --no-trunc <image>
```
Μπορείτε επίσης να δημιουργήσετε ένα **dockerfile από ένα εικόνα** με:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Διερεύνηση

Για να βρείτε προστεθειμένα/τροποποιημένα αρχεία σε εικόνες docker μπορείτε επίσης να χρησιμοποιήσετε το [**dive**](https://github.com/wagoodman/dive) (κατεβάστε το από [**ανακοινώσεις**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) utility:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Αυτό σας επιτρέπει να **πλοηγηθείτε μέσα από τα διάφορα blobs των εικόνων του docker** και να ελέγξετε ποια αρχεία τροποποιήθηκαν/προστέθηκαν. **Το κόκκινο** σημαίνει προσθήκη και **το κίτρινο** σημαίνει τροποποίηση. Χρησιμοποιήστε το **tab** για να μετακινηθείτε στην άλλη προβολή και το **space** για να συμπτύξετε/ανοίξετε φακέλους.

Με το die δεν θα μπορείτε να έχετε πρόσβαση στο περιεχόμενο των διαφορετικών σταδίων της εικόνας. Για να το κάνετε αυτό, θα πρέπει να **αποσυμπιέσετε κάθε στρώμα και να έχετε πρόσβαση** σε αυτό.\
Μπορείτε να αποσυμπιέσετε όλα τα στρώματα μιας εικόνας από τον κατάλογο όπου αποσυμπιέστηκε η εικόνα εκτελώντας:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Διαπιστευτήρια από τη μνήμη

Σημειώστε ότι όταν εκτελείτε ένα container docker μέσα σε έναν host **μπορείτε να δείτε τις διεργασίες που τρέχουν στο container από τον host** απλά εκτελώντας την εντολή `ps -ef`

Επομένως (ως root) μπορείτε **να αντλήσετε τη μνήμη των διεργασιών** από τον host και να αναζητήσετε **διαπιστευτήρια** ακριβώς [**όπως στο ακόλουθο παράδειγμα**](../../linux-hardening/privilege-escalation/#process-memory).
