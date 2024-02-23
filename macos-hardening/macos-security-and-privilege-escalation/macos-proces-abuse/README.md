# Κατάχρηση Διεργασιών στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Κατάχρηση Διεργασιών στο MacOS

Το MacOS, όπως κάθε άλλο λειτουργικό σύστημα, παρέχει μια ποικιλία μεθόδων και μηχανισμών για **διεργασίες να αλληλεπιδρούν, να επικοινωνούν και να μοιράζονται δεδομένα**. Αν και αυτές οι τεχνικές είναι απαραίτητες για την αποτελεσματική λειτουργία του συστήματος, μπορούν επίσης να καταχρηστούν από κακόβουλους χρήστες για **εκτέλεση κακόβουλων δραστηριοτήτων**.

### Ενσωμάτωση Βιβλιοθήκης

Η Ενσωμάτωση Βιβλιοθήκης είναι μια τεχνική όπου ένας επιτιθέμενος **αναγκάζει μια διεργασία να φορτώσει μια κακόβουλη βιβλιοθήκη**. Μόλις ενσωματωθεί, η βιβλιοθήκη τρέχει στο πλαίσιο της στόχευσης διεργασίας, παρέχοντας στον επιτιθέμενο τα ίδια δικαιώματα και πρόσβαση με τη διεργασία.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Αγκάληση Συνάρτησης

Η Αγκάληση Συνάρτησης περιλαμβάνει το **εμπλέκοντας κλήσεις συναρτήσεων** ή μηνύματα μέσα σε κώδικα λογισμικού. Με την αγκάληση συναρτήσεων, ένας επιτιθέμενος μπορεί να **τροποποιήσει τη συμπεριφορά** μιας διεργασίας, να παρατηρήσει ευαίσθητα δεδομένα ή ακόμη και να αποκτήσει έλεγχο επί της ροής εκτέλεσης.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Επικοινωνία Μεταξύ Διεργασιών

Η Επικοινωνία Μεταξύ Διεργασιών (IPC) αναφέρεται σε διάφορες μεθόδους με τις οποίες ξεχωριστές διεργασίες **μοιράζονται και ανταλλάσσουν δεδομένα**. Ενώ η IPC είναι θεμελιώδης για πολλές νόμιμες εφαρμογές, μπορεί επίσης να καταχρηστεί για να υπονομεύσει την απομόνωση διεργασιών, να διαρρεύσει ευαίσθητες πληροφορίες ή να εκτελέσει μη εξουσιοδοτημένες ενέργειες.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Ενσωμάτωση Εφαρμογών Electron

Οι εφαρμογές Electron που εκτελούνται με συγκεκριμένες μεταβλητές περιβάλλοντος μπορεί να είναι ευάλωτες στην ενσωμάτωση διεργασιών:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Ενσωμάτωση Chromium

Είναι δυνατόν να χρησιμοποιηθούν οι σημαίες `--load-extension` και `--use-fake-ui-for-media-stream` για να πραγματοποιηθεί μια **επίθεση man in the browser** επιτρέποντας την κλοπή πληκτρολογήσεων, κυκλοφορίας, cookies, ενσωμάτωση σελίδων...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Βρώμικο NIB

Τα αρχεία NIB **ορίζουν στοιχεία διεπαφής χρήστη (UI)** και τις αλληλεπιδράσεις τους μέσα σε μια εφαρμογή. Ωστόσο, μπορούν **να εκτελέσουν αυθαίρετες εντολές** και ο **Gatekeeper δεν εμποδίζει** μια ήδη εκτελούμενη εφαρμογή από το να εκτελεστεί αν ένα **αρχείο NIB τροποποιηθεί**. Επομένως, θα μπορούσαν να χρησιμοποιηθούν για να κάνουν αυθαίρετα προγράμματα να εκτελούν αυθαίρετες εντολές:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Ενσωμάτωση Εφαρμογών Java

Είναι δυνατόν να καταχραστείτε ορισμένες δυνατότητες της Java (όπως η μεταβλητή περιβάλλοντος **`_JAVA_OPTS`**) για να κάνετε μια εφαρμογή Java να εκτελέσει **αυθαίρετο κώδικα/εντολές**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Ενσωμάτωση Εφαρμογών .Net

Είναι δυνατόν να ενσωματώσετε κώδικα σε εφαρμογές .Net με το **κατάχρηση της λειτουργικότητας εντοπισμού σφαλμάτων του .Net** (που δεν προστατεύεται από τις προστασίες του macOS όπως η ενίσχυση κατά την εκτέλεση).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Ενσωμάτωση Perl

Ελέγξτε διάφορες επιλογές για να κάνετε ένα σενάριο Perl να εκτελέσει αυθαίρετο κώδικα σε:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ενσωμάτωση Ruby

Είναι επίσης δυνατόν να καταχραστείτε τις μεταβλητές περιβάλλοντος της Ruby για να κάνετε αυθαίρετα σενάρια να εκτελέσουν αυθαίρετο κώδικα:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Ενσωμάτωση Python

Αν η μεταβλητή περιβάλλοντος **`PYTHONINSPECT`** είναι ορισμένη, η διεργασία Python θα μεταβεί σε ένα κλιέ Python μόλις ολοκληρωθεί. Είναι επίσης δυνατόν να χρησιμοποιήσετε το **`PYTHONSTARTUP`** για να υποδείξετε ένα σενάριο Python που θα εκτελεστεί στην αρχή μιας διαδραστικής συνεδρίας.\
Ωστόσο, σημειώστε ότι το σενάριο **`PYTHONSTARTUP`** δεν θα εκτελεστεί όταν το **`PYTHONINSPECT`** δημιουργεί τη διαδραστική συνεδρία.

Άλλες μεταβλητές περιβάλλοντος όπως **`PYTHONPATH`** και **`PYTHONHOME`** μπορεί επίσης να είναι χρήσιμες για να κάνετε μια εντολή Python να εκτελέσει αυθαίρετο κώδικα.

Σημειώστε ότι τα εκτελέσι
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## Ανίχνευση

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) είναι μια εφαρμογή ανοιχτού κώδικα που μπορεί να **ανιχνεύσει και να μπλοκάρει ενέργειες ενσωμάτωσης διεργασιών**:

* Χρησιμοποιώντας **Μεταβλητές Περιβάλλοντος**: Θα παρακολουθεί την ύπαρξη οποιασδήποτε από τις ακόλουθες μεταβλητές περιβάλλοντος: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** και **`ELECTRON_RUN_AS_NODE`**
* Χρησιμοποιώντας κλήσεις **`task_for_pid`**: Για να βρει όταν μια διεργασία θέλει να λάβει τη **θύρα εργασίας μιας άλλης** που επιτρέπει την ενσωμάτωση κώδικα στη διεργασία.
* **Παράμετροι εφαρμογών Electron**: Κάποιος μπορεί να χρησιμοποιήσει τις παραμέτρους γραμμής εντολών **`--inspect`**, **`--inspect-brk`** και **`--remote-debugging-port`** για να ξεκινήσει μια εφαρμογή Electron σε λειτουργία εντοπισμού σφαλμάτων και έτσι να ενσωματώσει κώδικα σε αυτήν.
* Χρησιμοποιώντας **συμβολικούς συνδέσμους** ή **σκληρούς συνδέσμους**: Συνήθως το πιο κοινό κακόβουλο είναι να **τοποθετήσουμε ένα σύνδεσμο με τα δικαιώματα του χρήστη μας**, και **να τον κατευθύνουμε προς μια τοποθεσία με υψηλότερα δικαιώματα**. Η ανίχνευση είναι πολύ απλή τόσο για σκληρούς όσο και για συμβολικούς συνδέσμους. Αν η διαδικασία που δημιουργεί τον σύνδεσμο έχει ένα **διαφορετικό επίπεδο δικαιωμάτων** από το αρχείο-στόχο, δημιουργούμε μια **ειδοποίηση**. Δυστυχώς, στην περίπτωση των συμβολικών συνδέσμων, η αποκλεισμός δεν είναι δυνατός, καθώς δεν έχουμε πληροφορίες σχετικά με τον προορισμό του συνδέσμου πριν τη δημιουργία του. Αυτή είναι μια περιορισμένη λειτουργία του πλαισίου EndpointSecuriy της Apple.

### Κλήσεις που γίνονται από άλλες διεργασίες

Σε [**αυτήν την ανάρτηση στο blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) μπορείτε να βρείτε πώς είναι δυνατόν να χρησιμοποιηθεί η συνάρτηση **`task_name_for_pid`** για να λάβετε πληροφορίες σχετικά με άλλες **διεργασίες που ενσωματώνουν κώδικα σε μια διεργασία** και στη συνέχεια να λάβετε πληροφορίες σχετικά με αυτήν την άλλη διεργασία.

Σημειώστε ότι για να καλέσετε αυτήν τη συνάρτηση πρέπει να είστε **το ίδιο uid** με αυτόν που εκτελεί τη διεργασία ή **root** (και επιστρέφει πληροφορίες σχετικά με τη διεργασία, όχι έναν τρόπο για ενσωμάτωση κώδικα).

## Αναφορές

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
