# macOS Dirty NIB

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Για περισσότερες λεπτομέρειες σχετικά με την τεχνική, ελέγξτε την αρχική ανάρτηση από:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) και την επόμενη ανάρτηση από [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Ακολουθεί μια περίληψη:

### Τι είναι τα αρχεία Nib

Τα αρχεία Nib (συντομογραφία του NeXT Interface Builder), μέρος του οικοσυστήματος ανάπτυξης της Apple, προορίζονται για τον καθορισμό **UI στοιχείων** και των αλληλεπιδράσεών τους σε εφαρμογές. Περιλαμβάνουν σειριοποιημένα αντικείμενα όπως παράθυρα και κουμπιά, και φορτώνονται κατά την εκτέλεση. Παρά τη συνεχιζόμενη χρήση τους, η Apple τώρα προτείνει τα Storyboards για πιο ολοκληρωμένη οπτικοποίηση ροής UI.

Το κύριο αρχείο Nib αναφέρεται στην τιμή **`NSMainNibFile`** μέσα στο αρχείο `Info.plist` της εφαρμογής και φορτώνεται από τη λειτουργία **`NSApplicationMain`** που εκτελείται στη λειτουργία `main` της εφαρμογής.

### Διαδικασία Εισαγωγής Dirty Nib

#### Δημιουργία και Ρύθμιση ενός Αρχείου NIB

1. **Αρχική Ρύθμιση**:
* Δημιουργήστε ένα νέο αρχείο NIB χρησιμοποιώντας το XCode.
* Προσθέστε ένα Αντικείμενο στην διεπαφή, ρυθμίζοντας την κλάση του σε `NSAppleScript`.
* Ρυθμίστε την αρχική ιδιότητα `source` μέσω των Χαρακτηριστικών Χρόνου Εκτέλεσης που Ορίστηκαν από τον Χρήστη.
2. **Gadget Εκτέλεσης Κώδικα**:
* Η ρύθμιση διευκολύνει την εκτέλεση AppleScript κατόπιν αιτήματος.
* Ενσωματώστε ένα κουμπί για να ενεργοποιήσετε το αντικείμενο `Apple Script`, ενεργοποιώντας συγκεκριμένα τον επιλεγέα `executeAndReturnError:`.
3. **Δοκιμή**:
* Ένα απλό Apple Script για δοκιμαστικούς σκοπούς:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* Δοκιμάστε εκτελώντας το στον αποσφαλματωτή XCode και κάνοντας κλικ στο κουμπί.

#### Στοχοποίηση μιας Εφαρμογής (Παράδειγμα: Pages)

1. **Προετοιμασία**:
* Αντιγράψτε την στοχοθετημένη εφαρμογή (π.χ., Pages) σε έναν ξεχωριστό φάκελο (π.χ., `/tmp/`).
* Ξεκινήστε την εφαρμογή για να παρακάμψετε τα ζητήματα του Gatekeeper και να την αποθηκεύσετε στην κρυφή μνήμη.
2. **Αντικατάσταση Αρχείου NIB**:
* Αντικαταστήστε ένα υπάρχον αρχείο NIB (π.χ., NIB Πίνακα Σχετικά) με το κατασκευασμένο αρχείο DirtyNIB.
3. **Εκτέλεση**:
* Ενεργοποιήστε την εκτέλεση αλληλεπιδρώντας με την εφαρμογή (π.χ., επιλέγοντας το στοιχείο μενού `About`).

#### Απόδειξη της Έννοιας: Πρόσβαση σε Δεδομένα Χρήστη

* Τροποποιήστε το AppleScript για να αποκτήσετε πρόσβαση και να εξάγετε δεδομένα χρήστη, όπως φωτογραφίες, χωρίς τη συγκατάθεση του χρήστη.

### Δείγμα Κώδικα: Κακόβουλο Αρχείο .xib

* Αποκτήστε πρόσβαση και ελέγξτε ένα [**δείγμα κακόβουλου αρχείου .xib**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) που δείχνει την εκτέλεση αυθαίρετου κώδικα.

### Άλλο Παράδειγμα

Στην ανάρτηση [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) μπορείτε να βρείτε οδηγίες για το πώς να δημιουργήσετε ένα dirty nib.&#x20;

### Αντιμετώπιση Περιορισμών Εκκίνησης

* Οι Περιορισμοί Εκκίνησης εμποδίζουν την εκτέλεση εφαρμογών από απροσδόκητες τοποθεσίες (π.χ., `/tmp`).
* Είναι δυνατόν να εντοπιστούν εφαρμογές που δεν προστατεύονται από Περιορισμούς Εκκίνησης και να στοχοποιηθούν για εισαγωγή αρχείου NIB.

### Πρόσθετες Προστασίες macOS

Από το macOS Sonoma και μετά, οι τροποποιήσεις μέσα σε πακέτα εφαρμογών είναι περιορισμένες. Ωστόσο, οι προηγούμενες μέθοδοι περιλάμβαναν:

1. Αντιγραφή της εφαρμογής σε διαφορετική τοποθεσία (π.χ., `/tmp/`).
2. Μετονομασία φακέλων μέσα στο πακέτο εφαρμογής για να παρακαμφθούν οι αρχικές προστασίες.
3. Μετά την εκτέλεση της εφαρμογής για να καταχωρηθεί με τον Gatekeeper, τροποποίηση του πακέτου εφαρμογής (π.χ., αντικατάσταση του MainMenu.nib με το Dirty.nib).
4. Επαναφορά των φακέλων και επανεκτέλεση της εφαρμογής για να εκτελεστεί το εισαγόμενο αρχείο NIB.

**Σημείωση**: Οι πρόσφατες ενημερώσεις του macOS έχουν μετριάσει αυτήν την εκμετάλλευση αποτρέποντας τις τροποποιήσεις αρχείων εντός των πακέτων εφαρμογών μετά την αποθήκευση στην κρυφή μνήμη του Gatekeeper, καθιστώντας την εκμετάλλευση αναποτελεσματική.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
