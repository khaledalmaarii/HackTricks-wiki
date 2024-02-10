# Περιορισμοί Εκκίνησης/Περιβάλλοντος στο macOS & Προσωπική Μνήμη Εμπιστοσύνης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Βασικές Πληροφορίες

Οι περιορισμοί εκκίνησης στο macOS εισήχθηκαν για να ενισχύσουν την ασφάλεια, ρυθμίζοντας τον τρόπο, τον χρήστη και την προέλευση από την οποία μπορεί να ξεκινήσει ένα διεργασία. Εισήχθηκαν στο macOS Ventura και παρέχουν ένα πλαίσιο που κατηγοριοποιεί κάθε δυαδικό σύστημα σε διακριτές κατηγορίες περιορισμών, οι οποίες καθορίζονται μέσα στην προσωπική μνήμη εμπιστοσύνης, μια λίστα που περιέχει δυαδικά συστήματα και τις αντίστοιχες κατακερματισμένες τους τιμές. Αυτοί οι περιορισμοί επεκτείνονται σε κάθε εκτελέσιμο δυαδικό αρχείο εντός του συστήματος, περιλαμβάνοντας ένα σύνολο κανόνων που καθορίζουν τις απαιτήσεις για την εκκίνηση ενός συγκεκριμένου δυαδικού αρχείου. Οι κανόνες περιλαμβάνουν περιορισμούς που πρέπει να ικανοποιεί ένα δυαδικό αρχείο, περιορισμούς γονικής διεργασίας που πρέπει να πληροί η γονική διεργασία του, και περιορισμούς ευθύνης που πρέπει να τηρούνται από άλλες σχετικές οντότητες.

Ο μηχανισμός επεκτείνεται σε εφαρμογές τρίτων μερών μέσω των **περιορισμών περιβάλλοντος**, που ξεκινούν από το macOS Sonoma, επιτρέποντας στους προγραμματιστές να προστατεύουν τις εφαρμογές τους καθορίζοντας ένα σύνολο κλειδιών και τιμών για τους περιορισμούς περιβάλλοντος.

Ορίζετε τους περιορισμούς **εκκίνησης περιβάλλοντος και βιβλιοθηκών** σε λεξικά περιορισμών που είτε αποθηκεύετε σε αρχεία **`launchd` property list**, είτε σε ξεχωριστά αρχεία **property list** που χρησιμοποιείτε στον υπογραφή κώδικα.

Υπάρχουν 4 τύποι περιορισμών:

* **Περιορισμοί Εαυτού**: Περιορισμοί που εφαρμόζονται στο **τρέχον** δυαδικό αρχείο.
* **Περιορισμοί Γονικής Διεργασίας**: Περιορισμοί που εφαρμόζονται στη **γονική διεργασία** (για παράδειγμα η **`launchd`** που εκτελεί ένα υπηρεσία XP)
* **Περιορισμοί Ευθύνης**: Περιορισμοί που εφαρμόζονται στη **διεργασία που καλεί την υπηρεσία** σε μια επικοινωνία XPC
* **Περιορισμοί Φόρτωσης Βιβλιοθήκης**: Χρησιμοποιήστε περιορισμούς φόρτωσης βιβλιοθήκης για να περιγράψετε εκλεκτικά κώδικα που μπορεί να φορτωθεί

Έτσι, όταν μια διεργασία προσπαθεί να ξεκινήσει μια άλλη διεργασία - καλώντας τις συναρτήσεις `execve(_:_:_:)` ή `posix_spawn(_:_:_:_:_:_:)` - το λειτουργικό σύστημα ελέγχει αν το **εκτελέσιμο** αρχείο **ικανοποιεί** τον **περιορισμό του εαυτού του**. Επίσης, ελέγχει αν το **εκτελέσιμο** αρχείο της **γο
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Πρέπει να βρίσκεται στον τόμο System ή Cryptexes.
* `launch-type == 1`: Πρέπει να είναι ένα σύστημα υπηρεσίας (plist στο LaunchDaemons).
* `validation-category == 1`: Ένα εκτελέσιμο αρχείο του λειτουργικού συστήματος.
* `is-init-proc`: Launchd

### Αντιστροφή των κατηγοριών LC

Έχετε περισσότερες πληροφορίες [**εδώ**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), αλλά βασικά, ορίζονται στο **AMFI (AppleMobileFileIntegrity)**, οπότε πρέπει να κατεβάσετε το Kernel Development Kit για να πάρετε το **KEXT**. Τα σύμβολα που ξεκινούν με **`kConstraintCategory`** είναι τα **ενδιαφέροντα**. Αν τα εξάγετε, θα πάρετε έναν κωδικοποιημένο ροή DER (ASN.1) που θα πρέπει να αποκωδικοποιήσετε με το [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ή τη βιβλιοθήκη python-asn1 και το σενάριο `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) που θα σας δώσει ένα πιο κατανοητό αλφαριθμητικό.

## Περιορισμοί Περιβάλλοντος

Αυτοί είναι οι περιορισμοί εκκίνησης που έχουν ρυθμιστεί σε **εφαρμογές τρίτων**. Ο προγραμματιστής μπορεί να επιλέξει τα **γεγονότα** και τους **λογικούς τελεστές** που θα χρησιμοποιηθούν στην εφαρμογή του για να περιορίσει την πρόσβαση σε αυτήν.

Είναι δυνατόν να απαριθμήσετε τους περιορισμούς περιβάλλοντος μιας εφαρμογής με:
```bash
codesign -d -vvvv app.app
```
## Αποθήκες Εμπιστοσύνης

Στο **macOS** υπάρχουν μερικές αποθήκες εμπιστοσύνης:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Και στο iOS φαίνεται ότι βρίσκεται στο **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
Στο macOS που τρέχει σε συσκευές Apple Silicon, αν ένα υπογεγραμμένο από την Apple δυαδικό αρχείο δεν βρίσκεται στην αποθήκη εμπιστοσύνης, το AMFI θα αρνηθεί να το φορτώσει.
{% endhint %}

### Απαρίθμηση Αποθηκών Εμπιστοσύνης

Τα προηγούμενα αρχεία αποθήκης εμπιστοσύνης είναι σε μορφή **IMG4** και **IM4P**, με το IM4P να είναι η ενότητα φορτίου μιας μορφής IMG4.

Μπορείτε να χρησιμοποιήσετε το [**pyimg4**](https://github.com/m1stadev/PyIMG4) για να εξαγάγετε το φορτίο των βάσεων δεδομένων:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Μια άλλη επιλογή θα μπορούσε να είναι η χρήση του εργαλείου [**img4tool**](https://github.com/tihmstar/img4tool), το οποίο θα λειτουργήσει ακόμα και στο M1 ακόμα κι αν η έκδοση είναι παλιά και για x86\_64 αν το εγκαταστήσετε στις κατάλληλες τοποθεσίες).

Τώρα μπορείτε να χρησιμοποιήσετε το εργαλείο [**trustcache**](https://github.com/CRKatri/trustcache) για να λάβετε τις πληροφορίες σε μια αναγνώσιμη μορφή:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Η αποθήκη εμπιστοσύνης ακολουθεί την παρακάτω δομή, οπότε η **κατηγορία LC είναι η 4η στήλη**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Στη συνέχεια, μπορείτε να χρησιμοποιήσετε ένα σενάριο όπως [**αυτό**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) για να εξάγετε δεδομένα.

Από αυτά τα δεδομένα μπορείτε να ελέγξετε τις εφαρμογές με μια **τιμή περιορισμού εκκίνησης `0`**, που είναι αυτές που δεν έχουν περιορισμούς ([**ελέγξτε εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) για τις τιμές κάθε εφαρμογής).

## Προστασία από επιθέσεις

Οι περιορισμοί εκκίνησης θα είχαν αντιμετωπίσει αρκετές παλαιές επιθέσεις, **διασφαλίζοντας ότι η διαδικασία δεν θα εκτελεστεί σε απροσδόκητες συνθήκες:** Για παράδειγμα από απροσδόκητες τοποθεσίες ή όταν καλείται από μη αναμενόμενη γονική διεργασία (αν μόνο το launchd θα έπρεπε να το εκκινήσει).

Επιπλέον, οι περιορισμοί εκκίνησης αντιμετωπίζουν επίσης **επιθέσεις υποβάθμισης**.

Ωστόσο, δεν αντιμετωπίζουν κοινές καταχρήσεις XPC, ενσωματώσεις κώδικα Electron ή ενσωματώσεις dylib χωρίς επικύρωση βιβλιοθήκης (εκτός αν είναι γνωστά τα αναγνωριστικά ομάδας που μπορούν να φορτώσουν βιβλιοθήκες).

### Προστασία XPC Daemon

Στην έκδοση Sonoma, ένα σημαντικό σημείο είναι η **διαμόρφωση της ευθύνης της υπηρεσίας XPC daemon**. Η υπηρεσία XPC είναι υπεύθυνη για τον εαυτό της, αντί να είναι υπεύθυνος ο συνδεόμενος πελάτης. Αυτό καταγράφεται στην αναφορά ανατροφοδότησης FB13206884. Αυτή η ρύθμιση μπορεί να φαίνεται ελαττωματική, καθώς επιτρέπει ορισμένες αλληλεπιδράσεις με την υπηρεσία XPC:

- **Εκκίνηση της υπηρεσίας XPC**: Αν θεωρηθεί ως σφάλμα, αυτή η ρύθμιση δεν επιτρέπει την εκκίνηση της υπηρεσίας XPC μέσω κώδικα επιτιθέμενου.
- **Σύνδεση σε μια ενεργή υπηρεσία**: Αν η υπηρεσία XPC είναι ήδη εκτελούμενη (πιθανώς ενεργοποιημένη από την αρχική εφαρμογή της), δεν υπάρχουν εμπόδια για τη σύνδεση σε αυτήν.

Αν και η επιβολή περιορισμών στην υπηρεσία XPC μπορεί να είναι χρήσιμη με τον **περιορισμό του παραθύρου για πιθανές επιθέσεις**, δεν αντιμετωπίζει τον κύριο προβληματισμό. Η διασφάλιση της ασφάλειας της υπηρεσίας XPC απαιτεί ουσιαστικά **την αποτελεσματική επαλήθευση του συνδεόμενου πελάτη**. Αυτή παραμένει η μοναδική μέθοδος για την ενίσχυση της ασφάλειας της υπηρεσίας. Επίσης, αξίζει να σημειωθεί ότι η αναφερόμενη διαμόρφωση ευθύνης είναι προς το παρόν λειτουργική, πράγμα που μπορεί να μην συμφωνεί με τον αρχικό σχεδιασμό.

### Προστασία Electron

Ακόμα κι αν απαιτείται η εφαρμογή να **ανοίγεται από την LaunchService** (στους περιορισμούς των γονικών διεργασιών). Αυτό μπορεί να επιτευχθεί χρησιμοποιώντας την εντολή **`open`** (η οποία μπορεί να ορίσει μεταβλητές περιβάλλοντος) ή χρησιμοποιώντας το **API της Launch Services** (όπου μπορούν να δηλωθούν μεταβλητές περιβάλλοντος).

## Αναφορές

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στ
