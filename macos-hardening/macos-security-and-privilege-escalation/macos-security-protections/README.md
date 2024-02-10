# Προστασίες ασφάλειας του macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Gatekeeper

Ο Gatekeeper συνήθως χρησιμοποιείται για να αναφέρεται στον συνδυασμό των **Quarantine + Gatekeeper + XProtect**, 3 ασφαλείας modules του macOS που θα προσπαθήσουν να **εμποδίσουν τους χρήστες να εκτελέσουν πιθανώς κακόβουλο λογισμικό που έχει ληφθεί**.

Περισσότερες πληροφορίες στο:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Περιορισμοί Διεργασιών

### SIP - Προστασία Ακεραιότητας Συστήματος

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Αμμοθύρα

Η Αμμοθύρα του macOS **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στην αμμοθύρα στις **επιτρεπόμενες ενέργειες που καθορίζονται στο προφίλ της αμμοθύρας** με το οποίο η εφαρμογή εκτελείται. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο σε αναμενόμενους πόρους**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Διαφάνεια, Συναίνεση και Έλεγχος**

Το TCC (Διαφάνεια, Συναίνεση και Έλεγχος) είναι ένα πλαίσιο ασφαλείας. Σχεδιάστηκε για να **διαχειρίζεται τις άδειες** των εφαρμογών, ειδικότερα ρυθμίζοντας την πρόσβασή τους σε ευαίσθητα χαρακτηριστικά. Αυτό περιλαμβάνει στοιχεία όπως **υπηρεσίες τοποθεσίας, επαφές, φωτογραφίες, μικρόφωνο, κάμερα, προσβασιμότητα και πλήρη πρόσβαση στο δίσκο**. Το TCC διασφαλίζει ότι οι εφαρμογές μπορούν να έχουν πρόσβαση σε αυτά τα χαρακτηριστικά μόνο μετά από ρητή συναίνεση του χρήστη, ενισχύοντας έτσι την ιδιωτικότητα και τον έλεγχο των προσωπικών δεδομένων.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Περιορισμοί Εκκίνησης/Περιβάλλοντος & Προσωπική Εμπιστοσύνη

Οι περιορισμοί εκκίνησης στο macOS είναι μια λειτουργία ασφαλείας για να **ρυθμίζει την έναρξη διεργασιών** καθορίζοντας **ποιος μπορεί να ξεκινήσει** μια διεργασία, **πώς** και **από πού**. Εισήχθηκαν στο macOS Ventura, κατηγοριοποιούν τις δυαδικές αρχεία του συστήματος σε κατηγορίες περιορισμών μέσα σε μια **προσωπική εμπιστοσύνη**. Κάθε εκτελέσιμο δυαδικό έχει ορισμένους κανόνες για την έναρξή του, συμπεριλαμβανομένων των περιορισμών **αυτού, του γονέα και του υπεύθυνου**. Επεκτάθηκαν σε εφαρμογές τρίτων ως **Περιορισμοί Περιβάλλοντος** στο macOS Sonoma, αυτά τα χαρακτηριστικά βοηθούν στη μείωση των πιθανών εκμεταλλεύσεων του συστήματος διαχειρίζοντας τις συνθήκες έναρξης διεργασιών.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Εργαλείο Αφαίρεσης Κακόβουλου Λογισμικού

Το Εργαλείο Αφαίρεσης Κακόβουλου Λογισμικού (MRT) είναι μέρος της ασφαλείας του macOS.
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Απαρίθμηση

Είναι δυνατόν να **απαριθμήσετε όλα** τα ρυθμισμένα στοιχεία φόντου που εκτελούνται με το εργαλείο γραμμής εντολών της Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Επιπλέον, είναι επίσης δυνατό να αναφέρετε αυτές τις πληροφορίες με το [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Αυτές οι πληροφορίες αποθηκεύονται στο **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** και ο Τερματικός χρειάζεται FDA.

### Αλλοίωση του BTM

Όταν βρεθεί μια νέα διαρκής λειτουργία, γίνεται μια ειδοποίηση τύπου **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Έτσι, οποιοδήποτε τρόπος για να **αποτρέψει** αυτή η **ειδοποίηση** να σταλεί ή ο **πράκτορας να ειδοποιήσει** τον χρήστη θα βοηθήσει έναν επιτιθέμενο να _**παρακάμψει**_ το BTM.

* **Επαναφορά της βάσης δεδομένων**: Εκτελώντας την παρακάτω εντολή θα επαναφέρει τη βάση δεδομένων (θα την ξαναχτίσει από την αρχή), ωστόσο, για κάποιο λόγο, μετά την εκτέλεση αυτής της εντολής, **δεν θα ειδοποιηθεί καμία νέα διαρκής λειτουργία μέχρι να γίνει επανεκκίνηση του συστήματος**.
* Απαιτείται **root** πρόσβαση.
```bash
# Reset the database
sfltool resettbtm
```
* **Διακοπή του Πράκτορα**: Είναι δυνατόν να στείλετε ένα σήμα διακοπής στον πράκτορα, έτσι ώστε να **μην ειδοποιεί τον χρήστη** όταν ανιχνεύονται νέες αποκαλύψεις.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Σφάλμα**: Εάν η διαδικασία που δημιούργησε την μόνιμη παρουσία υπάρχει γρήγορα αμέσως μετά, το daemon θα προσπαθήσει να λάβει πληροφορίες για αυτήν, θα αποτύχει και δεν θα είναι σε θέση να στείλει το γεγονός που υποδηλώνει ότι μια νέα πράξη είναι μόνιμη.

Αναφορές και **περισσότερες πληροφορίες για το BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
