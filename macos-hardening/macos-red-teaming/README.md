# macOS Red Teaming

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Κατάχρηση των MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Εάν καταφέρετε να **παραβιάσετε τα διαπιστευτήρια διαχειριστή** για να αποκτήσετε πρόσβαση στην πλατφόρμα διαχείρισης, μπορείτε **πιθανώς να παραβιάσετε όλους τους υπολογιστές** διανέμοντας το malware σας στις μηχανές.

Για το red teaming σε περιβάλλοντα MacOS, συνιστάται ιδιαίτερα να έχετε κάποια κατανόηση του τρόπου λειτουργίας των MDMs:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Χρήση του MDM ως C2

Ένα MDM θα έχει άδεια να εγκαταστήσει, να ερωτήσει ή να αφαιρέσει προφίλ, να εγκαταστήσει εφαρμογές, να δημιουργήσει τοπικούς λογαριασμούς διαχειριστή, να ορίσει κωδικό πρόσβασης του firmware, να αλλάξει το κλειδί του FileVault...

Για να εκτελέσετε το δικό σας MDM, χρειάζεστε **το CSR σας να υπογραφεί από έναν προμηθευτή** τον οποίο μπορείτε να προσπαθήσετε να λάβετε από το [**https://mdmcert.download/**](https://mdmcert.download/). Και για να εκτελέσετε το δικό σας MDM για συσκευές Apple, μπορείτε να χρησιμοποιήσετε το [**MicroMDM**](https://github.com/micromdm/micromdm).

Ωστόσο, για να εγκαταστήσετε μια εφαρμογή σε μια εγγεγραμμένη συσκευή, εξακολουθείτε να χρειάζεστε να υπογραφεί από έναν λογαριασμό προγραμματιστή... ωστόσο, κατά την εγγραφή στο MDM η συσκευή προσθέτει το πιστοποιητικό SSL του MDM ως έμπιστη Αρχή (CA), οπότε τώρα μπορείτε να υπογράψετε οτιδήποτε.

Για να εγγράψετε τη συσκευή σε ένα MDM, χρειάζεστε να εγκαταστήσετε ένα αρχείο **`mobileconfig`** ως root, το οποίο μπορεί να παραδοθεί μέσω ενός αρχείου **pkg** (μπορείτε να το συμπιέσετε σε μορφή zip και όταν το κατεβάσετε από το safari θα αποσυμπιεστεί).

Ο **Mythic agent Orthrus** χρησιμοποιεί αυτήν την τεχνική.

### Κατάχρηση του JAMF PRO

Το JAMF μπορεί να εκτελέσει **προσαρμοσμένα scripts** (scripts που έχουν αναπτυχθεί από τον συστημικό διαχειριστή), **native payloads** (δημιουργία τοπικού λογαριασμού, ορισμός κωδικού EFI, παρακολούθηση αρχείων/διεργασιών...) και **MDM** (διαμορφώσεις συσκευής, πιστοποιητικά συσκευής...).

#### Αυτοεγγραφή JAMF

Πηγαίνετε σε μια σελίδα όπως `https://<όνομα-εταιρείας>.jamfcloud.com/enroll/` για να δείτε εάν έχουν ενεργοποιημένη την **αυτοεγγραφή**. Εάν το έχουν, μπορεί να **ζητήσει διαπιστευτήρια πρόσβασης**.

Μπορείτε να χρησιμοποιήσετε το script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) για να εκτελέσετε μια επίθεση password spraying.

Επιπλέον, αφού βρείτε κατάλληλα διαπιστευτήρια, μπορείτε να δοκιμάσετε να βρείτε με βίαιο τρόπο άλλα ονόματα χρηστών με την επόμενη φόρμα:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Πιστοποίηση συσκευής JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Το δυαδικό **`jamf`** περιείχε το μυστικό για να ανοίξει το keychain που την στιγμή της ανακάλυψης ήταν **κοινόχρηστο** από όλους και ήταν: **`jk23ucnq91jfu9aj`**.\
Επιπλέον, το jamf **διατηρείται** ως **LaunchDaemon** στο **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Πάροχος συσκευής JAMF

Η **URL**
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Έτσι, ένας επιτιθέμενος θα μπορούσε να εγκαταστήσει ένα κακόβουλο πακέτο (`pkg`) που **αντικαθιστά αυτό το αρχείο** κατά την εγκατάσταση, ορίζοντας το **URL σε ένα Mythic C2 listener από έναν πράκτορα Typhon** για να μπορεί να καταχραστεί το JAMF ως C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Παραπληροφόρηση JAMF

Για να **παραπλανήσετε την επικοινωνία** μεταξύ μιας συσκευής και του JMF, χρειάζεστε:

* Το **UUID** της συσκευής: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Το **JAMF keychain** από: `/Library/Application\ Support/Jamf/JAMF.keychain` που περιέχει το πιστοποιητικό της συσκευής

Με αυτές τις πληροφορίες, **δημιουργήστε ένα VM** με το **κλεμμένο** Hardware **UUID** και με το **SIP απενεργοποιημένο**, αποθηκεύστε το **JAMF keychain**, **συνδέστε** τον πράκτορα του Jamf και κλέψτε τις πληροφορίες του.

#### Κλοπή μυστικών

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Μπορείτε επίσης να παρακολουθείτε την τοποθεσία `/Library/Application Support/Jamf/tmp/` για τα **προσαρμοσμένα scripts** που οι διαχειριστές μπορεί να θέλουν να εκτελέσουν μέσω του Jamf καθώς αυτά τοποθετούνται εδώ, εκτελούνται και αφαιρούνται. Αυτά τα scripts **μπορεί να περιέχουν διαπιστευτήρια**.

Ωστόσο, τα **διαπιστευτήρια** μπορεί να περνούν μέσω αυτών των scripts ως **παράμετροι**, οπότε θα χρειαστεί να παρακολουθείτε την εντολή `ps aux | grep -i jamf` (χωρίς να είστε root).

Το script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) μπορεί να ακούει για νέα αρχεία που προστίθενται και νέες παραμέτρους διεργασιών.

### Απομακρυσμένη πρόσβαση στο macOS

Και επίσης για τα **ειδικά** **δίκτυα** **πρωτόκολλα** του **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Σε ορισμένες περιπτώσεις θα διαπιστώσετε ότι ο υπολογιστής **MacOS είναι συνδεδεμένος σε ένα AD**. Σε αυτό το σενάριο θα πρέπει να προσπαθήσετε να **απαριθμήσετε** τον ενεργό κατάλογο όπως είστε συνηθισμένοι. Βρείτε κάποια **βοήθεια** στις παρακάτω σελίδες:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Ένα εργαλείο **τοπικού MacOS** που μπορεί να σας βοηθήσει είναι το `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Επίσης, υπάρχουν μερικά εργαλεία που έχουν προετοιμαστεί για το MacOS για αυτόματη απαρίθμηση του AD και παιχνίδι με το Kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): Το MacHound είναι μια επέκταση του εργαλείου ελέγχου Bloodhound που επιτρέπει τη συλλογή και την εισαγωγή σχέσεων Active Directory σε υπολογιστές MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Το Bifrost είναι ένα έργο Objective-C που σχεδιάστηκε για να αλληλεπιδρά με τις διεπαφές Heimdal krb5 στο macOS. Ο στόχος του έργου είναι να επιτρέψει καλύτερο έλεγχο ασφαλείας γύρω από το Kerberos σε συσκευές macOS χρησιμοποιώντας τις ενσωματωμένες διεπαφές χωρίς να απαιτείται οποιοδήποτε άλλο πλαίσιο ή πακέτο στον στόχο.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Εργαλείο JavaScript για την Αυτοματοποίηση (JXA) για απαρίθμηση του Active Directory. 

### Πληροφορίες τομέα
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Χρήστες

Οι τρεις τύποι χρηστών του MacOS είναι:

* **Τοπικοί Χρήστες** - Διαχειρίζονται από την τοπική υπηρεσία OpenDirectory και δεν συνδέονται με το Active Directory.
* **Δικτυακοί Χρήστες** - Προσωρινοί χρήστες του Active Directory που απαιτούν σύνδεση στον διακομιστή DC για την πιστοποίησή τους.
* **Κινητοί Χρήστες** - Χρήστες του Active Directory με τοπικό αντίγραφο ασφαλείας για τα διαπιστευτήριά τους και τα αρχεία τους.

Οι τοπικές πληροφορίες για τους χρήστες και τις ομάδες αποθηκεύονται στον φάκελο _/var/db/dslocal/nodes/Default._\
Για παράδειγμα, οι πληροφορίες για τον χρήστη με το όνομα _mark_ αποθηκεύονται στο _/var/db/dslocal/nodes/Default/users/mark.plist_ και οι πληροφορίες για την ομάδα _admin_ βρίσκονται στο _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Εκτός από τη χρήση των ακμών HasSession και AdminTo, το **MacHound προσθέτει τρεις νέες ακμές** στη βάση δεδομένων Bloodhound:

* **CanSSH** - οντότητα που επιτρέπεται να συνδεθεί με SSH στον υπολογιστή
* **CanVNC** - οντότητα που επιτρέπεται να συνδεθεί με VNC στον υπολογιστή
* **CanAE** - οντότητα που επιτρέπεται να εκτελέσει AppleEvent scripts στον υπολογιστή
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Περισσότερες πληροφορίες στο [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Πρόσβαση στο Keychain

Το Keychain περιέχει πιθανώς ευαίσθητες πληροφορίες που, αν αποκτηθούν χωρίς να προκαλέσουν ειδοποίηση, μπορούν να βοηθήσουν στην προώθηση μιας άσκησης κόκκινης ομάδας:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Εξωτερικές Υπηρεσίες

Η κόκκινη ομάδα MacOS διαφέρει από μια κανονική κόκκινη ομάδα Windows, καθώς συνήθως **το MacOS είναι ενσωματωμένο με αρκετές εξωτερικές πλατφόρμες απευθείας**. Μια συνηθισμένη διαμόρφωση του MacOS είναι η πρόσβαση στον υπολογιστή χρησιμοποιώντας **συγχρονισμένα διαπιστευτήρια OneLogin και πρόσβαση σε διάφορες εξωτερικές υπηρεσίες** (όπως github, aws...) μέσω του OneLogin.

## Διάφορες τεχνικές κόκκινης ομάδας

### Safari

Όταν ένα αρχείο λήψης στο Safari είναι ένα "ασφαλές" αρχείο, θα ανοίξει **αυτόματα**. Έτσι, για παράδειγμα, αν κατεβάσετε ένα zip, θα αποσυμπιεστεί αυτόματα:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
