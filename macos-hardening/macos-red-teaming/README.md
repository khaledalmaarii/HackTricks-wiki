# macOS Red Teaming

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τεχνικές χάκινγκ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Κατάχρηση MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Εάν καταφέρετε να **διαρρεύσετε διαπιστευτήρια διαχειριστή** για πρόσβαση στην πλατφόρμα διαχείρισης, μπορείτε **πιθανώς να διαρρεύσετε όλους τους υπολογιστές** διανέμοντας το malware σας στις συσκευές.

Για το red teaming σε περιβάλλοντα MacOS είναι πολύ σημαντικό να έχετε μια κατανόηση για το πώς λειτουργούν τα MDMs:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Χρήση MDM ως C2

Ένα MDM έχει άδεια να εγκαταστήσει, να ερωτήσει ή να αφαιρέσει προφίλ, να εγκαταστήσει εφαρμογές, να δημιουργήσει τοπικούς λογαριασμούς διαχειριστή, να ορίσει κωδικό πρόσβασης firmware, να αλλάξει το κλειδί FileVault...

Για να τρέξετε το δικό σας MDM, χρειάζεστε το **CSR σας υπογεγραμμένο από έναν προμηθευτή** το οποίο θα μπορούσατε να προσπαθήσετε να λάβετε από το [**https://mdmcert.download/**](https://mdmcert.download/). Και για να τρέξετε το δικό σας MDM για συσκευές Apple μπορείτε να χρησιμοποιήσετε το [**MicroMDM**](https://github.com/micromdm/micromdm).

Ωστόσο, για να εγκαταστήσετε μια εφαρμογή σε μια εγγεγραμμένη συσκευή, πρέπει ακόμα να είναι υπογεγραμμένη από έναν λογαριασμό προγραμματιστή... ωστόσο, κατά την εγγραφή στο MDM η **συσκευή προσθέτει το πιστοποιητικό SSL του MDM ως έμπιστο CA**, οπότε τώρα μπορείτε να υπογράψετε οτιδήποτε.

Για να εγγράψετε τη συσκευή σε ένα MDM, πρέπει να εγκαταστήσετε ένα αρχείο **`mobileconfig`** ως ριζικός χρήστης, το οποίο θα μπορούσε να παραδοθεί μέσω ενός αρχείου **pkg** (μπορείτε να το συμπιέσετε σε zip και όταν το κατεβάσετε από το safari θα αποσυμπιέσεται).

Το **Mythic agent Orthrus** χρησιμοποιεί αυτήν την τεχνική.

### Κατάχρηση JAMF PRO

Το JAMF μπορεί να εκτελέσει **προσαρμοσμένα scripts** (scripts αναπτυγμένα από τον συστημικό διαχειριστή), **φορτία native** (δημιουργία τοπικών λογαριασμών, ορισμός κωδικού EFI, παρακολούθηση αρχείων/διεργασιών...) και **MDM** (διαμορφώσεις συσκευών, πιστοποιητικά συσκευών...).

#### Αυτο-εγγραφή JAMF

Πηγαίνετε σε μια σελίδα όπως `https://<company-name>.jamfcloud.com/enroll/` για να δείτε αν έχουν ενεργοποιημένη την **αυτό-εγγραφή**. Αν την έχουν, μπορεί **να ζητήσει διαπιστευτήρια για πρόσβαση**.

Μπορείτε να χρησιμοποιήσετε το script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) για να πραγματοποιήσετε επίθεση password spraying.

Επιπλέον, μετά την εύρεση κατάλληλων διαπιστευτηρίων μπορείτε να είστε σε θέση να κάνετε brute-force άλλα ονόματα χρηστών με την επόμενη φόρμα:

![](<../../.gitbook/assets/image (107).png>)

#### Ταυτοποίηση συσκευής JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Το **`jamf`** δυαδικό αρχείο περιείχε το μυστικό για να ανοίξει το keychain το οποίο την χρονική στιγμή της ανακάλυψης ήταν **κοινόχρηστο** μεταξύ όλων και ήταν: **`jk23ucnq91jfu9aj`**.\
Επιπλέον, το jamf **διατηρεί** ως **LaunchDaemon** στο **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Πάροχος συσκευής JAMF

Η **URL** του **JSS** (Jamf Software Server) που θα χρησιμοποιήσει το **`jamf`** βρίσκεται στο **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Αυτό το αρχείο περιέχει βασικά τη διεύθυνση URL:

{% code overflow="wrap" %}
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

Έτσι, ένας εισβολέας θα μπορούσε να αποθέσει ένα κακόβουλο πακέτο (`pkg`) που **αντικαθιστά αυτό το αρχείο** κατά την εγκατάσταση, ρυθμίζοντας το **URL σε ένα Mythic C2 listener από έναν πράκτορα Typhon** για να μπορεί τώρα να καταχραστεί το JAMF ως C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Παραποίηση JAMF

Για να **παρασιτήσετε την επικοινωνία** μεταξύ μιας συσκευής και του JMF χρειάζεστε:

* Το **UUID** της συσκευής: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Το **keychain του JAMF** από: `/Library/Application\ Support/Jamf/JAMF.keychain` το οποίο περιέχει το πιστοποιητικό της συσκευής

Με αυτές τις πληροφορίες, **δημιουργήστε ένα VM** με το **κλεμμένο** Hardware **UUID** και με το **SIP απενεργοποιημένο**, αφήστε το **JAMF keychain,** **συνδέστε** το Jamf **agent** και κλέψτε τις πληροφορίες του.

#### Κλοπή Μυστικών

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Μπορείτε επίσης να παρακολουθείτε την τοποθεσία `/Library/Application Support/Jamf/tmp/` για τα **προσαρμοσμένα scripts** που οι διαχειριστές ενδέχεται να θέλουν να εκτελέσουν μέσω του Jamf καθώς είναι **τοποθετημένα εδώ, εκτελούνται και αφαιρούνται**. Αυτά τα scripts **μπορεί να περιέχουν διαπιστευτήρια**.

Ωστόσο, τα **διαπιστευτήρια** μπορεί να περνούν μέσω αυτών των scripts ως **παράμετροι**, οπότε θα πρέπει να παρακολουθείτε την εντολή `ps aux | grep -i jamf` (χωρίς να είστε root).

Το script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) μπορεί να ακούει για νέα αρχεία που προστίθενται και νέες παραμέτρους διεργασιών.

### Απομακρυσμένη Πρόσβαση στο macOS

Και επίσης για τα "ειδικά" **πρωτόκολλα δικτύου** του **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Σε ορισμένες περιπτώσεις θα διαπιστώσετε ότι ο **υπολογιστής MacOS είναι συνδεδεμένος σε ένα AD**. Σε αυτό το σενάριο θα πρέπει να προσπαθήσετε να **απαριθμήσετε** το active directory όπως είστε συνηθισμένοι. Βρείτε κάποια **βοήθεια** στις παρακάτω σελίδες:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Ένα **τοπικό εργαλείο MacOS** που μπορεί να σας βοηθήσει είναι το `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Επίσης υπάρχουν μερικά εργαλεία που έχουν προετοιμαστεί για το MacOS για αυτόματη απαρίθμηση του AD και παιχνίδι με το kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): Το MacHound είναι μια επέκταση του εργαλείου ελέγχου Bloodhound που επιτρέπει τη συλλογή και την εισαγωγή σχέσεων Active Directory σε υπολογιστές MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Το Bifrost είναι ένα έργο Objective-C σχεδιασμένο για αλληλεπίδραση με τα APIs Heimdal krb5 στο macOS. Ο στόχος του έργου είναι να επιτρέψει καλύτερο έλεγχο ασφαλείας γύρω από το Kerberos σε συσκευές macOS χρησιμοποιώντας φυσικά APIs χωρίς την ανάγκη άλλου πλαισίου ή πακέτων στον στόχο.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Εργαλείο JavaScript για Automation (JXA) για απαρίθμηση Active Directory.
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Χρήστες

Οι τρεις τύποι χρηστών του MacOS είναι:

- **Τοπικοί Χρήστες** - Διαχειρίζονται από την τοπική υπηρεσία OpenDirectory, δεν συνδέονται με κανέναν τρόπο στο Active Directory.
- **Δίκτυα Χρήστες** - Ευάλωτοι χρήστες του Active Directory που απαιτούν σύνδεση με τον εξυπηρετητή DC για πιστοποίηση.
- **Κινητοί Χρήστες** - Χρήστες του Active Directory με τοπικό αντίγραφο ασφαλείας για τα διαπιστευτήριά τους και τα αρχεία τους.

Οι τοπικές πληροφορίες σχετικά με τους χρήστες και τις ομάδες αποθηκεύονται στον φάκελο _/var/db/dslocal/nodes/Default._\
Για παράδειγμα, οι πληροφορίες για τον χρήστη με το όνομα _mark_ αποθηκεύονται στο _/var/db/dslocal/nodes/Default/users/mark.plist_ και οι πληροφορίες για την ομάδα _admin_ βρίσκονται στο _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Εκτός από τη χρήση των ακμών HasSession και AdminTo, το **MacHound προσθέτει τρεις νέες ακμές** στη βάση δεδομένων Bloodhound:

- **CanSSH** - οντότητα που επιτρέπεται να συνδεθεί μέσω SSH στον υπολογιστή
- **CanVNC** - οντότητα που επιτρέπεται να συνδεθεί μέσω VNC στον υπολογιστή
- **CanAE** - οντότητα που επιτρέπεται να εκτελέσει scripts AppleEvent στον υπολογιστή
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

Το Keychain περιέχει πιθανότατα ευαίσθητες πληροφορίες που, αν προσπεραστούν η προκαλέσουν εναλλακτικά μια ειδοποίηση, μπορεί να βοηθήσουν στην προώθηση μιας άσκησης κόκκινης ομάδας:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Εξωτερικές Υπηρεσίες

Η Κόκκινη Ομάδα MacOS διαφέρει από μια κανονική Κόκκινη Ομάδα Windows καθώς συνήθως **η MacOS είναι ενσωματωμένη με αρκετές εξωτερικές πλατφόρμες απευθείας**. Μια συνηθισμένη ρύθμιση της MacOS είναι η πρόσβαση στον υπολογιστή χρησιμοποιώντας **συγχρονισμένα διαπιστευτήρια OneLogin και πρόσβαση σε διάφορες εξωτερικές υπηρεσίες** (όπως github, aws...) μέσω του OneLogin.

## Διάφορες Τεχνικές Κόκκινης Ομάδας

### Safari

Όταν ένα αρχείο κατεβάζεται στο Safari, αν είναι ένα "ασφαλές" αρχείο, θα **ανοίγεται αυτόματα**. Έτσι, για παράδειγμα, αν **κατεβάσετε ένα zip**, θα αποσυμπιέζεται αυτόματα:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
