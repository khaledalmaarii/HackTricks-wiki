# Ασφάλεια & Ανόδος Προνομίων στο macOS

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στο [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server για επικοινωνία με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Hacking**\
Ασχοληθείτε με περιεχόμενο που εξετάζει την αγωνία και τις προκλήσεις του hacking

**Ειδήσεις Hacking σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο κόσμο του hacking μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενήμεροι με τις νεότερες ανταμοιβές ευρημάτων και τις κρίσιμες ενημερώσεις πλατφόρμας

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε τη συνεργασία με κορυφαίους χάκερ σήμερα!

## Βασικά για το macOS

Αν δεν είστε εξοικειωμένοι με το macOS, θα πρέπει να αρχίσετε να μάθετε τα βασικά του macOS:

* Ειδικά αρχεία & δικαιώματα του macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Συνηθισμένοι χρήστες του macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Η **αρχιτεκτονική** του πυρήνα

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Συνηθισμένες υπηρεσίες & πρωτόκολλα δικτύου του macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Για να κατεβάσετε ένα `tar.gz` αλλάξτε ένα URL όπως [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) σε [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### Διαχείριση Συστημάτων macOS MDM

Στις εταιρείες τα συστήματα **macOS** είναι πιθανόν να διαχειρίζονται με ένα MDM. Επομένως, από την άποψη ενός επιτιθέμενου είναι ενδιαφέρον να γνωρίζει **πώς λειτουργεί αυτό**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### macOS - Επιθεώρηση, Αποσφαλμάτωση και Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Προστασίες Ασφαλείας του macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Επιφάνεια Επίθεσης

### Δικαιώματα Αρχείων

Αν ένα **διεργασία που τρέχει ως ριζοχρήστης γράφει** ένα αρχείο που μπορεί να ελεγχθεί από έναν χρήστη, ο χρήστης μπορεί να εκμεταλλευτεί αυτό για **ανόδο προνομίων**.\
Αυτό μπορεί να συμβεί στις ακόλουθες καταστάσεις:

* Το αρχείο που χρησιμοποιήθηκε είχε ήδη δημιουργηθεί από έναν χρήστη (ανήκε στον χρήστη)
* Το αρχείο που χρησιμοποιήθηκε είναι εγγράψιμο από τον χρήστη λόγω ενός γκρουπ
* Το αρχείο που χρησιμοποιήθηκε βρίσκεται μέσα σε έναν κατάλογο που ανήκει στον χρήστη (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)
* Το αρχείο που χρησιμοποιήθηκε βρίσκεται μέσα σε έναν κατάλογο που ανήκει στο ριζοχρήστη αλλά ο χρήστης έχει δικαίωμα εγγραφής επάνω του λόγω ενός γκρουπ (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)

Το να μπορεί κάποιος **να δημιουργήσει ένα αρχείο** που θα **χρησιμοποιηθεί από τον ριζοχρήστη**, επιτρέπει σε έναν χρήστη να **εκμεταλλευτεί το περιεχόμενό του** ή ακόμη να δημιουργήσει **συμβολικούς συνδέσμους/σκληρούς συνδέσμους** για να τον κατευθύνει σε άλλο μέρος.

Για αυτού του είδους τις ευπάθειες μην ξεχνάτε να **ελέγχετε ευάλωτους εγκαταστάτες `.pkg`**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Επέκταση Αρχείου & Χειριστές εφαρμογών σχήματος URL

Παράξενες εφαρμογές που έχουν καταχωρηθεί από επεκτάσεις αρχείων μπορούν να εκμεταλλευτούνται και διαφορετικές εφαρμογές μπορούν να καταχωρηθούν για να ανοίγουν συγκεκριμένα πρωτόκολλα

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Ανόδος Προνομίων TCC / SIP στο macOS

Στο macOS **εφαρμογές και δυαδικά αρχεία μπορούν να έχουν δικαιώματα** πρόσβασης σε φακέλους ή ρυθμίσεις που τα καθιστούν πιο προνομιούχα από άλλα.

Επομένως, ένας επιτιθέμενος που θέλει να διακινδυνεύσει με επιτυχία ένα μηχάνημα macOS θα πρέπει να **αναβαθμίσει τα προνόμιά του στο TCC** (ή ακόμη και **να παρακάμψει το SIP**, ανάλογα με τις ανάγκες του).

Αυτά τα προνόμια συνήθως δίνονται στη μορφή **δικαιωμάτων** με τα οποία η εφαρμογή είναι υπογεγραμμένη, ή η εφαρμογή μπορεί να ζητήσει κάποιες προσβάσεις και μετά την **έγκριση του χρήστη** μπορούν να βρεθούν στις **βάσεις δεδομένων TCC**. Ένας άλλος τρόπος με τον οποίο μια διαδικασία μπορεί να αποκτήσει αυτά τα προνόμια είναι να είναι **παιδί μιας διαδικασίας** με αυτά τα **προνόμια**, καθώς συνήθως **κληρονομούνται**.

Ακολουθήστε αυτούς τους συνδέσμους για να βρείτε διαφορετικούς τρόπους για [**ανόδο προνομίων στο TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), για [**παράκαμψη του TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) και πώς στο παρελθόν [**έχει παρακαμφθεί το SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Κλασική
## Αναφορές

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) διακομιστή για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Hacking**\
Ασχοληθείτε με περιεχόμενο που εξερευνά την αγωνία και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενήμεροι με τον γρήγορο κόσμο του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενήμεροι με τις νεότερες ανακοινώσεις για νέες αμοιβές ευρετηρίων και κρίσιμες ενημερώσεις πλατφόρμας

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε τη συνεργασία με κορυφαίους χάκερ σήμερα!

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην ομάδα [**Discord**](https://discord.gg/hRep4RUj7f) ή στην ομάδα [**telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε χάκινγκ κόλπα υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
