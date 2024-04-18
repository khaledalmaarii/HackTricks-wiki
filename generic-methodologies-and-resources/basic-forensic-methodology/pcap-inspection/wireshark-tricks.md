# Κόλπα Wireshark

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο βασικός στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κλοπή πληροφοριών.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

## Βελτιώστε τις δεξιότητές σας στο Wireshark

### Οδηγοί

Οι ακόλουθοι οδηγοί είναι εκπληκτικοί για να μάθετε μερικά ψυχαγωγικά βασικά κόλπα:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Αναλυμένες Πληροφορίες

**Ειδικές Πληροφορίες**

Κάνοντας κλικ σε _**Ανάλυση** --> **Ειδικές Πληροφορίες**_ θα έχετε μια **επισκόπηση** του τι συμβαίνει στα **αναλυμένα** πακέτα:

![](<../../../.gitbook/assets/image (253).png>)

**Επιλυμένες Διευθύνσεις**

Κάτω από _**Στατιστικά --> Επιλυμένες Διευθύνσεις**_ μπορείτε να βρείτε πολλές **πληροφορίες** που έχουν "**επιλυθεί**" από το wireshark όπως θύρα/μεταφορά σε πρωτόκολλο, MAC στον κατασκευαστή, κλπ. Είναι ενδιαφέρον να γνωρίζετε τι εμπλέκεται στην επικοινωνία.

![](<../../../.gitbook/assets/image (890).png>)

**Ιεραρχία Πρωτοκόλλου**

Κάτω από _**Στατιστικά --> Ιεραρχία Πρωτοκόλλου**_ μπορείτε να βρείτε τα **πρωτόκολλα** που **εμπλέκονται** στην επικοινωνία και δεδομένα σχετικά με αυτά.

![](<../../../.gitbook/assets/image (583).png>)

**Συνομιλίες**

Κάτω από _**Στατιστικά --> Συνομιλίες**_ μπορείτε να βρείτε ένα **σύνολο των συνομιλιών** στην επικοινωνία και δεδομένα σχετικά με αυτές.

![](<../../../.gitbook/assets/image (450).png>)

**Ακραίες Σημεία**

Κάτω από _**Στατιστικά --> Ακραία Σημεία**_ μπορείτε να βρείτε ένα **σύνολο των ακραίων σημείων** στην επικοινωνία και δεδομένα για καθένα από αυτά.

![](<../../../.gitbook/assets/image (893).png>)

**Πληροφορίες DNS**

Κάτω από _**Στατιστικά --> DNS**_ μπορείτε να βρείτε στατιστικά σχετικά με τα καταγεγραμμένα αιτήματα DNS.

![](<../../../.gitbook/assets/image (1060).png>)

**Γράφημα I/O**

Κάτω από _**Στατιστικά --> Γράφημα I/O**_ μπορείτε να βρείτε ένα **γράφημα της επικοινωνίας.**

![](<../../../.gitbook/assets/image (989).png>)

### Φίλτρα

Εδώ μπορείτε να βρείτε φίλτρα wireshark ανάλογα με το πρωτόκολλο: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Άλλα ενδιαφέροντα φίλτρα:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Κίνηση HTTP και αρχική κίνηση HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Κίνηση HTTP και αρχική κίνηση HTTPS + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Κίνηση HTTP και αρχική κίνηση HTTPS + TCP SYN + αιτήσεις DNS

### Αναζήτηση

Αν θέλετε να **αναζητήσετε** **περιεχόμενο** μέσα στα **πακέτα** των συνεδριών πατήστε _CTRL+f_. Μπορείτε να προσθέσετε νέα επίπεδα στην κύρια γραμμή πληροφοριών (Αρ., Χρόνος, Πηγή, κλπ.) πατώντας το δεξί κουμπί και στη συνέχεια την επεξεργασία στήλης.

### Δωρεάν εργαστήρια pcap

**Εξάσκηση με τις δωρεάν προκλήσεις του:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Αναγνώριση Domain

Μπορείτε να προσθέσετε μια στήλη που εμφανίζει τον Κεφαλίδα Κεφαλίδας HTTP:

![](<../../../.gitbook/assets/image (635).png>)

Και μια στήλη που προσθέτει το όνομα Διακομιστή από μια αρχική σύνδεση HTTPS (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Αναγνώριση τοπικών ονομάτων υπολογιστή

### Από DHCP

Στο τρέχον Wireshark αντί για `bootp` πρέπει να αναζητήσετε το `DHCP`

![](<../../../.gitbook/assets/image (1010).png>)

### Από NBNS

![](<../../../.gitbook/assets/image (1000).png>)

## Αποκρυπτογράφηση TLS

### Αποκρυπτογράφηση κίνησης https με ιδιωτικό κλειδί διακομιστή

_επεξεργασία>προτίμηση>πρωτόκολλο>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

Πατήστε _Επεξεργασία_ και προσθέστε όλα τα δεδομένα του διακομιστή και το ιδιωτικό κλειδί (_IP, Θύρα, Πρωτόκολλο, Αρχείο κλειδιού και κωδικό πρόσβασης_)

### Αποκρυπτογράφηση κίνησης https με συμμετρικά κλειδιά συνεδρίας

Τόσο ο Firefox όσο και ο Chrome έχουν τη δυνατότητα να καταγράφουν τα κλειδιά συνεδρίας TLS, τα οποία μπορούν να χρησιμοποιηθούν με το Wireshark για την αποκρυπτογράφηση της κίνησης TLS. Αυτό επιτρέπει την ανάλυση των ασφαλών επικοινωνιών. Περισσότερες λεπτομέρειες για το πώς να εκτελέσετε αυτήν την αποκρυπτογράφηση μπορείτε να βρείτε σε οδηγό στο [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Για να ανιχνεύσετε αυτό αναζητήστε μέ
## ADB επικοινωνία

Εξαγωγή ενός APK από μια ADB επικοινωνία όπου το APK στάλθηκε:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι ένας μηχανισμός αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει δωρεάν λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τον μηχανισμό τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
