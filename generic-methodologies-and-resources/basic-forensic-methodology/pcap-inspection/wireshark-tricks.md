# Κόλπα Wireshark

## Κόλπα Wireshark

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βελτιώστε τις δεξιότητες σας στο Wireshark

### Οδηγοί

Οι παρακάτω οδηγοί είναι εκπληκτικοί για να μάθετε μερικά ψυχαγωγικά βασικά κόλπα:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Αναλυμένες πληροφορίες

**Ειδικές πληροφορίες**

Κάνοντας κλικ στο _**Ανάλυση** --> **Ειδικές πληροφορίες**_ θα έχετε μια **επισκόπηση** του τι συμβαίνει στα αναλυμένα πακέτα:

![](<../../../.gitbook/assets/image (570).png>)

**Επιλυμένες διευθύνσεις**

Στο _**Στατιστικά --> Επιλυμένες διευθύνσεις**_ μπορείτε να βρείτε πολλές πληροφορίες που έχουν "**επιλυθεί**" από το wireshark, όπως θύρα/μεταφορά σε πρωτόκολλο, MAC στον κατασκευαστή, κλπ. Είναι ενδιαφέρον να γνωρίζετε τι εμπλέκεται στην επικοινωνία.

![](<../../../.gitbook/assets/image (571).png>)

**Ιεραρχία πρωτοκόλλων**

Στο _**Στατιστικά --> Ιεραρχία πρωτοκόλλων**_ μπορείτε να βρείτε τα **πρωτόκολλα** που εμπλέκονται στην επικοινωνία και πληροφορίες για αυτά.

![](<../../../.gitbook/assets/image (572).png>)

**Συνομιλίες**

Στο _**Στατιστικά --> Συνομιλίες**_ μπορείτε να βρείτε ένα **σύνολο πληροφοριών για τις συνομιλίες** στην επικοινωνία και πληροφορίες για αυτές.

![](<../../../.gitbook/assets/image (573).png>)

**Σημεία άφιξης**

Στο _**Στατιστικά --> Σημεία άφιξης**_ μπορείτε να βρείτε ένα **σύνολο πληροφοριών για τα σημεία άφιξης** στην επικοινωνία και πληροφορίες για καθένα από αυτά.

![](<../../../.gitbook/assets/image (575).png>)

**Πληροφορίες DNS**

Στο _**Στατιστικά --> DNS**_ μπορείτε να βρείτε στατιστικά σχετικά με τα καταγεγραμμένα αιτήματα DNS.

![](<../../../.gitbook/assets/image (577).png>)

**Διάγραμμα I/O**

Στο _**Στατιστικά --> Διάγραμμα I/O**_ μπορείτε να βρείτε ένα **διάγραμμα της επικοινωνίας**.

![](<../../../.gitbook/assets/image (574).png>)

### Φίλτρα

Εδώ μπορείτε να βρείτε φίλτρα wireshark ανάλογα με το πρωτόκολλο: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Άλλα ενδιαφέροντα φίλτρα:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Κίνηση HTTP και αρχική κίνηση HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Κίνηση HTTP και αρχική κίνηση HTTPS + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and
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
<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
