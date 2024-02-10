<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Έλεγχος BSSIDs

Όταν λάβετε ένα αρχείο καταγραφής του οποίου η κύρια κίνηση είναι Wifi χρησιμοποιώντας το WireShark, μπορείτε να αρχίσετε να ερευνάτε όλα τα SSID της καταγραφής με το _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Βίαιη Δύναμη

Ένας από τους στήλες αυτής της οθόνης υποδεικνύει εάν **βρέθηκε οποιαδήποτε πιστοποίηση μέσα στο pcap**. Εάν αυτό είναι το περιστατικό, μπορείτε να δοκιμάσετε να το βρείτε με βίαιη δύναμη χρησιμοποιώντας το `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Για παράδειγμα, θα ανακτήσει τον κωδικό πρόσβασης WPA που προστατεύει ένα PSK (pre shared-key), ο οποίος θα απαιτηθεί αργότερα για την αποκρυπτογράφηση της κίνησης.

# Δεδομένα στα Beacons / Side Channel

Εάν υποψιάζεστε ότι **δεδομένα διαρρέουν μέσα στα beacons ενός δικτύου Wifi**, μπορείτε να ελέγξετε τα beacons του δικτύου χρησιμοποιώντας ένα φίλτρο όπως το εξής: `wlan contains <ΟΝΟΜΑτουΔΙΚΤΥΟΥ>`, ή `wlan.ssid == "ΟΝΟΜΑτουΔΙΚΤΥΟΥ"` αναζήτηση μέσα στα φιλτραρισμένα πακέτα για ύποπτες αλφαριθμητικές ακολουθίες.

# Εύρεση Άγνωστων Διευθύνσεων MAC σε Ένα Δίκτυο Wifi

Ο παρακάτω σύνδεσμος θα είναι χρήσιμος για να βρείτε τις **μηχανές που αποστέλλουν δεδομένα μέσα σε ένα δίκτυο Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Εάν ήδη γνωρίζετε **διευθύνσεις MAC, μπορείτε να τις αφαιρέσετε από την έξοδο** προσθέτοντας ελέγχους όπως αυτός: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Αφού ανιχνεύσετε **άγνωστες διευθύνσεις MAC** που επικοινωνούν μέσα στο δίκτυο, μπορείτε να χρησιμοποιήσετε **φίλτρα** όπως το εξής: `wlan.addr==<διεύθυνση MAC> && (ftp || http || ssh || telnet)` για να φιλτράρετε την κίνησή τους. Σημειώστε ότι τα φίλτρα ftp/http/ssh/telnet είναι χρήσιμα εάν έχετε αποκρυπτογραφήσει την κίνηση.

# Αποκρυπτογράφηση Κίνησης

Επεξεργασία --> Προτιμήσεις --> Πρωτόκολλα --> IEEE 802.11--> Επεξεργασία

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
