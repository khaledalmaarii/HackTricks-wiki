{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε τεχνικές χάκερ καταθέτοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>
{% endhint %}

# Έλεγχος BSSIDs

Όταν λάβετε ένα αρχείο καταγραφής του οποίου η κύρια κίνηση είναι Wifi χρησιμοποιώντας το WireShark μπορείτε να αρχίσετε την έρευνα όλων των SSIDs της καταγραφής με _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Επίθεση Brute Force

Ένα από τα πεδία αυτής της οθόνης υποδεικνύει εάν **βρέθηκε κάποια ταυτοποίηση μέσα στο αρχείο καταγραφής**. Αν αυτό ισχύει, μπορείτε να δοκιμάσετε να το αποκρυπτογραφήσετε χρησιμοποιώντας το `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Για παράδειγμα, θα ανακτήσει τον κωδικό πρόσβασης WPA που προστατεύει ένα PSK (κοινόχρηστο κλειδί), ο οποίος θα απαιτηθεί για να αποκρυπτογραφήσετε την κίνηση αργότερα.

# Δεδομένα στα Beacons / Πλευρικό Κανάλι

Εάν υποψιάζεστε ότι **δεδομένα διαρρέουν μέσα στα beacons ενός δικτύου Wifi** μπορείτε να ελέγξετε τα beacons του δικτύου χρησιμοποιώντας ένα φίλτρο όπως το εξής: `wlan contains <ΟΝΟΜΑτουΔΙΚΤΥΟΥ>`, ή `wlan.ssid == "ΟΝΟΜΑτουΔΙΚΤΥΟΥ"` αναζητήστε μέσα στα φιλτραρισμένα πακέτα για ύποπτες συμβολοσειρές.

# Εύρεση Άγνωστων Διευθύνσεων MAC σε Ένα Δίκτυο Wifi

Ο παρακάτω σύνδεσμος θα είναι χρήσιμος για να βρείτε τις **συσκευές που στέλνουν δεδομένα μέσα σε ένα Δίκτυο Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Εάν γνωρίζετε ήδη **διευθύνσεις MAC** μπορείτε να τις αφαιρέσετε από την έξοδο προσθέτοντας ελέγχους όπως αυτόν: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Αφού ανιχνεύσετε **άγνωστες διευθύνσεις MAC** που επικοινωνούν μέσα στο δίκτυο μπορείτε να χρησιμοποιήσετε **φίλτρα** όπως το ακόλουθο: `wlan.addr==<Διεύθυνση MAC> && (ftp || http || ssh || telnet)` για να φιλτράρετε την κίνησή τους. Σημειώστε ότι τα φίλτρα ftp/http/ssh/telnet είναι χρήσιμα εάν έχετε αποκρυπτογραφήσει την κίνηση.

# Αποκρυπτογράφηση Κίνησης

Επεξεργασία --> Προτιμήσεις --> Πρωτόκολλα --> IEEE 802.11--> Επεξεργασία

![](<../../../.gitbook/assets/image (426).png>)
```
