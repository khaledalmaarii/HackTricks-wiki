# SPI

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

SPI (Serial Peripheral Interface) είναι ένα Πρωτόκολλο Σύνθετης Σειριακής Επικοινωνίας που χρησιμοποιείται σε ενσωματωμένα συστήματα για σύντομες αποστάσεις επικοινωνίας μεταξύ ICs (Ενσωματωμένων Κυκλωμάτων). Το Πρωτόκολλο Επικοινωνίας SPI χρησιμοποιεί την αρχιτεκτονική master-slave, η οποία ελέγχεται από το Ρολόι και το Σήμα Επιλογής Chip. Μια αρχιτεκτονική master-slave αποτελείται από έναν master (συνήθως έναν μικροεπεξεργαστή) που διαχειρίζεται εξωτερικές περιφερειακές συσκευές όπως EEPROM, αισθητήρες, συσκευές ελέγχου κ.λπ., οι οποίες θεωρούνται ως slaves.

Πολλοί slaves μπορούν να συνδεθούν σε έναν master, αλλά οι slaves δεν μπορούν να επικοινωνούν μεταξύ τους. Οι slaves ελέγχονται από δύο ακίδες, το ρολόι και την επιλογή chip. Καθώς το SPI είναι ένα πρωτόκολλο συγχρονισμένης επικοινωνίας, οι ακίδες εισόδου και εξόδου ακολουθούν τα σήματα ρολογιού. Η επιλογή chip χρησιμοποιείται από τον master για να επιλέξει έναν slave και να αλληλεπιδράσει μαζί του. Όταν η επιλογή chip είναι υψηλή, η συσκευή slave δεν είναι επιλεγμένη, ενώ όταν είναι χαμηλή, το chip έχει επιλεγεί και ο master θα αλληλεπιδράσει με τον slave.

Οι MOSI (Master Out, Slave In) και MISO (Master In, Slave Out) είναι υπεύθυνες για την αποστολή και λήψη δεδομένων. Τα δεδομένα αποστέλλονται στη συσκευή slave μέσω της ακίδας MOSI ενώ η επιλογή chip διατηρείται χαμηλή. Τα δεδομένα εισόδου περιέχουν οδηγίες, διευθύνσεις μνήμης ή δεδομένα σύμφωνα με το φύλλο δεδομένων του προμηθευτή της συσκευής slave. Μετά από μια έγκυρη είσοδο, η ακίδα MISO είναι υπεύθυνη για τη μετάδοση δεδομένων στον master. Τα δεδομένα εξόδου αποστέλλονται ακριβώς στον επόμενο κύκλο ρολογιού μετά την ολοκλήρωση της εισόδου. Οι ακίδες MISO μεταδίδουν δεδομένα μέχρι να ολοκληρωθεί η μετάδοση ή ο master να θέσει την ακίδα επιλογής chip υψηλή (σε αυτή την περίπτωση, ο slave θα σταματήσει τη μετάδοση και ο master δεν θα ακούσει μετά από αυτόν τον κύκλο ρολογιού).

## Dumping Firmware from EEPROMs

Η εξαγωγή firmware μπορεί να είναι χρήσιμη για την ανάλυση του firmware και την εύρεση ευπαθειών σε αυτό. Συχνά, το firmware δεν είναι διαθέσιμο στο διαδίκτυο ή είναι άσχετο λόγω παραλλαγών παραγόντων όπως ο αριθμός μοντέλου, η έκδοση κ.λπ. Επομένως, η εξαγωγή του firmware απευθείας από τη φυσική συσκευή μπορεί να είναι χρήσιμη για να είμαστε συγκεκριμένοι κατά την αναζήτηση απειλών.

Η απόκτηση Σειριακής Κονσόλας μπορεί να είναι χρήσιμη, αλλά συχνά συμβαίνει ότι τα αρχεία είναι μόνο για ανάγνωση. Αυτό περιορίζει την ανάλυση για διάφορους λόγους. Για παράδειγμα, εργαλεία που απαιτούνται για την αποστολή και λήψη πακέτων δεν θα υπάρχουν στο firmware. Έτσι, η εξαγωγή των δυαδικών αρχείων για αντίστροφη μηχανική δεν είναι εφικτή. Επομένως, η ύπαρξη ολόκληρου του firmware αποθηκευμένου στο σύστημα και η εξαγωγή των δυαδικών αρχείων για ανάλυση μπορεί να είναι πολύ χρήσιμη.

Επίσης, κατά τη διάρκεια της red teaming και της φυσικής πρόσβασης σε συσκευές, η εξαγωγή του firmware μπορεί να βοηθήσει στην τροποποίηση των αρχείων ή στην εισαγωγή κακόβουλων αρχείων και στη συνέχεια στην επαναφόρτωσή τους στη μνήμη, κάτι που θα μπορούσε να είναι χρήσιμο για την εμφύτευση ενός backdoor στη συσκευή. Επομένως, υπάρχουν πολλές δυνατότητες που μπορούν να ξεκλειδωθούν με την εξαγωγή firmware.

### CH341A EEPROM Programmer and Reader

Αυτή η συσκευή είναι ένα οικονομικό εργαλείο για την εξαγωγή firmwares από EEPROMs και επίσης για την επαναφόρτωσή τους με αρχεία firmware. Έχει γίνει δημοφιλής επιλογή για εργασία με τσιπ BIOS υπολογιστών (τα οποία είναι απλώς EEPROMs). Αυτή η συσκευή συνδέεται μέσω USB και χρειάζεται ελάχιστα εργαλεία για να ξεκινήσει. Επίσης, συνήθως ολοκληρώνει την εργασία γρήγορα, οπότε μπορεί να είναι χρήσιμη και για φυσική πρόσβαση σε συσκευές.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Συνδέστε τη μνήμη EEPROM με τον Προγραμματιστή CH341a και συνδέστε τη συσκευή στον υπολογιστή. Σε περίπτωση που η συσκευή δεν ανιχνεύεται, δοκιμάστε να εγκαταστήσετε τους οδηγούς στον υπολογιστή. Επίσης, βεβαιωθείτε ότι η EEPROM είναι συνδεδεμένη στη σωστή κατεύθυνση (συνήθως, τοποθετήστε την ακίδα VCC σε αντίστροφη κατεύθυνση από τον συνδετήρα USB) αλλιώς, το λογισμικό δεν θα μπορεί να ανιχνεύσει το chip. Ανατρέξτε στο διάγραμμα αν χρειαστεί:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Τέλος, χρησιμοποιήστε λογισμικά όπως το flashrom, G-Flash (GUI), κ.λπ. για την εξαγωγή του firmware. Το G-Flash είναι ένα ελάχιστο εργαλείο GUI που είναι γρήγορο και ανιχνεύει αυτόματα την EEPROM. Αυτό μπορεί να είναι χρήσιμο αν το firmware πρέπει να εξαχθεί γρήγορα, χωρίς πολλές τροποποιήσεις στην τεκμηρίωση.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Μετά την εξαγωγή του firmware, η ανάλυση μπορεί να γίνει στα δυαδικά αρχεία. Εργαλεία όπως τα strings, hexdump, xxd, binwalk, κ.λπ. μπορούν να χρησιμοποιηθούν για την εξαγωγή πολλών πληροφοριών σχετικά με το firmware καθώς και ολόκληρο το σύστημα αρχείων.

Για να εξάγετε τα περιεχόμενα από το firmware, μπορεί να χρησιμοποιηθεί το binwalk. Το Binwalk αναλύει για υπογραφές hex και αναγνωρίζει τα αρχεία στο δυαδικό αρχείο και είναι ικανό να τα εξάγει.
```
binwalk -e <filename>
```
Το μπορεί να είναι .bin ή .rom ανάλογα με τα εργαλεία και τις ρυθμίσεις που χρησιμοποιούνται.

{% hint style="danger" %}
Σημειώστε ότι η εξαγωγή firmware είναι μια λεπτή διαδικασία και απαιτεί πολλή υπομονή. Οποιαδήποτε κακή διαχείριση μπορεί να διαφθείρει το firmware ή ακόμη και να το διαγράψει εντελώς και να καταστήσει τη συσκευή μη λειτουργική. Συνιστάται να μελετήσετε τη συγκεκριμένη συσκευή πριν προσπαθήσετε να εξαγάγετε το firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Σημειώστε ότι ακόμη και αν το PINOUT του Pirate Bus υποδεικνύει ακίδες για **MOSI** και **MISO** για σύνδεση με SPI, ωστόσο μερικά SPIs μπορεί να υποδεικνύουν ακίδες ως DI και DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Σε Windows ή Linux μπορείτε να χρησιμοποιήσετε το πρόγραμμα [**`flashrom`**](https://www.flashrom.org/Flashrom) για να αποθηκεύσετε το περιεχόμενο της μνήμης flash εκτελώντας κάτι σαν:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στο** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) ή στο [**telegram group**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
