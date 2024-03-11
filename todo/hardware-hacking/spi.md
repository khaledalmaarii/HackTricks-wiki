<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Βασικές Πληροφορίες

Το SPI (Serial Peripheral Interface) είναι ένα Πρωτόκολλο Σειριακής Περιφερειακής Επικοινωνίας που χρησιμοποιείται σε ενσωματωμένα συστήματα για την επικοινωνία σε μικρές αποστάσεις μεταξύ ολοκληρωμένων κυκλωμάτων (ICs). Το Πρωτόκολλο Επικοινωνίας SPI χρησιμοποιεί την αρχιτεκτονική αφεντικού-υπηρέτη που οργανώνεται από το Σήμα Ρολογιού και την Επιλογή Τσιπ. Η αρχιτεκτονική αφεντικού-υπηρέτη αποτελείται από έναν αφεντικό (συνήθως ένα μικροεπεξεργαστή) που διαχειρίζεται εξωτερικές περιφερειακές συσκευές όπως EEPROM, αισθητήρες, συσκευές ελέγχου, κ.λπ. που θεωρούνται υπηρέτες.

Πολλοί υπηρέτες μπορούν να συνδεθούν σε έναν αφεντικό, αλλά οι υπηρέτες δεν μπορούν να επικοινωνήσουν μεταξύ τους. Οι υπηρέτες διοικούνται από δύο ακίδες, το ρολόι και την επιλογή τσιπ. Καθώς το SPI είναι ένα συγχρονισμένο πρωτόκολλο επικοινωνίας, οι ακίδες εισόδου και εξόδου ακολουθούν τα σήματα του ρολογιού. Η επιλογή τσιπ χρησιμοποιείται από τον αφεντικό για να επιλέξει έναν υπηρέτη και να αλληλεπιδράσει μαζί του. Όταν η επιλογή τσιπ είναι υψηλή, η συσκευή υπηρέτης δεν επιλέγεται, ενώ όταν είναι χαμηλή, το τσιπ έχει επιλεγεί και ο αφεντικός θα αλληλεπιδρά με τον υπηρέτη.

Οι MOSI (Master Out, Slave In) και MISO (Master In, Slave Out) είναι υπεύθυνες για την αποστολή και λήψη δεδομένων. Τα δεδομένα στέλνονται στη συσκευή υπηρέτη μέσω της ακίδας MOSI ενώ η επιλογή τσιπ κρατείται χαμηλή. Τα δεδομένα εισόδου περιέχουν οδηγίες, διευθύνσεις μνήμης ή δεδομένα σύμφωνα με το φυλλάδιο του προμηθευτή της συσκευής υπηρέτη. Μετά από μια έγκυρη είσοδο, η ακίδα MISO είναι υπεύθυνη για τη μετάδοση δεδομένων στον αφεντικό. Τα δεδομένα εξόδου στέλνονται ακριβώς στον επόμενο κύκλο ρολογιού μετά το τέλος της εισόδου. Οι ακίδες MISO μεταδίδουν δεδομένα μέχρι την πλήρη μετάδοση των δεδομένων ή μέχρι ο αφεντικός να ορίσει την ακίδα επιλογής τσιπ υψηλή (σε αυτήν την περίπτωση, ο υπηρέτης θα σταματήσει τη μετάδοση και ο αφεντικός δεν θα ακούει μετά από αυτόν τον κύκλο ρολογιού).

# Αποθήκευση Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Σημείωση ότι ακόμα και αν το PINOUT του Pirate Bus υποδεικνύει ακίδες για **MOSI** και **MISO** για σύνδεση στο SPI, ορισμένα SPI μπορεί να υποδεικνύουν ακίδες ως DI και DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

Σε Windows ή Linux μπορείτε να χρησιμοποιήσετε το πρόγραμμα [**`flashrom`**](https://www.flashrom.org/Flashrom) για να αποθηκεύσετε το περιεχόμενο της μνήμης flash εκτελώντας κάτι παρόμοιο με:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
