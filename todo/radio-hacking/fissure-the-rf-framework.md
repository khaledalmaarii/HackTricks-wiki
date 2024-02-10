# FISSURE - Το RF Framework

**Ανεξάρτητη συχνότητα βασισμένη σε SDR κατανόηση σήματος και αντίστροφη μηχανική**

Το FISSURE είναι ένα ανοικτού κώδικα RF και αντίστροφο μηχανικής framework σχεδιασμένο για όλα τα επίπεδα δεξιοτήτων με hooks για ανίχνευση και ταξινόμηση σήματος, ανακάλυψη πρωτοκόλλου, εκτέλεση επιθέσεων, διαχείριση IQ, ανάλυση ευπαθειών, αυτοματισμό και AI/ML. Το framework κατασκευάστηκε για να προωθήσει την γρήγορη ενσωμάτωση λογισμικών ενοτήτων, ραδιοφώνων, πρωτοκόλλων, δεδομένων σήματος, σεναρίων, ροών, αναφορικού υλικού και εργαλείων τρίτων. Το FISSURE είναι ένα εργαλείο που επιτρέπει τη ροή εργασίας και επιτρέπει στις ομάδες να εξοικειωθούν εύκολα, μοιράζοντας την ίδια αποδεδειγμένη βασική διαμόρφωση για συγκεκριμένες διανομές Linux.

Το framework και τα εργαλεία που περιλαμβάνονται στο FISSURE σχεδιάστηκαν για να ανιχνεύουν την παρουσία ενέργειας RF, να κατανοούν τα χαρακτηριστικά ενός σήματος, να συλλέγουν και να αναλύουν δείγματα, να αναπτύσσουν τεχνικές μετάδοσης και/ή εισαγωγής και να δημιουργούν προσαρμοσμένα φορτία ή μηνύματα. Το FISSURE περιέχει μια αυξανόμενη βιβλιοθήκη πληροφοριών πρωτοκόλλου και σήματος για να βοηθήσει στην αναγνώριση, τη δημιουργία πακέτων και το fuzzing. Υπάρχουν δυνατότητες αρχειοθέτησης σε απευθείας σύνδεση για να κατεβάσετε αρχεία σήματος και να δημιουργήσετε λίστες αναπαραγωγής για να προσομοιώσετε την κίνηση και να δοκιμάσετε συστήματα.

Ο φιλικός κώδικας Python και η διεπαφή χρήστη επιτρέπουν στους αρχάριους να μάθουν γρήγορα για δημοφιλή εργαλεία και τεχνικές που αφορούν το RF και την αντίστροφη μηχανική. Οι εκπαιδευτές στην κυβερνοασφάλεια και τη μηχανική μπορούν να εκμεταλλευτούν το ενσωματωμένο υλικό ή να χρησιμοποιήσουν το framework για να επιδείξουν τις δικές τους εφαρμογές στον πραγματικό κόσμο. Οι προγραμματιστές και οι ερευνητές μπορούν να χρησιμοποιήσουν το FISSURE για τις καθημερινές τους εργασίες ή για να αποκαλύψουν τις πρωτοποριακές λύσεις τους σε ένα ευρύτερο κοινό. Καθώς η ευαισθητοποίηση και η χρήση του FISSURE αυξάνονται στην κοινότητα, τόσο θα αυξηθεί η ικανότητά του όσο και η ευρύτητα της τεχνολογίας που περιλαμβάνει.

**Πρόσθετες Πληροφορίες**

* [Σελίδα AIS](https://www.ainfosec.com/technologies/fissure/)
* [Διαφάνειες GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Άρθρο GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Βίντεο GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Μεταγραφή Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Ξεκινώντας

**Υποστηριζόμενα**

Υπάρχουν τρεις κλαδιά μέσα στο FISSURE για να διευκολυνθεί η πλοήγηση στα αρχεία και να μειωθεί η επανάληψη του κώδικα. Ο κλάδος Python2\_maint-3.7 περιέχει έναν κώδικα που βασίζεται στην Python2, PyQt4 και GNU Radio 3.7. Ο κλάδος Python3\_maint-3.8 βασίζεται στην Python3, PyQt5 και GNU Radio 3.8. Ο κλάδος Python3\_maint-3.10 βασίζεται στην Python3, PyQt5 και GNU Radio 3.10.

|   Λειτουργικό Σύστημα   |   Κλάδος FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Σε εξέλιξη (beta)**

Αυτά τα λειτουργικά συστήματα είναι ακόμα σε κατάσταση beta. Βρίσκονται υπό ανάπτυξη και γνωρίζεται ότι λείπουν αρκετά χαρακτηριστικά. Τα αντικείμενα στον εγκαταστάτη μπορεί να συγκρούονται με υπάρχοντα προγράμματα ή να αποτύχουν να εγκατασταθούν μέχρι να αφαιρεθεί η κατάσταση.

|     Λειτουργικό Σύστημα     |    Κλάδος FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Σημείωση: Ορισμένα εργαλεία λογισμικού δεν λειτουργούν για κάθε λειτουργικό σύστημα. Ανατρέξτε στο [Λογισμικό και Συγκρούσεις](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Εγκατάσταση**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Αυτό θα εγκαταστήσει τις απαιτούμενες εξαρτήσεις λογισμικού PyQt που απαιτούνται για να ξεκινήσουν οι γραφικές διεπαφές εγκατάστασης αν δεν βρεθούν.

Στη συνέχεια, επιλέξτε την επιλογή που ταιριάζει καλύτερα με το λειτουργικό σας σύστημα (θα ανιχνευθεί αυτόματα αν το λειτουργικό σας σύστημα ταιριάζει με μια επιλογή).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Συνιστάται να εγκαταστήσετε το FISSURE σε ένα καθαρό λειτουργικό σύστημα για να αποφύγετε υπάρχουσες συγκρούσεις. Επιλέξτε όλα τα συνιστώμενα πλαίσια ελέγχου (προεπιλεγμένο κουμπί) για να αποφύγετε σφάλματα κατά τη χρήση των διάφορων εργαλείων μέσα στο FISSURE. Θα υπάρχουν πολλές ενδείξεις κατά τη διάρκεια της εγκατάστασης, που κυρίως θα ζητούν αυξημένα δικαιώματα και ονόματα χρηστών. Εάν ένα στοιχείο περιέχει μια ενότητα "Επαλήθευση" στο τέλος, ο εγκαταστάτης θα εκτελέσει την εντολή που ακολουθεί και θα επισημάνει το στοιχείο του πλαισίου ελέγχου με πράσινο ή κόκκινο ανάλογα με το αν παράγονται σφάλματα από την εντολή. Τα επιλεγμένα στοιχεία χωρίς ενότητα "Επαλήθευση" θα παραμείνουν μαύρα μετά την εγκατάσταση.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Χρήση**

Ανοίξτε ένα τερματικό και εισάγετε:
```
fissure
```
Ανατρέξτε στο μενού Βοήθεια του FISSURE για περισσότερες λεπτομέρειες σχετικά με τη χρήση.

## Λεπτομέρειες

**Συστατικά**

* Πίνακας ελέγχου
* Κεντρικός κόμβος (HIPRFISR)
* Αναγνώριση σήματος στόχου (TSI)
* Ανακάλυψη πρωτοκόλλου (PD)
* Ροή γράφου και εκτελεστής σεναρίων (FGE)

![συστατικά](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Δυνατότητες**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Ανιχνευτής Σήματος**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Παραμόρφωση IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Αναζήτηση Σήματος**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Αναγνώριση Προτύπου**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Επιθέσεις**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Λίστες Σήματος**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Συλλογή Εικόνων**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Δημιουργία Πακέτου**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Ενσωμάτωση Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Υπολογιστής CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Καταγραφή**_            |

**Υλικό**

Παρακάτω υπάρχει μια λίστα με το "υποστηριζόμενο" υλικό με διάφορα επίπεδα ενσωμάτωσης:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Προσαρμογείς 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Μαθήματα

Το FISSURE διαθέτει αρκετούς χρήσιμους οδηγούς για να γίνετε εξοικειωμένοι με διάφορες τεχνολογίες και τεχνικές. Πολλά περιλαμβάνουν βήματα για τη χρήση διάφορων εργαλείων που ενσωματώνονται στο FISSURE.

* [Μάθημα 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Μάθημα 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Μάθημα 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Μάθημα 4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Μάθημα 5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Μάθημα 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Μάθημα 7: Τύποι Δεδομένων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Μάθημα 8: Προσαρμοσμένα Μπλοκ GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Μάθημα 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Μάθημα 10: Εξετάσεις Ασυρμάτου Τηλεπικοινωνιών](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Μάθημα 11: Εργαλεία Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Οδοιπορικό

* [ ] Προσθήκη περισσότερων τύπων υλικού, πρωτοκόλλων RF, παραμέτρων σήματος, εργαλείων ανάλυσης
* [ ] Υποστήριξη περισσότερων λειτουργικών συστημάτων
* [ ] Ανάπτυξη υλικού μαθήματος γύρω από το FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, κλπ.)
* [ ] Δημιουργία ενός συνθέτη σήματος, εξαγωγέα χαρακτηριστικών και ταξινομητή σήματος με επιλέξιμες τεχνικές AI/ML
* [ ] Υλοποίηση μηχανισμών αναδρομικής αποδιαμόρφωσης για την παραγωγή μιας ακολουθίας bit από άγνωστα σήματα
* [ ] Μετάβαση των κύριων συστατικ
## Επικοινωνία

Συμμετέχετε στον διακομιστή Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Ακολουθήστε στο Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Ανάπτυξη Επιχείρησης - Assured Information Security, Inc. - bd@ainfosec.com

## Ευγνωμοσύνες

Αναγνωρίζουμε και είμαστε ευγνώμονες σε αυτούς τους προγραμματιστές:

[Ευγνωμοσύνες](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ευχαριστίες

Ειδικές ευχαριστίες στον Δρ. Samuel Mantravadi και τον Joseph Reith για τη συνεισφορά τους σε αυτό το έργο.
