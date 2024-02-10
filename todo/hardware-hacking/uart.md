<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Βασικές Πληροφορίες

Το UART είναι ένας σειριακός πρωτόκολλος, που σημαίνει ότι μεταφέρει δεδομένα μεταξύ συστατικών ένα bit τη φορά. Αντίθετα, τα παράλληλα πρωτόκολλα επικοινωνίας μεταφέρουν δεδομένα ταυτόχρονα μέσω πολλαπλών καναλιών. Κοινά σειριακά πρωτόκολλα περιλαμβάνουν τα RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express και USB.

Γενικά, η γραμμή διατηρείται υψηλή (σε λογική τιμή 1) όταν το UART βρίσκεται σε κατάσταση αδράνειας. Στη συνέχεια, για να σηματοδοτήσει την έναρξη μιας μεταφοράς δεδομένων, ο αποστολέας στέλνει ένα bit έναρξης στον παραλήπτη, κατά τη διάρκεια του οποίου το σήμα διατηρείται χαμηλό (σε λογική τιμή 0). Στη συνέχεια, ο αποστολέας στέλνει πέντε έως οκτώ bits δεδομένων που περιέχουν το πραγματικό μήνυμα, ακολουθούμενα από ένα προαιρετικό bit περιττότητας και ένα ή δύο bits σταματήματος (με λογική τιμή 1), ανάλογα με τη διαμόρφωση. Το bit περιττότητας, που χρησιμοποιείται για έλεγχο σφαλμάτων, σπάνια βλέπεται στην πράξη. Το bit (ή τα bits) σταματήματος υποδηλώνουν το τέλος της μετάδοσης.

Αποκαλούμε την πιο κοινή διαμόρφωση 8N1: οκτώ bits δεδομένων, χωρίς περιττότητα και ένα bit σταματήματος. Για παράδειγμα, εάν θέλαμε να στείλουμε τον χαρακτήρα C, ή το 0x43 σε ASCII, σε μια διαμόρφωση UART 8N1, θα στείλουμε τα εξής bits: 0 (το bit έναρξης); 0, 1, 0, 0, 0, 0, 1, 1 (η τιμή του 0x43 σε δυαδική μορφή) και 0 (το bit σταματήματος).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Εργαλεία υλικού για επικοινωνία με το UART:

* Προσαρμογέας USB-to-serial
* Προσαρμογείς με τους ενσωματωμένους κυκλώματα CP2102 ή PL2303
* Πολυεργαλείο όπως το Bus Pirate, το Adafruit FT232H, το Shikra ή το Attify Badge

## Αναγνώριση Θυρών UART

Το UART έχει 4 θύρες: **TX** (Αποστολή), **RX** (Λήψη), **Vcc** (Τάση) και **GND** (Γείωση). Μπορείτε να βρείτε 4 θύρες με τα γράμματα **`TX`** και **`RX`** **γραμμένα** στην πλακέτα. Αλλά εάν δεν υπάρχει καμία ένδειξη, μπορεί να χρειαστεί να προσπαθήσετε να τις βρείτε μόνοι σας χρησιμοποιώντας ένα **πολύμετρο** ή έναν **λογικό αναλυτή**.

Με ένα **πολύμετρο** και τη συσκευή απενεργοποιημένη:

* Για να αναγνωρίσετε τον ακροδέκτη **GND** χρησιμοποιήστε τη λειτουργία **Δοκιμή Συνέχειας**, τοποθετήστε τον πίσω ακροδέκτη στη γείωση και δοκιμάστε με τον κόκκινο μέχρι να ακούσετε ήχο από το πολύμετρο. Μπορεί να βρεθούν πολλοί ακροδέκτες γείωσης στην πλακέτα, οπότε μπορεί να έχετε βρει ή όχι αυτόν που ανήκει στο UART.
* Για να αναγνωρίσετε τη θύρα **VCC**, ρυθμίστε τη λειτουρ
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
