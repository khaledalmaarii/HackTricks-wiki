<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Ελέγξτε για πιθανές ενέργειες μέσα στην εφαρμογή GUI

Οι **Κοινές Διάλογοι** είναι αυτές οι επιλογές για **αποθήκευση αρχείου**, **ανοιγμα αρχείου**, επιλογή γραμματοσειράς, χρώματος... Οι περισσότερες από αυτές θα **προσφέρουν μια πλήρη λειτουργικότητα του Explorer**. Αυτό σημαίνει ότι θα μπορείτε να έχετε πρόσβαση σε λειτουργίες του Explorer εάν έχετε πρόσβαση σε αυτές τις επιλογές:

* Κλείσιμο/Κλείσιμο ως
* Άνοιγμα/Άνοιγμα με
* Εκτύπωση
* Εξαγωγή/Εισαγωγή
* Αναζήτηση
* Σάρωση

Θα πρέπει να ελέγξετε εάν μπορείτε:

* Να τροποποιήσετε ή να δημιουργήσετε νέα αρχεία
* Να δημιουργήσετε συμβολικούς συνδέσμους
* Να έχετε πρόσβαση σε περιορισμένες περιοχές
* Να εκτελέσετε άλλες εφαρμογές

## Εκτέλεση Εντολών

Ίσως **χρησιμοποιώντας την επιλογή `Άνοιγμα με`** μπορείτε να ανοίξετε/εκτελέσετε κάποιο είδος κέλυφους.

### Windows

Για παράδειγμα _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ βρείτε περισσότερα δυαδικά που μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών (και για την εκτέλεση απροσδόκητων ενεργειών) εδώ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Περισσότερα εδώ: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Παράκαμψη περιορισμών διαδρομής

* **Μεταβλητές περιβάλλοντος**: Υπάρχουν πολλές μεταβλητές περιβάλλοντος που δείχνουν σε κάποια διαδρομή
* **Άλλα πρωτόκολλα**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Συμβολικοί σύνδεσμοι**
* **Συντομεύσεις**: CTRL+N (ανοίγει νέα συνεδρία), CTRL+R (Εκτέλεση Εντολών), CTRL+SHIFT+ESC (Διαχειριστής Εργασιών),  Windows+E (ανοίγει τον εξερευνητή), CTRL-B, CTRL-I (Αγαπημένα), CTRL-H (Ιστορικό), CTRL-L, CTRL-O (Διάλογος Ανοίγματος Αρχείου), CTRL-P (Διάλογος Εκτύπωσης), CTRL-S (Αποθήκευση ως)
* Κρυφό μενού Διαχειριστή: CTRL-ALT-F8, CTRL-ESC-F9
* **URI του κέλυφους**: _shell:Εργαλεία Διαχείρισης, shell:ΒιβλιοθήκεςΕγγράφων, shell:Βιβλιοθήκες, shell:ΠροφίλΧρηστών, shell:Προσωπικό, shell:ΦάκελοςΑναζήτησης, shell:Σύστημαshell:ΦάκελοςΔικτύου, shell:ΣτείλεΣε, shell:ΠροφίλΧρηστών, shell:Κοινά Εργαλεία Διαχείρισης, shell:ΥπολογιστήςΦάκελος, shell:ΦάκελοςInternet,_
* **Διαδρομές UNC**: Διαδρομές για σύνδεση σε κοινόχ
## Σάρωση

* Σαρώστε από την αριστερή πλευρά προς τη δεξιά για να δείτε όλα τα ανοιχτά παράθυρα, ελαχιστοποιώντας την εφαρμογή KIOSK και έχοντας πρόσβαση στον πλήρη λειτουργικό σύστημα απευθείας.
* Σαρώστε από τη δεξιά πλευρά προς την αριστερά για να ανοίξετε το Κέντρο Δράσης, ελαχιστοποιώντας την εφαρμογή KIOSK και έχοντας πρόσβαση στον πλήρη λειτουργικό σύστημα απευθείας.
* Σαρώστε από την επάνω άκρη προς τα μέσα για να εμφανιστεί η γραμμή τίτλου για μια εφαρμογή που έχει ανοίξει σε πλήρη οθόνη.
* Σαρώστε προς τα πάνω από το κάτω μέρος για να εμφανιστεί η γραμμή εργασιών σε μια εφαρμογή πλήρους οθόνης.

## Κόλπα Internet Explorer

### 'Εργαλειοθήκη εικόνων'

Είναι μια εργαλειοθήκη που εμφανίζεται στην πάνω αριστερή γωνία της εικόνας όταν γίνεται κλικ. Θα μπορείτε να Αποθηκεύσετε, Εκτυπώσετε, Αποστολή μέσω ηλεκτρονικού ταχυδρομείου, Ανοίξτε το "Οι εικόνες μου" στον Εξερευνητή. Το Kiosk πρέπει να χρησιμοποιεί τον Internet Explorer.

### Πρωτόκολλο Shell

Πληκτρολογήστε αυτές τις διευθύνσεις URL για να αποκτήσετε μια προβολή του Εξερευνητή:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Πίνακας Ελέγχου
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Ο υπολογιστής μου
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Οι τοποθεσίες του δικτύου μου
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Εμφάνιση Επεκτάσεων Αρχείων

Ελέγξτε αυτήν τη σελίδα για περισσότερες πληροφορίες: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Κόλπα περιηγητών

Αντίγραφο ασφαλείας των εκδόσεων iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Δημιουργήστε ένα κοινό διάλογο χρησιμοποιώντας JavaScript και αποκτήστε πρόσβαση στον εξερευνητή αρχείων: `document.write('<input/type=file>')`
Πηγή: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Χειρονομίες και κουμπιά

* Σαρώστε προς τα πάνω με τέσσερα (ή πέντε) δάχτυλα / Διπλό πάτημα στο κουμπί Αρχικής σελίδας: Για να δείτε την προβολή πολλαπλών εργασιών και να αλλάξετε εφαρμογή.

* Σαρώστε προς τη μία ή την άλλη κατεύθυνση με τέσσερα ή πέντε δάχτυλα: Προκειμένου να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή.

* Κλείστε την οθόνη με πέντε δάχτυλα / Αγγίξτε το κουμπί Αρχικής σελίδας / Σαρώστε προς τα πάνω με ένα δάχτυλο από το κάτω μέρος της οθόνης με γρήγορη κίνηση προς τα πάνω: Για να αποκτήσετε πρόσβαση στην Αρχική σελίδα.

* Σαρώστε με ένα δάχτυλο από το κάτω μέρος της οθόνης με αργή κίνηση 1-2 ίντσες: Θα εμφανιστεί η γραμμή εργαλείων.

* Σαρώστε προς τα κάτω από την κορυφή της οθόνης με ένα δάχτυλο: Για να δείτε τις ειδοποιήσεις σας.

* Σαρώστε προς τα κάτω με ένα δάχτυλο στην πάνω δεξιά γωνία της οθόνης: Για να δείτε το κέντρο ελέγχου του iPad Pro.

* Σαρώστε ένα δάχτυλο α
### Συντομεύσεις Safari

| Συντόμευση              | Ενέργεια                                          |
| ----------------------- | ------------------------------------------------- |
| ⌘L (Command-L)          | Άνοιγμα τοποθεσίας                                 |
| ⌘T                      | Άνοιγμα νέας καρτέλας                              |
| ⌘W                      | Κλείσιμο τρέχουσας καρτέλας                        |
| ⌘R                      | Ανανέωση τρέχουσας καρτέλας                        |
| ⌘.                      | Διακοπή φόρτωσης τρέχουσας καρτέλας                |
| ^⇥                      | Μετάβαση στην επόμενη καρτέλα                      |
| ^⇧⇥ (Control-Shift-Tab) | Μετάβαση στην προηγούμενη καρτέλα                  |
| ⌘L                      | Επιλογή του πεδίου κειμένου/URL για τροποποίηση    |
| ⌘⇧T (Command-Shift-T)   | Άνοιγμα τελευταίας κλεισμένης καρτέλας (μπορεί να χρησιμοποιηθεί πολλές φορές) |
| ⌘\[                     | Πήγαινε πίσω μια σελίδα στο ιστορικό περιήγησής σας |
| ⌘]                      | Πήγαινε μπροστά μια σελίδα στο ιστορικό περιήγησής σας |
| ⌘⇧R                     | Ενεργοποίηση της λειτουργίας ανάγνωσης              |

### Συντομεύσεις Mail

| Συντόμευση                   | Ενέργεια                        |
| -------------------------- | ---------------------------- |
| ⌘L                         | Άνοιγμα τοποθεσίας                |
| ⌘T                         | Άνοιγμα νέας καρτέλας             |
| ⌘W                         | Κλείσιμο τρέχουσας καρτέλας       |
| ⌘R                         | Ανανέωση τρέχουσας καρτέλας       |
| ⌘.                         | Διακοπή φόρτωσης τρέχουσας καρτέλας |
| ⌘⌥F (Command-Option/Alt-F) | Αναζήτηση στο εισερχόμενο ταχυδρομείο σας |

# Αναφορές

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
