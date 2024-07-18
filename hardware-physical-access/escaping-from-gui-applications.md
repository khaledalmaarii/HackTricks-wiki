# Διαφυγή από τα KIOSKs

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στη 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο βασικός στόχος του WhiteIntel είναι η καταπολέμηση των αποκλεισμών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

## Έλεγχος φυσικής συσκευής

|   Συστατικό   | Ενέργεια                                                               |
| ------------- | -------------------------------------------------------------------- |
| Κουμπί ενεργοποίησης  | Η εναλλαγή της συσκευής ενεργοποίησης και απενεργοποίησης μπορεί να αποκαλύψει την οθόνη εκκίνησης      |
| Καλώδιο τροφοδοσίας   | Ελέγξτε εάν η συσκευή επανεκκινείται όταν αποσυνδέεται η τροφοδοσία εσπευσμένα   |
| Θύρες USB     | Συνδέστε φυσικό πληκτρολόγιο με περισσότερες συντομεύσεις                        |
| Ethernet      | Η σάρωση δικτύου ή το sniffing μπορεί να ενεργοποιήσει περαιτέρω εκμετάλλευση             |


## Έλεγχος πιθανών ενεργειών μέσα στην εφαρμογή GUI

Οι **Κοινές Διάλογοι** είναι αυτές οι επιλογές του **αποθήκευση ενός αρχείου**, **ανοίγματος ενός αρχείου**, επιλογής γραμματοσειράς, χρώματος... Οι περισσότεροι από αυτούς θα **προσφέρουν πλήρη λειτουργικότητα Explorer**. Αυτό σημαίνει ότι θα μπορείτε να έχετε πρόσβαση σε λειτουργίες Explorer αν μπορείτε να έχετε πρόσβαση σε αυτές τις επιλογές:

* Κλείσιμο/Κλείσιμο ως
* Άνοιγμα/Άνοιγμα με
* Εκτύπωση
* Εξαγωγή/Εισαγωγή
* Αναζήτηση
* Σάρωση

Θα πρέπει να ελέγξετε αν μπορείτε:

* Να τροποποιήσετε ή να δημιουργήσετε νέα αρχεία
* Να δημιουργήσετε συμβολικούς συνδέσμους
* Να έχετε πρόσβαση σε περιορισμένες περιοχές
* Να εκτελέσετε άλλες εφαρμογές

### Εκτέλεση Εντολών

Ίσως **χρησιμοποιώντας την επιλογή `Άνοιγμα με`** μπορείτε να ανοίξετε/εκτελέσετε κάποιο είδος κέλυφους.

#### Windows

Για παράδειγμα _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ βρείτε περισσότερα δυαδικά που μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών (και την εκτέλεση απροσδόκητων ενεργειών) εδώ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Περισσότερα εδώ: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Παράκαμψη περιορισμών διαδρομής

* **Μεταβλητές περιβάλλοντος**: Υπάρχουν πολλές μεταβλητές περιβάλλοντος που δείχνουν σε κάποια διαδρομή
* **Άλλοι πρωτόκολλοι**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Συμβολικοί σύνδεσμοι**
* **Συντομεύσεις**: CTRL+N (ανοίγει νέα συνεδρία), CTRL+R (Εκτέλεση Εντολών), CTRL+SHIFT+ESC (Διαχειριστής Εργασιών), Windows+E (ανοίγει τον εξερευνητή), CTRL-B, CTRL-I (Αγαπημένα), CTRL-H (Ιστορικό), CTRL-L, CTRL-O (Διάλογος Αρχείου/Άνοιγμα), CTRL-P (Διάλογος Εκτύπωσης), CTRL-S (Αποθήκευση ως)
* Κρυφό μενού Διαχειριστή: CTRL-ALT-F8, CTRL-ESC-F9
* **URI κέλυφους**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **Διαδρομές UNC**: Διαδρομές για σύνδεση σε κοινόχρηστους φακέλους. Θα πρέπει να δοκιμάσετε να συνδεθείτε στο C$ της τοπικής μηχανής ("\\\127.0.0.1\c$\Windows\System32")
* **Περισσότερες διαδρομές UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Λήψη των δυαδικών σας

Κονσόλα: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Εξερευνητής: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Επεξεργαστής καταχωρήσεων: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Πρόσβαση στο σύστημα αρχείων από τον περιηγητή

| ΔΙΑΔΡΟΜΗ                | ΔΙΑΔΡΟΜΗ              | ΔΙΑΔΡΟΜΗ               | ΔΙΑΔΡΟΜΗ                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |
### ShortCuts

* Sticky Keys – Πατήστε SHIFT 5 φορές
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Κρατήστε πατημένο το NUMLOCK για 5 δευτερόλεπτα
* Filter Keys – Κρατήστε πατημένο το δεξί SHIFT για 12 δευτερόλεπτα
* WINDOWS+F1 – Αναζήτηση Windows
* WINDOWS+D – Εμφάνιση επιφάνειας εργασίας
* WINDOWS+E – Εκκίνηση του Windows Explorer
* WINDOWS+R – Εκτέλεση
* WINDOWS+U – Κέντρο Ευκολιών Πρόσβασης
* WINDOWS+F – Αναζήτηση
* SHIFT+F10 – Μενού περιβάλλοντος
* CTRL+SHIFT+ESC – Διαχειριστής εργασιών
* CTRL+ALT+DEL – Οθόνη εκκίνησης σε νεότερες εκδόσεις των Windows
* F1 – Βοήθεια F3 – Αναζήτηση
* F6 – Γραμμή διεύθυνσης
* F11 – Εναλλαγή σε πλήρη οθόνη μέσα στο Internet Explorer
* CTRL+H – Ιστορικό Internet Explorer
* CTRL+T – Internet Explorer – Νέα καρτέλα
* CTRL+N – Internet Explorer – Νέα σελίδα
* CTRL+O – Άνοιγμα αρχείου
* CTRL+S – Αποθήκευση CTRL+N – Νέα RDP / Citrix

### Swipes

* Σύρετε από την αριστερή πλευρά προς τη δεξιά για να δείτε όλα τα ανοιχτά παράθυρα, ελαχιστοποιώντας την εφαρμογή KIOSK και έχοντας πρόσβαση απευθείας σε ολόκληρο το λειτουργικό σύστημα.
* Σύρετε από τη δεξιά πλευρά προς την αριστερή για να ανοίξετε το Κέντρο Δράσης, ελαχιστοποιώντας την εφαρμογή KIOSK και έχοντας πρόσβαση απευθείας σε ολόκληρο το λειτουργικό σύστημα.
* Σύρετε από την επάνω άκρη για να εμφανιστεί η γραμμή τίτλου για μια εφαρμογή που έχει ανοίξει σε πλήρη οθόνη.
* Σύρετε προς τα πάνω από το κάτω μέρος για να εμφανιστεί η γραμμή εργασιών σε μια εφαρμογή πλήρους οθόνης.

### Internet Explorer Tricks

#### 'Εργαλείο Εικόνας'

Είναι ένα εργαλείο που εμφανίζεται στην πάνω αριστερή πλευρά της εικόνας όταν γίνει κλικ. Θα μπορείτε να Αποθηκεύσετε, Εκτυπώσετε, Στείλετε μέσω email, Ανοίξετε το "Οι Εικόνες μου" στον Εξερευνητή. Το Kiosk πρέπει να χρησιμοποιεί τον Internet Explorer.

#### Πρωτόκολλο Shell

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
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Ο Υπολογιστής μου
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Οι Τοποθεσίες του Δικτύου μου
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Εμφάνιση Επεκτάσεων Αρχείων

Ελέγξτε αυτήν τη σελίδα για περισσότερες πληροφορίες: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Κόλπα Περιηγητών

Αντίγραφα ασφαλείας iKat εκδόσεων:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Δημιουργήστε ένα κοινό διάλογο χρησιμοποιώντας JavaScript και αποκτήστε πρόσβαση στον εξερευνητή αρχείων: `document.write('<input/type=file>')`\
Πηγή: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Χειρονομίες και κουμπιά

* Σύρετε προς τα επάνω με τέσσερα (ή πέντε) δάχτυλα / Διπλό πάτημα στο κουμπί Αρχικής σελίδας: Για να δείτε την προβολή πολλαπλών εργασιών και να αλλάξετε εφαρμογή
* Σύρετε με έναν τρόπο ή άλλο με τέσσερα ή πέντε δάχτυλα: Για να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή
* Κλείστε την οθόνη με πέντε δάχτυλα / Αγγίξτε γρήγορα το κουμπί Αρχικής σελίδας / Σύρετε προς τα επάνω με 1 δάχτυλο από το κάτω μέρος της οθόνης: Για πρόσβαση στην Αρχική σελίδα
* Σύρετε ένα δάχτυλο από το κάτω μέρος της οθόνης μόλις 1-2 ίντσες (αργά): Θα εμφανιστεί η βάση
* Σύρετε προς τα κάτω από την κορυφή της οθόνης με 1 δάχτυλο: Για να δείτε τις ειδοποιήσεις σας
* Σύρετε προς τα κάτω με 1 δάχτυλο στην πάνω δεξιά γωνία της οθόνης: Για να δείτε το κέντρο ελέγχου του iPad Pro
* Σύρετε ένα δάχτυλο από τα αριστερά της οθόνης 1-2 ίντσες: Για να δείτε την προβολή Σήμερα
* Σύρετε γρήγορα ένα δάχτυλο από το κέντρο της οθόνης προς τα δεξιά ή αριστερά: Για να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή
* Πατήστε και κρατήστε πατημένο το κουμπί Ενεργοποίησης/Απενεργοποίησης στην επάνω δεξιά γωνία του iPad + Μετακινήστε τον διακόπτη Απενεργοποίησης εντελώς προς τα δεξιά: Για να κλείσετε
* Πατήστε το κουμπί Ενεργοποίησης/Απενεργοποίησης στην επάνω δεξιά γωνία του iPad και το κουμπί Αρχικής σελίδας για λίγα δευτερόλεπτα: Για να επιβάλετε μια σκληρή απενεργοποίηση
* Πατήστε το κουμπί Ενεργοποίησης/Απενεργοποίησης στην επάνω δεξιά γωνία του iPad και το κουμπί Αρχικής σελίδας γρήγορα: Για να τραβήξετε μια στιγμιότυπη που θα εμφανιστεί στην κάτω αριστερή γωνία της οθόνης. Πατήστε και τα δύο κουμπιά ταυτόχρονα πολύ σύντομα όπως αν τα κρατάτε λίγα δευτερόλεπτα θα εκτελεστεί μια σκληρή απενεργοποίηση.

### Συντομεύσεις

Θα πρέπει να έχετε ένα πληκτρολόγιο iPad ή έναν προσαρμογέα πληκτρολογίου USB. Εδώ θα εμφανιστούν μόνο οι συντομεύσεις που μπορούν να βοηθήσουν στην απόδραση από την εφαρμογή.

| Κλειδί | Όνομα         |
| --- | ------------ |
| ⌘   | Εντολή      |
| ⌥   | Επιλογή (Alt) |
| ⇧   | Μετατόπιση        |
| ↩   | Επιστροφή       |
| ⇥   | Tab          |
| ^   | Έλεγχος      |
| ←   | Αριστερό Βέλος   |
| →   | Δεξί Βέλος  |
| ↑   | Πάνω Βέλος     |
| ↓   | Κάτω Βέλος   |

#### Συντομεύσεις Συστήματος

Αυτές οι συντομεύσεις είναι για τις οπτικές ρυθμίσεις και τις ρυθμίσεις ήχου, ανάλογα με τη χρήση του iPad.

| Συντόμευση | Ενέργεια                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Σκοτεινή οθόνη                                                                    |
| F2       | Φωτεινή οθόνη                                                                |
| F7       | Πίσω ένα τραγούδι                                                                  |
| F
#### Συντομεύσεις Safari

| Συντόμευση              | Ενέργεια                                         |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Άνοιγμα τοποθεσίας                               |
| ⌘T                      | Άνοιγμα νέας καρτέλας                           |
| ⌘W                      | Κλείσιμο της τρέχουσας καρτέλας               |
| ⌘R                      | Ανανέωση της τρέχουσας καρτέλας              |
| ⌘.                      | Διακοπή φόρτωσης της τρέχουσας καρτέλας     |
| ^⇥                      | Μετάβαση στην επόμενη καρτέλα                  |
| ^⇧⇥ (Control-Shift-Tab) | Μετάβαση στην προηγούμενη καρτέλα            |
| ⌘L                      | Επιλογή του πεδίου κειμένου/URL για τροποποίηση |
| ⌘⇧T (Command-Shift-T)   | Άνοιγμα τελευταίας κλεισμένης καρτέλας (μπορεί να χρησιμοποιηθεί πολλές φορές) |
| ⌘\[                     | Πήγαινε πίσω σε μια σελίδα στο ιστορικό περιήγησής σας |
| ⌘]                      | Πήγαινε μπροστά σε μια σελίδα στο ιστορικό περιήγησής σας |
| ⌘⇧R                     | Ενεργοποίηση λειτουργίας Αναγνώστη            |

#### Συντομεύσεις Mail

| Συντόμευση                   | Ενέργεια                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Άνοιγμα τοποθεσίας                |
| ⌘T                         | Άνοιγμα νέας καρτέλας           |
| ⌘W                         | Κλείσιμο της τρέχουσας καρτέλας |
| ⌘R                         | Ανανέωση της τρέχουσας καρτέλας   |
| ⌘.                         | Διακοπή φόρτωσης της τρέχουσας καρτέλας |
| ⌘⌥F (Command-Option/Alt-F) | Αναζήτηση στο εισερχόμενα σας    |

## Αναφορές

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αρπαγών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
