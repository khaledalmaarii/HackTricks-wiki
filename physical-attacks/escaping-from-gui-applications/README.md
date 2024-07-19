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


# Έλεγχος για πιθανές ενέργειες μέσα στην εφαρμογή GUI

**Κοινά παράθυρα διαλόγου** είναι αυτές οι επιλογές του **αποθηκεύω ένα αρχείο**, **ανοίγω ένα αρχείο**, επιλέγοντας μια γραμματοσειρά, ένα χρώμα... Οι περισσότερες από αυτές θα **προσφέρουν πλήρη λειτουργικότητα Explorer**. Αυτό σημαίνει ότι θα μπορείτε να έχετε πρόσβαση σε λειτουργίες του Explorer αν μπορείτε να έχετε πρόσβαση σε αυτές τις επιλογές:

* Κλείσιμο/Κλείσιμο ως
* Άνοιγμα/Άνοιγμα με
* Εκτύπωση
* Εξαγωγή/Εισαγωγή
* Αναζήτηση
* Σάρωση

Πρέπει να ελέγξετε αν μπορείτε να:

* Τροποποιήσετε ή δημιουργήσετε νέα αρχεία
* Δημιουργήσετε συμβολικούς συνδέσμους
* Αποκτήσετε πρόσβαση σε περιοχές περιορισμένης πρόσβασης
* Εκτελέσετε άλλες εφαρμογές

## Εκτέλεση εντολών

Ίσως **χρησιμοποιώντας μια επιλογή `Άνοιγμα με`** μπορείτε να ανοίξετε/εκτελέσετε κάποιο είδος shell.

### Windows

Για παράδειγμα _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ βρείτε περισσότερους δυαδικούς κωδικούς που μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών (και την εκτέλεση απροσδόκητων ενεργειών) εδώ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Περισσότερα εδώ: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Παράκαμψη περιορισμών διαδρομής

* **Μεταβλητές περιβάλλοντος**: Υπάρχουν πολλές μεταβλητές περιβάλλοντος που δείχνουν σε κάποια διαδρομή
* **Άλλες πρωτόκολλες**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Συμβολικοί σύνδεσμοι**
* **Συντομεύσεις**: CTRL+N (άνοιγμα νέας συνεδρίας), CTRL+R (Εκτέλεση Εντολών), CTRL+SHIFT+ESC (Διαχείριση Εργασιών),  Windows+E (άνοιγμα explorer), CTRL-B, CTRL-I (Αγαπημένα), CTRL-H (Ιστορικό), CTRL-L, CTRL-O (Αρχείο/Άνοιγμα Διαλόγου), CTRL-P (Διάλογος Εκτύπωσης), CTRL-S (Αποθήκευση ως)
* Κρυφό Διαχειριστικό μενού: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC διαδρομές**: Διαδρομές για σύνδεση σε κοινόχρηστα φακέλους. Πρέπει να προσπαθήσετε να συνδεθείτε στο C$ της τοπικής μηχανής ("\\\127.0.0.1\c$\Windows\System32")
* **Περισσότερες UNC διαδρομές:**

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

## Κατεβάστε τους δυαδικούς σας κωδικούς

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Πρόσβαση στο σύστημα αρχείων από τον περιηγητή

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Συντομεύσεις

* Sticky Keys – Πατήστε SHIFT 5 φορές
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Κρατήστε το NUMLOCK για 5 δευτερόλεπτα
* Filter Keys – Κρατήστε το δεξί SHIFT για 12 δευτερόλεπτα
* WINDOWS+F1 – Αναζήτηση Windows
* WINDOWS+D – Εμφάνιση Επιφάνειας Εργασίας
* WINDOWS+E – Εκκίνηση Windows Explorer
* WINDOWS+R – Εκτέλεση
* WINDOWS+U – Κέντρο Προσβασιμότητας
* WINDOWS+F – Αναζήτηση
* SHIFT+F10 – Μενού περιβάλλοντος
* CTRL+SHIFT+ESC – Διαχείριση Εργασιών
* CTRL+ALT+DEL – Οθόνη εκκίνησης σε νεότερες εκδόσεις Windows
* F1 – Βοήθεια F3 – Αναζήτηση
* F6 – Γραμμή διευθύνσεων
* F11 – Εναλλαγή πλήρους οθόνης μέσα στο Internet Explorer
* CTRL+H – Ιστορικό Internet Explorer
* CTRL+T – Internet Explorer – Νέα καρτέλα
* CTRL+N – Internet Explorer – Νέα σελίδα
* CTRL+O – Άνοιγμα αρχείου
* CTRL+S – Αποθήκευση CTRL+N – Νέα RDP / Citrix

## Swipes

* Σύρετε από την αριστερή πλευρά προς τα δεξιά για να δείτε όλα τα ανοιχτά Windows, ελαχιστοποιώντας την εφαρμογή KIOSK και αποκτώντας άμεση πρόσβαση σε ολόκληρο το λειτουργικό σύστημα.
* Σύρετε από τη δεξιά πλευρά προς τα αριστερά για να ανοίξετε το Κέντρο Ενεργειών, ελαχιστοποιώντας την εφαρμογή KIOSK και αποκτώντας άμεση πρόσβαση σε ολόκληρο το λειτουργικό σύστημα.
* Σύρετε από την επάνω άκρη για να κάνετε την γραμμή τίτλου ορατή για μια εφαρμογή που έχει ανοιχτεί σε πλήρη οθόνη.
* Σύρετε προς τα πάνω από το κάτω μέρος για να εμφανίσετε τη γραμμή εργασιών σε μια εφαρμογή πλήρους οθόνης.

## Τεχνάσματα Internet Explorer

### 'Εργαλειοθήκη Εικόνας'

Είναι μια εργαλειοθήκη που εμφανίζεται στην επάνω αριστερή γωνία της εικόνας όταν κάνετε κλικ. Θα μπορείτε να Αποθηκεύσετε, Εκτυπώσετε, Στείλετε μέσω email, Ανοίξετε "Οι Εικόνες Μου" στον Explorer. Το Kiosk πρέπει να χρησιμοποιεί τον Internet Explorer.

### Πρωτόκολλο Shell

Πληκτρολογήστε αυτές τις διευθύνσεις URL για να αποκτήσετε μια προβολή Explorer:

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
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Ο Υπολογιστής Μου
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Οι Δικτυακοί Τόποι Μου
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Εμφάνιση Επεκτάσεων Αρχείων

Ελέγξτε αυτή τη σελίδα για περισσότερες πληροφορίες: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Τεχνάσματα περιηγητών

Αντίγραφα ασφαλείας εκδόσεων iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Δημιουργήστε ένα κοινό διάλογο χρησιμοποιώντας JavaScript και αποκτήστε πρόσβαση στον εξερευνητή αρχείων: `document.write('<input/type=file>')`
Πηγή: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Γεστουρές και κουμπιά

* Σύρετε προς τα πάνω με τέσσερα (ή πέντε) δάχτυλα / Διπλό πατήστε το κουμπί Home: Για να δείτε την προβολή πολλαπλών εργασιών και να αλλάξετε εφαρμογή

* Σύρετε από τη μία ή την άλλη πλευρά με τέσσερα ή πέντε δάχτυλα: Για να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή

* Συμπιέστε την οθόνη με πέντε δάχτυλα / Πατήστε το κουμπί Home / Σύρετε προς τα πάνω με 1 δάχτυλο από το κάτω μέρος της οθόνης σε γρήγορη κίνηση προς τα πάνω: Για να αποκτήσετε πρόσβαση στην Αρχική οθόνη

* Σύρετε ένα δάχτυλο από το κάτω μέρος της οθόνης μόλις 1-2 ίντσες (αργά): Η βάση θα εμφανιστεί

* Σύρετε προς τα κάτω από την κορυφή της οθόνης με 1 δάχτυλο: Για να δείτε τις ειδοποιήσεις σας

* Σύρετε προς τα κάτω με 1 δάχτυλο στην επάνω δεξιά γωνία της οθόνης: Για να δείτε το κέντρο ελέγχου του iPad Pro

* Σύρετε 1 δάχτυλο από την αριστερή πλευρά της οθόνης 1-2 ίντσες: Για να δείτε την προβολή Σήμερα

* Σύρετε γρήγορα 1 δάχτυλο από το κέντρο της οθόνης προς τα δεξιά ή αριστερά: Για να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή

* Πατήστε και κρατήστε το κουμπί On/**Off**/Sleep στην επάνω δεξιά γωνία του **iPad +** Μετακινήστε το ρυθμιστικό "Slide to **power off**" μέχρι το τέλος προς τα δεξιά: Για να απενεργοποιήσετε

* Πατήστε το κουμπί On/**Off**/Sleep στην επάνω δεξιά γωνία του **iPad και το κουμπί Home για μερικά δευτερόλεπτα**: Για να αναγκάσετε μια σκληρή απενεργοποίηση

* Πατήστε το κουμπί On/**Off**/Sleep στην επάνω δεξιά γωνία του **iPad και το κουμπί Home γρήγορα**: Για να τραβήξετε ένα στιγμιότυπο οθόνης που θα εμφανιστεί στην κάτω αριστερή γωνία της οθόνης. Πατήστε και τα δύο κουμπιά ταυτόχρονα πολύ σύντομα, καθώς αν τα κρατήσετε για μερικά δευτερόλεπτα θα εκτελεστεί μια σκληρή απενεργοποίηση.

## Συντομεύσεις

Πρέπει να έχετε ένα πληκτρολόγιο iPad ή έναν προσαρμογέα USB πληκτρολογίου. Μόνο οι συντομεύσεις που θα μπορούσαν να βοηθήσουν στην έξοδο από την εφαρμογή θα εμφανιστούν εδώ.

| Key | Name         |
| --- | ------------ |
| ⌘   | Εντολή      |
| ⌥   | Επιλογή (Alt) |
| ⇧   | Shift        |
| ↩   | Επιστροφή       |
| ⇥   | Ταμπ          |
| ^   | Έλεγχος      |
| ←   | Αριστερό Βέλος   |
| →   | Δεξί Βέλος  |
| ↑   | Άνω Βέλος     |
| ↓   | Κάτω Βέλος   |

### Συντομεύσεις συστήματος

Αυτές οι συντομεύσεις είναι για τις ρυθμίσεις οπτικών και ήχου, ανάλογα με τη χρήση του iPad.

| Συντόμευση | Ενέργεια                                                                         |
| ----------- | ------------------------------------------------------------------------------ |
| F1          | Σβήσιμο οθόνης                                                                    |
| F2          | Φωτεινότητα οθόνης                                                                |
| F7          | Πίσω ένα τραγούδι                                                                  |
| F8          | Αναπαραγωγή/παύση                                                                 |
| F9          | Παράλειψη τραγουδιού                                                              |
| F10         | Σίγαση                                                                           |
| F11         | Μείωση έντασης                                                                    |
| F12         | Αύξηση έντασης                                                                    |
| ⌘ Space     | Εμφάνιση λίστας διαθέσιμων γλωσσών; για να επιλέξετε μία, πατήστε ξανά το πλήκτρο διαστήματος. |

### Πλοήγηση iPad

| Συντόμευση                                           | Ενέργεια                                                  |
| ---------------------------------------------------- | --------------------------------------------------------- |
| ⌘H                                                 | Μετάβαση στην Αρχική οθόνη                                |
| ⌘⇧H (Εντολή-Shift-H)                              | Μετάβαση στην Αρχική οθόνη                                |
| ⌘ (Space)                                          | Άνοιγμα Spotlight                                        |
| ⌘⇥ (Εντολή-Ταμπ)                                   | Λίστα τελευταίων δέκα χρησιμοποιημένων εφαρμογών         |
| ⌘\~                                                | Μετάβαση στην τελευταία εφαρμογή                           |
| ⌘⇧3 (Εντολή-Shift-3)                              | Στιγμιότυπο οθόνης (εμφανίζεται στην κάτω αριστερή γωνία για αποθήκευση ή ενέργεια) |
| ⌘⇧4                                                | Στιγμιότυπο οθόνης και άνοιγμα στον επεξεργαστή           |
| Πατήστε και κρατήστε ⌘                             | Λίστα διαθέσιμων συντομεύσεων για την εφαρμογή           |
| ⌘⌥D (Εντολή-Επιλογή/Alt-D)                         | Εμφάνιση της βάσης                                        |
| ^⌥H (Έλεγχος-Επιλογή-H)                             | Κουμπί Αρχικής                                           |
| ^⌥H H (Έλεγχος-Επιλογή-H-H)                         | Εμφάνιση της γραμμής πολλαπλών εργασιών                   |
| ^⌥I (Έλεγχος-Επιλογή-i)                             | Επιλογέας στοιχείων                                       |
| Escape                                             | Κουμπί πίσω                                             |
| → (Δεξί βέλος)                                    | Επόμενο στοιχείο                                         |
| ← (Αριστερό βέλος)                                     | Προηγούμενο στοιχείο                                     |
| ↑↓ (Άνω βέλος, Κάτω βέλος)                          | Πατήστε ταυτόχρονα το επιλεγμένο στοιχείο                |
| ⌥ ↓ (Επιλογή-Κάτω βέλος)                            | Κύλιση προς τα κάτω                                      |
| ⌥↑ (Επιλογή-Άνω βέλος)                               | Κύλιση προς τα πάνω                                      |
| ⌥← ή ⌥→ (Επιλογή-Αριστερό βέλος ή Επιλογή-Δεξί βέλος) | Κύλιση αριστερά ή δεξιά                                  |
| ^⌥S (Έλεγχος-Επιλογή-S)                             | Ενεργοποίηση ή απενεργοποίηση της ομιλίας VoiceOver      |
| ⌘⇧⇥ (Εντολή-Shift-Ταμπ)                            | Εναλλαγή στην προηγούμενη εφαρμογή                       |
| ⌘⇥ (Εντολή-Ταμπ)                                   | Επιστροφή στην αρχική εφαρμογή                           |
| ←+→, στη συνέχεια Επιλογή + ← ή Επιλογή+→                   | Πλοήγηση μέσω της βάσης                                   |

### Συντομεύσεις Safari

| Συντόμευση                | Ενέργεια                                           |
| ------------------------- | -------------------------------------------------- |
| ⌘L (Εντολή-L)            | Άνοιγμα Τοποθεσίας                                |
| ⌘T                      | Άνοιγμα νέας καρτέλας                             |
| ⌘W                      | Κλείσιμο της τρέχουσας καρτέλας                   |
| ⌘R                      | Ανανεώστε την τρέχουσα καρτέλα                    |
| ⌘.                      | Σταματήστε τη φόρτωση της τρέχουσας καρτέλας      |
| ^⇥                      | Εναλλαγή στην επόμενη καρτέλα                     |
| ^⇧⇥ (Έλεγχος-Shift-Ταμπ) | Μετακίνηση στην προηγούμενη καρτέλα                |
| ⌘L                      | Επιλογή του πεδίου εισόδου κειμένου/URL για τροποποίηση |
| ⌘⇧T (Εντολή-Shift-T)   | Άνοιγμα της τελευταίας κλειστής καρτέλας (μπορεί να χρησιμοποιηθεί πολλές φορές) |
| ⌘\[                     | Πηγαίνετε πίσω μία σελίδα στην ιστορία περιήγησης  |
| ⌘]                      | Πηγαίνετε μπροστά μία σελίδα στην ιστορία περιήγησης |
| ⌘⇧R                     | Ενεργοποίηση Λειτουργίας Αναγνωστή                |

### Συντομεύσεις Mail

| Συντόμευση                   | Ενέργεια                       |
| ---------------------------- | ------------------------------ |
| ⌘L                         | Άνοιγμα Τοποθεσίας            |
| ⌘T                         | Άνοιγμα νέας καρτέλας         |
| ⌘W                         | Κλείσιμο της τρέχουσας καρτέλας |
| ⌘R                         | Ανανεώστε την τρέχουσα καρτέλα |
| ⌘.                         | Σταματήστε τη φόρτωση της τρέχουσας καρτέλας |
| ⌘⌥F (Εντολή-Επιλογή/Alt-F) | Αναζήτηση στο γραμματοκιβώτιό σας |

# Αναφορές

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


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
