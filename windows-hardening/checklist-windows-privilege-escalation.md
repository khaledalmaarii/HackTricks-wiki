# Λίστα ελέγχου - Εξέλιξη προνομίων τοπικά στα Windows

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### **Καλύτερο εργαλείο για αναζήτηση διανυσματικών εξέλιξης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες Συστήματος](windows-local-privilege-escalation/#system-info)

* [ ] Αποκτήστε [**Πληροφορίες Συστήματος**](windows-local-privilege-escalation/#system-info)
* [ ] Αναζητήστε **εκμεταλλεύσεις πυρήνα** χρησιμοποιώντας **σενάρια** (scripts) (windows-local-privilege-escalation/#version-exploits)
* [ ] Χρησιμοποιήστε τη **Google για αναζήτηση** εκμεταλλεύσεων πυρήνα
* [ ] Χρησιμοποιήστε το **searchsploit για αναζήτηση** εκμεταλλεύσεων πυρήνα
* [ ] Ενδιαφέρουσες πληροφορίες στις [**μεταβλητές περιβάλλοντος**](windows-local-privilege-escalation/#environment)?
* [ ] Κωδικοί στο [**ιστορικό PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Ενδιαφέρουσες πληροφορίες στις [**ρυθμίσεις Internet**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Δίσκοι**](windows-local-privilege-escalation/#drives)?
* [ ] [**Εκμετάλλευση WSUS**](windows-local-privilege-escalation/#wsus)?
* [**Πάντα Εγκατεστημένο με Υψηλά Δικαιώματα**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Απαρίθμηση Logging/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Ελέγξτε τις [**ρυθμίσεις Ελέγχου**](windows-local-privilege-escalation/#audit-settings) και [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Ελέγξτε το [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Ελέγξτε αν το [**WDigest**](windows-local-privilege-escalation/#wdigest) είναι ενεργό
* [ ] [**Προστασία LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Φύλαξη Διαπιστευτηρίων**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Κρυφά Διαπιστευτήρια**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Ελέγξτε αν υπάρχει κάποιο [**Αντιιό**](windows-av-bypass)
* [**Πολιτική AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Προνόμια Χρηστών**](windows-local-privilege-escalation/#users-and-groups)
* Ελέγξτε τα [**τρέχοντα** προνόμια χρήστη](windows-local-privilege-escalation/#users-and-groups)
* Είστε [**μέλος κάποιας ομάδας με προνόμια**](windows-local-privilege-escalation/#privileged-groups)?
* Ελέγξτε αν έχετε ενεργοποιημένα [κάποια από αυτά τα διακριτικά](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Συνεδρίες Χρηστών**](windows-local-privilege-escalation/#logged-users-sessions)?
* Ελέγξτε τα [**σπίτια χρηστών**](windows-local-privilege-escalation/#home-folders) (πρόσβαση?)
* Ελέγξτε τη [**Πολιτική Κωδικών**](windows-local-privilege-escalation/#password-policy)
* Τι υπάρχει μέσα στο [**Πρόχειρο**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Δίκτυο](windows-local-privilege-escalation/#network)

* Ελέγξτε τις **τρέχουσες** [**πληροφορίες δικτύου**](windows-local-privilege-escalation/#network)
* Ελέγξτε **κρυφές τοπικές υπηρεσίες** περιορισμένες προς τα έξω

### [Εκτελούμενες Διεργασίες](windows-local-privilege-escalation/#running-processes)

* Άδειες αρχείων και φακέλων των διεργασιών [**αρχείων και φακέλων**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Εξόρυξη κωδικών μνήμης**](windows-local-privilege-escalation/#memory-password-mining)
* [**Ευάλωτες εφαρμογές GUI**](windows-local-privilege-escalation/#insecure-gui-apps)
* Κλέψτε διαπιστευτήρια με **ενδιαφέρουσες διεργασίες** μέσω `ProcDump.exe` ? (firefox, chrome, κλπ ...)

### [Υπηρεσίες](windows-local-privilege-escalation/#services)

* [Μπορείτε να **τροποποιήσετε κάποια υπηρεσία**;](windows-local-privilege-escalation#permissions)
* [Μπορείτε να **τροποποιήσετε** το **δυαδικό** που **εκτελείται** από κάποια **υπηρεσία**;](windows-local-privilege-escalation/#modify-service-binary-path)
* [Μπορείτε να **τροποποιήσετε** το **μητρώο** μιας **υπηρεσίας**;](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [Μπορείτε να εκμεταλλευτείτε κάποιο **μη-περιγραμμένο δυαδικό υπηρεσίας**;](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Εφαρμογές**](windows-local-privilege-escalation/#applications)

* **Δικαιώματα εγγραφής σε εγκατεστημένες εφαρμογές**](windows-local-privilege-escalation/#write-permissions)
* [**Εφαρμογές Εκκίνησης**](windows-local-privilege-escalation/#run-at-startup)
* **Ευάλωτοι** [**Οδηγοί**](windows-local-privilege-escalation/#drivers)

### [Απάτη DLL](windows-local-privilege-escalation/#path-dll-hijacking)

* Μπορείτε **να γράψετε σε οποιοδήποτε φάκελο μέσα στο PATH**;
* Υπάρχει κάποιο γνωστό δυαδικό υπηρεσίας που **προσπαθεί να φορτώσει κάποιο μη υπάρχον DLL**;
* Μπορείτε **να γράψετε** σε οποιονδήποτε **φάκελο δυαδικών**;
### [Δίκτυο](windows-local-privilege-escalation/#network)

* [ ] Καταμέτρηση του δικτύου (κοινόχρηστους φακέλους, διεπαφές, δρομολόγια, γείτονες, ...)
* [ ] Εξέταση των υπηρεσιών δικτύου που ακούνε στο localhost (127.0.0.1)

### [Διαπιστευτήρια Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)διαπιστευτήρια
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) διαπιστευτήρια που μπορείτε να χρησιμοποιήσετε?
* [ ] Ενδιαφέροντα [**DPAPI διαπιστευτήρια**](windows-local-privilege-escalation/#dpapi)?
* [ ] Κωδικοί αποθηκευμένων [**δικτύων Wifi**](windows-local-privilege-escalation/#wifi)?
* [ ] Ενδιαφέρουσες πληροφορίες σε [**αποθηκευμένες συνδέσεις RDP**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Κωδικοί σε [**πρόσφατα εκτελεσμένες εντολές**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Διαχειριστής διαπιστευτηρίων [**Remote Desktop**](windows-local-privilege-escalation/#remote-desktop-credential-manager); κωδικοί;
* [ ] Το [**AppCmd.exe** υπάρχει](windows-local-privilege-escalation/#appcmd-exe); Διαπιστευτήρια;
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm); DLL Side Loading?

### [Αρχεία και Καταχώριση (Διαπιστευτήρια)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Διαπιστευτήρια**](windows-local-privilege-escalation/#putty-creds) **και** [**κλειδιά κεντρικού SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Κλειδιά SSH στο μητρώο**](windows-local-privilege-escalation/#ssh-keys-in-registry);
* [ ] Κωδικοί σε [**ανεπίβλεπα αρχεία**](windows-local-privilege-escalation/#unattended-files);
* [ ] Οποιαδήποτε αντίγραφα ασφαλείας [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups);
* [ ] [**Διαπιστευτήρια Cloud**](windows-local-privilege-escalation/#cloud-credentials);
* [ ] Αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml);
* [**Κρυφός κωδικός GPP**](windows-local-privilege-escalation/#cached-gpp-pasword);
* Κωδικός σε [**αρχείο ρυθμίσεων IIS Web**](windows-local-privilege-escalation/#iis-web-config);
* Ενδιαφέρουσες πληροφορίες σε [**καταγραφές ιστού**](windows-local-privilege-escalation/#logs);
* Θέλετε να [**ζητήσετε διαπιστευτήρια**](windows-local-privilege-escalation/#ask-for-credentials) από τον χρήστη;
* Ενδιαφέροντα [**αρχεία μέσα στον Κάδο Ανακύκλωσης**](windows-local-privilege-escalation/#credentials-in-the-recyclebin);
* Άλλη [**καταχώριση που περιέχει διαπιστευτήρια**](windows-local-privilege-escalation/#inside-the-registry);
* Μέσα στα [**δεδομένα του προγράμματος περιήγησης**](windows-local-privilege-escalation/#browsers-history) (βάσεις δεδομένων, ιστορικό, σελιδοδείκτες, ...);
* [**Γενική αναζήτηση κωδικών πρόσβασης**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) σε αρχεία και καταχώριση;
* [**Εργαλεία**](windows-local-privilege-escalation/#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Διαρροές Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Έχετε πρόσβαση σε οποιονδήποτε handler ενός διεργασίας που εκτελείται από διαχειριστή;

### [Παραποίηση Πελάτη Ονομασμένου Σωλήνα](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Ελέγξτε αν μπορείτε να το εκμεταλλευτείτε
