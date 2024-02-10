# Έλεγχος - Εκμετάλλευση Προνομίων Τοπικού Συστήματος Windows

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### **Καλύτερο εργαλείο για την αναζήτηση διανομής προνομίων τοπικού συστήματος Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Πληροφορίες Συστήματος](windows-local-privilege-escalation/#system-info)

* [ ] Αποκτήστε [**πληροφορίες συστήματος**](windows-local-privilege-escalation/#system-info)
* [ ] Αναζητήστε **εκμεταλλεύσεις πυρήνα** [**χρησιμοποιώντας σενάρια**](windows-local-privilege-escalation/#version-exploits)
* [ ] Χρησιμοποιήστε τη **Google για αναζήτηση** εκμεταλλεύσεων πυρήνα
* [ ] Χρησιμοποιήστε το **searchsploit για αναζήτηση** εκμεταλλεύσεων πυρήνα
* [ ] Ενδιαφέρουσες πληροφορίες στις [**μεταβλητές περιβάλλοντος**](windows-local-privilege-escalation/#environment)?
* [ ] Κωδικοί πρόσβασης στο [**ιστορικό PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Ενδιαφέρουσες πληροφορίες στις [**ρυθμίσεις διαδικτύου**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Δίσκοι**](windows-local-privilege-escalation/#drives)?
* [ ] [**Εκμετάλλευση WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Απαρίθμηση Καταγραφής/Ανίχνευσης AV](windows-local-privilege-escalation/#enumeration)

* [ ] Ελέγξτε τις ρυθμίσεις [**Ελέγχου** ](windows-local-privilege-escalation/#audit-settings)και [**WEF** ](windows-local-privilege-escalation/#wef)
* [ ] Ελέγξτε το [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Ελέγξτε εάν είναι ενεργό το [**WDigest** ](windows-local-privilege-escalation/#wdigest)
* [ ] [**Προστασία LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Προστασία Διαπιστευτηρίων**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Κρυφά Διαπιστευτήρια**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Ελέγξτε εάν υπάρχει κάποιο [**AV**](windows-av-bypass)
* [ ] [**Πολιτική AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Δικαιώματα Χρηστών**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Ελέγξτε τα [**τρέχοντα** δικαιώματα χρήστη](windows-local-privilege-escalation/#users-and-groups)
* [ ] Είστε [**μέλος κάποιας προνομιούχας ομάδας**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Ελέγξτε εάν έχετε ενεργοποιημένα [κάποια από αυτά τα δικαιώματα](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Συνεδρίες Χρηστών**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Ελέγξτε τα [**αρχεία home των χρηστών**](windows-local-privilege-escalation/#home-folders) (πρόσβαση?)
* [ ] Ελέγξτε την [**Πολιτική Κωδικού Πρόσβασης**](windows-local-privilege-escalation/#password-policy)
* [ ] Τι υπάρχει [**στο Πρόχειρο**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Δίκτυο](windows-local-privilege-escalation/#network)

* [ ] Ελέγξτε τις **τρέχουσες πληροφορίες δικτύου** [**
### [Δίκτυο](windows-local-privilege-escalation/#network)

* [ ] Απαριθμήστε το δίκτυο (κοινόχρηστους φακέλους, διεπαφές, διαδρομές, γείτονες, ...)
* [ ] Εξετάστε προσεκτικά τις υπηρεσίες δικτύου που ακούνε στο localhost (127.0.0.1)

### [Διαπιστευτήρια Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] Διαπιστευτήρια [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] Διαπιστευτήρια [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) που μπορείτε να χρησιμοποιήσετε;
* [ ] Ενδιαφέροντα [**DPAPI credentials**](windows-local-privilege-escalation/#dpapi);
* [ ] Κωδικοί πρόσβασης αποθηκευμένων [**ασύρματων δικτύων**](windows-local-privilege-escalation/#wifi);
* [ ] Ενδιαφέρουσες πληροφορίες στις [**αποθηκευμένες συνδέσεις RDP**](windows-local-privilege-escalation/#saved-rdp-connections);
* [ ] Κωδικοί πρόσβασης στις [**πρόσφατα εκτελεσμένες εντολές**](windows-local-privilege-escalation/#recently-run-commands);
* [ ] Κωδικοί πρόσβασης του [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager);
* [ ] Υπάρχει το [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe); Διαπιστευτήρια;
* [ ] Το [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm); DLL Side Loading;

### [Αρχεία και Καταχώρηση (Διαπιστευτήρια)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Διαπιστευτήρια**](windows-local-privilege-escalation/#putty-creds) **και** [**κλειδιά SSH του κεντρικού υπολογιστή**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] Κλειδιά [**SSH στην καταχώρηση**](windows-local-privilege-escalation/#ssh-keys-in-registry);
* [ ] Κωδικοί πρόσβασης σε [**ανεπίβλεπτα αρχεία**](windows-local-privilege-escalation/#unattended-files);
* [ ] Οποιοδήποτε αντίγραφο ασφαλείας [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups);
* [ ] [**Διαπιστευτήρια Cloud**](windows-local-privilege-escalation/#cloud-credentials);
* [ ] Το αρχείο [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml);
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword);
* [ ] Κωδικός πρόσβασης στο [**αρχείο διαμόρφωσης του IIS Web**](windows-local-privilege-escalation/#iis-web-config);
* [ ] Ενδιαφέρουσες πληροφορίες στα [**αρχεία καταγραφής του web**](windows-local-privilege-escalation/#logs);
* [ ] Θέλετε να [**ζητήσετε διαπιστευτήρια**](windows-local-privilege-escalation/#ask-for-credentials) από τον χρήστη;
* [ ] Ενδιαφέροντα [**αρχεία μέσα στον κάδο ανακύκλωσης**](windows-local-privilege-escalation/#credentials-in-the-recyclebin);
* [ ] Άλλη [**καταχώρηση που περιέχει διαπιστευτήρια**](windows-local-privilege-escalation/#inside-the-registry);
* [ ] Μέσα στα [**δεδομένα του προγράμματος περιήγησης**](windows-local-privilege-escalation/#browsers-history) (βάσεις δεδομένων, ιστορικό, σελιδοδείκτες, ...);
* [ ] [**Γενική αναζήτηση κωδικών πρόσβασης**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) σε αρχεία και καταχώρηση;
* [ ] [**Εργαλεία**](windows-local-privilege-escalation/#tools-that-search-for-passwords) για αυτόματη αναζήτηση κωδικών πρόσβασης

### [Διαρροές Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Έχετε πρόσβαση σε οποιοδήποτε handler ενός διεργασίας που εκτελείται από τον διαχειριστή;

### [Παραπληροφόρηση Πελάτη Ονομασμένου Σωλήνα](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Ελέγξτε αν μπορείτε να το καταχραστείτε

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
