# Κλοπή Πιστοποιητικών AD CS

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτό είναι ένα μικρό σύνολο πληροφοριών για τα κεφάλαια Κλοπής από την εκπληκτική έρευνα του [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Τι μπορώ να κάνω με ένα πιστοποιητικό

Πριν ελέγξουμε πώς να κλέψουμε τα πιστοποιητικά, εδώ έχετε μερικές πληροφορίες για το πώς να βρείτε για τι χρησιμοποιείται το πιστοποιητικό:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Εξαγωγή Πιστοποιητικών Χρησιμοποιώντας τα Crypto APIs – THEFT1

Σε μια **διαδραστική συνεδρία επιφάνειας εργασίας**, η εξαγωγή ενός πιστοποιητικού χρήστη ή μηχανής, μαζί με το ιδιωτικό κλειδί, μπορεί να γίνει εύκολα, ειδικά αν το **ιδιωτικό κλειδί είναι εξαγώγιμο**. Αυτό μπορεί να επιτευχθεί μεταβαίνοντας στο πιστοποιητικό στο `certmgr.msc`, κάνοντας δεξί κλικ πάνω του και επιλέγοντας `All Tasks → Export` για να δημιουργηθεί ένα αρχείο .pfx με κωδικό πρόσβασης.

Για μια **προγραμματιστική προσέγγιση**, είναι διαθέσιμα εργαλεία όπως το PowerShell `ExportPfxCertificate` cmdlet ή έργα όπως το [CertStealer C# project του TheWover](https://github.com/TheWover/CertStealer). Αυτά χρησιμοποιούν το **Microsoft CryptoAPI** (CAPI) ή το Cryptography API: Next Generation (CNG) για να αλληλεπιδράσουν με το αποθετήριο πιστοποιητικών. Αυτές οι διεπαφές παρέχουν μια σειρά από κρυπτογραφικές υπηρεσίες, συμπεριλαμβανομένων αυτών που είναι απαραίτητες για την αποθήκευση και την πιστοποίηση πιστοποιητικών.

Ωστόσο, αν ένα ιδιωτικό κλειδί έχει οριστεί ως μη εξαγώγιμο, τόσο το CAPI όσο και το CNG θα αποκλείσουν κανονικά την εξαγωγή τέτοιων πιστοποιητικών. Για να παρακάμψετε αυτόν τον περιορισμό, μπορούν να χρησιμοποιηθούν εργαλεία όπως το **Mimikatz**. Το Mimikatz προσφέρει τις εντολές `crypto::capi` και `crypto::cng` για να τροποποιήσει τις αντίστοιχες διεπαφές, επιτρέποντας την εξαγωγή ιδιωτικών κλειδιών. Συγκεκριμένα, η εντολή `crypto::capi` τροποποιεί το CAPI εντός της τρέχουσας διεργασίας, ενώ η εντολή `crypto::cng` στοχεύει τη μνήμη του **lsass.exe** για τροποποίηση.

## Κλοπή Πιστοποιητικού Χρήστη μέσω του DPAPI – THEFT2

Περισσότερες πληροφορίες για το DPAPI στο:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Στα Windows, τα **ιδιωτικά κλειδιά πιστοποιητικών προστατεύονται από το DPAPI**. Είναι σημαντικό να αναγνωρίσετε ότι οι **τοποθεσίες αποθήκευσης για τα ιδιωτικά κλειδιά χρήστη και μηχανής** είναι διαφορετικές, και οι δομές αρχείων διαφέρουν ανάλογα με την κρυπτογραφική API που χρησιμοποιείται από το λειτουργικό σύστημα. Το **SharpDPAPI** είναι ένα εργαλείο που μπορεί να πλοηγηθεί αυτόματα σε αυτές τις διαφορές κατά την αποκρυπτογράφηση των DPAPI blobs.

Τα **πιστοποιητικά χρήστη** βρίσκονται κυρίως στο μητρώο κάτω από `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, αλλά μερικά μπορεί να βρεθούν επίσης στον κατάλογο `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Τα αντίστοιχα **ιδιωτικά κλειδιά** για αυτά τα πιστοποιητικά αποθηκεύονται συνήθως στο `%APPDATA%\Microsoft\Crypto\RSA\User SID\` για τα κλειδιά **CAPI** και `%APPDATA%\Microsoft\Crypto\Keys\` για τα κλειδιά **CNG**.

Για να **εξαχθεί ένα πιστοποιητικό και το σχετικό ιδιωτικό κλειδί**, η διαδικασία περιλαμβάνει:

1. **Επιλογή του πιστοποιητικού στόχου** από το αποθετήριο του χρήστη και ανάκτηση του ονόματος του αποθηκευτικού χώρου του.
2. **Εντοπισμός του απαιτούμενου DPAPI masterkey** για να αποκρυπτογραφηθεί το αντίστοιχο ιδιωτικό κλειδί.
3. **Αποκρυπτογράφηση του ιδιωτικού κλειδιού** χρησιμοποιώντας το απλό κείμενο DPAPI masterkey.

Για την **απόκτηση του απλού κειμένου DPAPI masterkey**, μπορούν να χρησιμοποιηθούν οι ακόλουθες προσεγγίσεις:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Για να διευκολυνθεί η αποκρυπτογράφηση αρχείων masterkey και αρχείων ιδιωτικού κλειδιού, η εντολή `certificates` από το [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) αποδεικνύεται ωφέλιμη. Δέχεται `/pvk`, `/mkfile`, `/password` ή `{GUID}:KEY` ως ορίσματα για να αποκρυπτογραφήσει τα ιδιωτικά κλειδιά και τα συνδεδεμένα πιστοποιητικά, δημιουργώντας κατόπιν ένα αρχείο `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Κλοπή Πιστοποιητικού Μηχανής μέσω του DPAPI – THEFT3

Τα πιστοποιητικά μηχανής που αποθηκεύονται από τα Windows στο μητρώο στη διεύθυνση `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` και οι σχετικοί ιδιωτικοί κλειδιούς που βρίσκονται στο `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (για το CAPI) και `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (για το CNG) κρυπτογραφούνται χρησιμοποιώντας τα κλειδιά DPAPI της μηχανής. Αυτά τα κλειδιά δεν μπορούν να αποκρυπτογραφηθούν με το αντίγραφο ασφαλείας του κλειδιού DPAPI της τομέα· αντ' αυτού, απαιτείται το **DPAPI_SYSTEM LSA secret**, το οποίο μόνο ο χρήστης SYSTEM μπορεί να αποκτήσει πρόσβαση.

Η χειροκίνητη αποκρυπτογράφηση μπορεί να επιτευχθεί εκτελώντας την εντολή `lsadump::secrets` στο **Mimikatz** για να εξαγάγετε το DPAPI_SYSTEM LSA secret και στη συνέχεια χρησιμοποιώντας αυτό το κλειδί για να αποκρυπτογραφήσετε τους κλειδιούς μηχανής. Εναλλακτικά, μπορεί να χρησιμοποιηθεί η εντολή `crypto::certificates /export /systemstore:LOCAL_MACHINE` του Mimikatz μετά την επιδιόρθωση του CAPI/CNG όπως περιγράφηκε προηγουμένως.

Το **SharpDPAPI** προσφέρει μια πιο αυτοματοποιημένη προσέγγιση με την εντολή του certificates. Όταν χρησιμοποιείται η σημαία `/machine` με αυξημένα δικαιώματα, ανεβαίνει στο σύστημα, αποθηκεύει το DPAPI_SYSTEM LSA secret, το χρησιμοποιεί για να αποκρυπτογραφήσει τους κλειδιούς μηχανής DPAPI και στη συνέχεια χρησιμοποιεί αυτά τα κλειδιά κειμένου για να αποκρυπτογραφήσει οποιοδήποτε ιδιωτικό κλειδί πιστοποιητικού μηχανής.


## Εύρεση Αρχείων Πιστοποιητικού – THEFT4

Τα πιστοποιητικά βρίσκονται μερικές φορές απευθείας στο σύστημα αρχείων, όπως σε κοινόχρηστους φακέλους ή στον φάκελο Λήψεων. Οι πιο συνηθισμένοι τύποι αρχείων πιστοποιητικού που στοχεύουν σε περιβάλλοντα Windows είναι τα αρχεία `.pfx` και `.p12`. Αν και λιγότερο συχνά, εμφανίζονται επίσης αρχεία με τις επεκτάσεις `.pkcs12` και `.pem`. Επιπλέον, σημαντικές επεκτάσεις αρχείων που σχετίζονται με πιστοποιητικά περιλαμβάνουν:
- `.key` για ιδιωτικά κλειδιά,
- `.crt`/`.cer` για μόνο πιστοποιητικά,
- `.csr` για αιτήσεις υπογραφής πιστοποιητικού, που δεν περιέχουν πιστοποιητικά ή ιδιωτικά κλειδιά,
- `.jks`/`.keystore`/`.keys` για αποθηκευτήρια κλειδιών Java, τα οποία μπορεί να περιέχουν πιστοποιητικά μαζί με ιδιωτικά κλειδιά που χρησιμοποιούνται από εφαρμογές Java.

Αυτά τα αρχεία μπορούν να αναζητηθούν χρησιμοποιώντας το PowerShell ή τη γραμμή εντολών εξετάζοντας τις αναφερόμενες επεκτάσεις.

Σε περιπτώσεις όπου βρίσκεται ένα αρχείο πιστοποιητικού PKCS#12 και προστατεύεται με κωδικό πρόσβασης, είναι δυνατή η εξαγωγή ενός κατακερματισμού μέσω της χρήσης του `pfx2john.py`, διαθέσιμου στο [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Στη συνέχεια, μπορεί να χρησιμοποιηθεί το JohnTheRipper για να προσπαθήσει να αποκρυπτογραφήσει τον κωδικό πρόσβασης.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Κλοπή διαπιστευτηρίων NTLM μέσω PKINIT - THEFT5

Το παρακάτω περιεχόμενο εξηγεί μια μέθοδο για την κλοπή διαπιστευτηρίων NTLM μέσω PKINIT, ειδικότερα μέσω της μεθόδου κλοπής που ονομάζεται THEFT5. Εδώ παρουσιάζεται μια επαναεξήγηση με παθητική φωνή, με ανωνυμοποίηση του περιεχομένου και σύνοψη όπου είναι εφαρμόσιμο:

Για να υποστηρίξει την πιστοποίηση NTLM [MS-NLMP] για εφαρμογές που δεν διευκολύνουν την πιστοποίηση Kerberos, ο KDC είναι σχεδιασμένος να επιστρέφει τη μονοδιάστατη συνάρτηση NTLM (OWF) του χρήστη μέσα στο πιστοποιητικό προνομίων (PAC), ειδικότερα στον πίνακα `PAC_CREDENTIAL_INFO`, όταν χρησιμοποιείται το PKCA. Συνεπώς, αν ένας λογαριασμός πιστοποιηθεί και ασφαλίσει ένα Ticket-Granting Ticket (TGT) μέσω PKINIT, παρέχεται αυτόματα ένας μηχανισμός που επιτρέπει στον τρέχοντα υπολογιστή να εξάγει το NTLM hash από το TGT για τη διατήρηση των πρωτοκόλλων πιστοποίησης παλαιότερων εκδόσεων. Αυτή η διαδικασία περιλαμβάνει την αποκρυπτογράφηση της δομής `PAC_CREDENTIAL_DATA`, η οποία είναι ουσιαστικά μια NDR σειριοποιημένη απεικόνιση του κειμένου NTLM.

Το εργαλείο **Kekeo**, προσβάσιμο στο [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), αναφέρεται ως ικανό να ζητήσει ένα TGT που περιέχει αυτά τα συγκεκριμένα δεδομένα, διευκολύνοντας έτσι την ανάκτηση του NTLM του χρήστη. Η εντολή που χρησιμοποιείται για αυτόν τον σκοπό είναι η εξής:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Επιπλέον, παρατηρείται ότι το Kekeo μπορεί να επεξεργαστεί πιστοποιητικά που προστατεύονται από έξυπνες κάρτες, εφόσον μπορεί να ανακτηθεί το pin, με αναφορά στο [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Η ίδια δυνατότητα υποδηλώνεται ότι υποστηρίζεται από το **Rubeus**, διαθέσιμο στο [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Αυτή η εξήγηση περιλαμβάνει τη διαδικασία και τα εργαλεία που συμμετέχουν στην κλοπή διαπιστευτηρίων NTLM μέσω PKINIT, επικεντρώνοντας στην ανάκτηση των κατακερματισμένων NTLM μέσω TGT που έχουν αποκτηθεί χρησιμοποιώντας PKINIT, και τα εργαλεία που διευκολύνουν αυτήν τη διαδικασία.

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
