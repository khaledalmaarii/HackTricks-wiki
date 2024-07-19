# AD CS Certificate Theft

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

**Αυτή είναι μια μικρή περίληψη των κεφαλαίων Κλοπής της καταπληκτικής έρευνας από [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## Τι μπορώ να κάνω με ένα πιστοποιητικό

Πριν ελέγξετε πώς να κλέψετε τα πιστοποιητικά, εδώ έχετε μερικές πληροφορίες σχετικά με το πώς να βρείτε για ποιο σκοπό είναι χρήσιμο το πιστοποιητικό:
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
## Exporting Certificates Using the Crypto APIs – THEFT1

In an **interactive desktop session**, extracting a user or machine certificate, along with the private key, can be easily done, particularly if the **private key is exportable**. This can be achieved by navigating to the certificate in `certmgr.msc`, right-clicking on it, and selecting `All Tasks → Export` to generate a password-protected .pfx file.

For a **programmatic approach**, tools such as the PowerShell `ExportPfxCertificate` cmdlet or projects like [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) are available. These utilize the **Microsoft CryptoAPI** (CAPI) or the Cryptography API: Next Generation (CNG) to interact with the certificate store. These APIs provide a range of cryptographic services, including those necessary for certificate storage and authentication.

However, if a private key is set as non-exportable, both CAPI and CNG will normally block the extraction of such certificates. To bypass this restriction, tools like **Mimikatz** can be employed. Mimikatz offers `crypto::capi` and `crypto::cng` commands to patch the respective APIs, allowing for the exportation of private keys. Specifically, `crypto::capi` patches the CAPI within the current process, while `crypto::cng` targets the memory of **lsass.exe** for patching.

## User Certificate Theft via DPAPI – THEFT2

More info about DPAPI in:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows, **οι ιδιωτικοί κωδικοί πιστοποίησης προστατεύονται από το DPAPI**. Είναι κρίσιμο να αναγνωρίσουμε ότι οι **θέσεις αποθήκευσης για τους ιδιωτικούς κωδικούς χρηστών και μηχανών** είναι διακριτές, και οι δομές αρχείων διαφέρουν ανάλογα με την κρυπτογραφική API που χρησιμοποιείται από το λειτουργικό σύστημα. **SharpDPAPI** είναι ένα εργαλείο που μπορεί να πλοηγηθεί σε αυτές τις διαφορές αυτόματα κατά την αποκρυπτογράφηση των DPAPI blobs.

**Οι πιστοποιήσεις χρηστών** φιλοξενούνται κυρίως στο μητρώο κάτω από `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, αλλά μερικές μπορούν επίσης να βρεθούν στον κατάλογο `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Οι αντίστοιχοι **ιδιωτικοί κωδικοί** για αυτές τις πιστοποιήσεις αποθηκεύονται συνήθως στο `%APPDATA%\Microsoft\Crypto\RSA\User SID\` για **CAPI** κωδικούς και στο `%APPDATA%\Microsoft\Crypto\Keys\` για **CNG** κωδικούς.

Για να **εξαγάγετε μια πιστοποίηση και τον σχετικό ιδιωτικό κωδικό της**, η διαδικασία περιλαμβάνει:

1. **Επιλέγοντας την στοχευμένη πιστοποίηση** από το κατάστημα του χρήστη και ανακτώντας το όνομα του αποθηκευτικού κωδικού της.
2. **Εντοπίζοντας τον απαιτούμενο DPAPI masterkey** για να αποκρυπτογραφήσετε τον αντίστοιχο ιδιωτικό κωδικό.
3. **Αποκρυπτογραφώντας τον ιδιωτικό κωδικό** χρησιμοποιώντας τον απλό DPAPI masterkey.

Για **να αποκτήσετε τον απλό DPAPI masterkey**, οι παρακάτω προσεγγίσεις μπορούν να χρησιμοποιηθούν:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Για να απλοποιηθεί η αποκρυπτογράφηση των αρχείων masterkey και των αρχείων ιδιωτικού κλειδιού, η εντολή `certificates` από το [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) αποδεικνύεται χρήσιμη. Δέχεται τα `/pvk`, `/mkfile`, `/password` ή `{GUID}:KEY` ως παραμέτρους για να αποκρυπτογραφήσει τα ιδιωτικά κλειδιά και τα συνδεδεμένα πιστοποιητικά, παράγοντας στη συνέχεια ένα αρχείο `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Κλοπή Πιστοποιητικού Μηχανής μέσω DPAPI – THEFT3

Τα πιστοποιητικά μηχανής που αποθηκεύονται από τα Windows στο μητρώο στη διαδρομή `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` και τα αντίστοιχα ιδιωτικά κλειδιά που βρίσκονται στη διαδρομή `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (για CAPI) και `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (για CNG) είναι κρυπτογραφημένα χρησιμοποιώντας τα κύρια κλειδιά DPAPI της μηχανής. Αυτά τα κλειδιά δεν μπορούν να αποκρυπτογραφηθούν με το αντίγραφο ασφαλείας DPAPI του τομέα; αντίθετα, απαιτείται το **DPAPI_SYSTEM LSA secret**, το οποίο μπορεί να προσπελαστεί μόνο από τον χρήστη SYSTEM.

Η χειροκίνητη αποκρυπτογράφηση μπορεί να επιτευχθεί εκτελώντας την εντολή `lsadump::secrets` στο **Mimikatz** για να εξάγει το DPAPI_SYSTEM LSA secret και στη συνέχεια χρησιμοποιώντας αυτό το κλειδί για να αποκρυπτογραφήσει τα κύρια κλειδιά της μηχανής. Εναλλακτικά, η εντολή `crypto::certificates /export /systemstore:LOCAL_MACHINE` του Mimikatz μπορεί να χρησιμοποιηθεί μετά την επιδιόρθωση CAPI/CNG όπως περιγράφηκε προηγουμένως.

**SharpDPAPI** προσφέρει μια πιο αυτοματοποιημένη προσέγγιση με την εντολή πιστοποιητικών του. Όταν χρησιμοποιείται η σημαία `/machine` με ανυψωμένα δικαιώματα, αναβαθμίζεται σε SYSTEM, εξάγει το DPAPI_SYSTEM LSA secret, το χρησιμοποιεί για να αποκρυπτογραφήσει τα κύρια κλειδιά DPAPI της μηχανής και στη συνέχεια χρησιμοποιεί αυτά τα κλειδιά σε καθαρό κείμενο ως πίνακα αναζήτησης για να αποκρυπτογραφήσει οποιαδήποτε ιδιωτικά κλειδιά πιστοποιητικού μηχανής.

## Εύρεση Αρχείων Πιστοποιητικών – THEFT4

Τα πιστοποιητικά βρίσκονται μερικές φορές απευθείας μέσα στο σύστημα αρχείων, όπως σε κοινές διανομές αρχείων ή στον φάκελο Λήψεις. Οι πιο συχνά συναντώμενοι τύποι αρχείων πιστοποιητικών που στοχεύουν σε περιβάλλοντα Windows είναι τα αρχεία `.pfx` και `.p12`. Αν και λιγότερο συχνά, αρχεία με επεκτάσεις `.pkcs12` και `.pem` εμφανίζονται επίσης. Άλλες αξιοσημείωτες επεκτάσεις αρχείων που σχετίζονται με πιστοποιητικά περιλαμβάνουν:
- `.key` για ιδιωτικά κλειδιά,
- `.crt`/`.cer` για μόνο πιστοποιητικά,
- `.csr` για Αιτήσεις Υπογραφής Πιστοποιητικού, οι οποίες δεν περιέχουν πιστοποιητικά ή ιδιωτικά κλειδιά,
- `.jks`/`.keystore`/`.keys` για Java Keystores, τα οποία μπορεί να περιέχουν πιστοποιητικά μαζί με ιδιωτικά κλειδιά που χρησιμοποιούνται από εφαρμογές Java.

Αυτά τα αρχεία μπορούν να αναζητηθούν χρησιμοποιώντας το PowerShell ή τη γραμμή εντολών αναζητώντας τις αναφερόμενες επεκτάσεις.

Σε περιπτώσεις όπου βρεθεί ένα αρχείο πιστοποιητικού PKCS#12 και είναι προστατευμένο με κωδικό πρόσβασης, η εξαγωγή ενός hash είναι δυνατή μέσω της χρήσης του `pfx2john.py`, διαθέσιμου στο [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Στη συνέχεια, μπορεί να χρησιμοποιηθεί το JohnTheRipper για να προσπαθήσει να σπάσει τον κωδικό πρόσβασης.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Το παρόν περιεχόμενο εξηγεί μια μέθοδο για την κλοπή διαπιστευτηρίων NTLM μέσω PKINIT, συγκεκριμένα μέσω της μεθόδου κλοπής που ονομάζεται THEFT5. Ακολουθεί μια επαναδιατύπωση σε παθητική φωνή, με το περιεχόμενο ανωνυμοποιημένο και συνοπτικό όπου είναι απαραίτητο:

Για να υποστηριχθεί η αυθεντικοποίηση NTLM [MS-NLMP] για εφαρμογές που δεν διευκολύνουν την αυθεντικοποίηση Kerberos, ο KDC έχει σχεδιαστεί να επιστρέφει τη μία κατεύθυνση λειτουργία (OWF) NTLM του χρήστη μέσα στο πιστοποιητικό χαρακτηριστικών προνομίων (PAC), συγκεκριμένα στο buffer `PAC_CREDENTIAL_INFO`, όταν χρησιμοποιείται το PKCA. Ως εκ τούτου, εάν ένας λογαριασμός αυθεντικοποιηθεί και εξασφαλίσει ένα Ticket-Granting Ticket (TGT) μέσω PKINIT, παρέχεται εγγενώς ένας μηχανισμός που επιτρέπει στον τρέχοντα υπολογιστή να εξάγει το hash NTLM από το TGT για να υποστηρίξει τα παλαιά πρωτόκολλα αυθεντικοποίησης. Αυτή η διαδικασία περιλαμβάνει την αποκρυπτογράφηση της δομής `PAC_CREDENTIAL_DATA`, η οποία είναι ουσιαστικά μια NDR σειριοποιημένη απεικόνιση του απλού κειμένου NTLM.

Η χρησιμότητα **Kekeo**, προσβάσιμη στο [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), αναφέρεται ως ικανή να ζητήσει ένα TGT που περιέχει αυτά τα συγκεκριμένα δεδομένα, διευκολύνοντας έτσι την ανάκτηση του NTLM του χρήστη. Η εντολή που χρησιμοποιείται για αυτόν τον σκοπό είναι η εξής:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Επιπλέον, σημειώνεται ότι το Kekeo μπορεί να επεξεργαστεί πιστοποιητικά που προστατεύονται από smartcard, εφόσον το pin μπορεί να ανακτηθεί, με αναφορά στο [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Η ίδια δυνατότητα υποδεικνύεται ότι υποστηρίζεται από το **Rubeus**, διαθέσιμο στο [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Αυτή η εξήγηση περιλαμβάνει τη διαδικασία και τα εργαλεία που εμπλέκονται στην κλοπή διαπιστευτηρίων NTLM μέσω PKINIT, εστιάζοντας στην ανάκτηση των NTLM hashes μέσω TGT που αποκτήθηκε χρησιμοποιώντας PKINIT, και τα εργαλεία που διευκολύνουν αυτή τη διαδικασία.

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
