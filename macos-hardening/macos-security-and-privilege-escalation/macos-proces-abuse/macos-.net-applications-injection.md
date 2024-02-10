# Εισαγωγή σε εφαρμογές .Net στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτό είναι ένα σύνοψη του άρθρου [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Ελέγξτε το για περισσότερες λεπτομέρειες!**

## Αποσφαλμάτωση .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Δημιουργία μιας συνεδρίας αποσφαλμάτωσης** <a href="#net-core-debugging" id="net-core-debugging"></a>

Η διαχείριση της επικοινωνίας μεταξύ αποσφαλματωτή και αποσφαλματούμενου στο .NET γίνεται από το [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Αυτό το στοιχείο δημιουργεί δύο ονομασμένα αγωγούς ανά .NET διεργασία, όπως φαίνεται στο [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), οι οποίοι εκκινούν μέσω του [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Αυτοί οι αγωγοί έχουν ως επίθεμα τα **`-in`** και **`-out`**.

Επισκεπτόμενοι το **`$TMPDIR`** του χρήστη, μπορεί κανείς να βρει τους αγωγούς αποσφαλμάτωσης που είναι διαθέσιμοι για την αποσφαλμάτωση εφαρμογών .Net.

Ο [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) είναι υπεύθυνος για τη διαχείριση της επικοινωνίας από έναν αποσφαλματωτή. Για να ξεκινήσει μια νέα συνεδρία αποσφαλμάτωσης, ένας αποσφαλματωτής πρέπει να στείλει ένα μήνυμα μέσω του αγωγού `out` που ξεκινά με μια δομή `MessageHeader`, η οποία περιγράφεται λεπτομερώς στον πηγαίο κώδικα του .NET:
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Για να ζητηθεί μια νέα συνεδρία, αυτή η δομή συμπληρώνεται ως εξής, ορίζοντας τον τύπο μηνύματος σε `MT_SessionRequest` και την έκδοση πρωτοκόλλου στην τρέχουσα έκδοση:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Αυτή η κεφαλίδα στέλνεται στον στόχο χρησιμοποιώντας την κλήση συστήματος `write`, ακολουθούμενη από τη δομή `sessionRequestData` που περιέχει ένα GUID για τη συνεδρία:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Μια λειτουργία ανάγνωσης στο αγωγό `out` επιβεβαιώνει την επιτυχία ή την αποτυχία της διαδικασίας αποσφαλμάτωσης:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Ανάγνωση Μνήμης
Μόλις έχει δημιουργηθεί μια συνεδρία αποσφαλμάτωσης, η μνήμη μπορεί να διαβαστεί χρησιμοποιώντας τον τύπο μηνύματος [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Η συνάρτηση readMemory είναι λεπτομερής, εκτελώντας τα απαραίτητα βήματα για να στείλει ένα αίτημα ανάγνωσης και να ανακτήσει την απόκριση:
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
Η πλήρης απόδειξη του concept (POC) είναι διαθέσιμη [εδώ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Εγγραφή Μνήμης

Αντίστοιχα, η μνήμη μπορεί να εγγραφεί χρησιμοποιώντας τη συνάρτηση `writeMemory`. Η διαδικασία περιλαμβάνει την ρύθμιση του τύπου μηνύματος σε `MT_WriteMemory`, τον καθορισμό της διεύθυνσης και του μήκους των δεδομένων, και στη συνέχεια την αποστολή των δεδομένων:
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
Το σχετικό POC είναι διαθέσιμο [εδώ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Εκτέλεση κώδικα .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Για να εκτελέσετε κώδικα, πρέπει να εντοπίσετε μια περιοχή μνήμης με δικαιώματα rwx, το οποίο μπορεί να γίνει χρησιμοποιώντας την εντολή vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Είναι απαραίτητο να εντοπιστεί ένα σημείο για την αντικατάσταση ενός δείκτη συνάρτησης, και στο .NET Core αυτό μπορεί να γίνει στο **Dynamic Function Table (DFT)**. Αυτός ο πίνακας, που περιγράφεται στο [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), χρησιμοποιείται από το runtime για τις βοηθητικές συναρτήσεις JIT μεταγλώττισης.

Για συστήματα x64, μπορεί να χρησιμοποιηθεί η τεχνική του signature hunting για να βρεθεί μια αναφορά στο σύμβολο `_hlpDynamicFuncTable` στο `libcorclr.dll`.

Η συνάρτηση αποσφαλμάτωσης `MT_GetDCB` παρέχει χρήσιμες πληροφορίες, συμπεριλαμβανομένης της διεύθυνσης μιας βοηθητικής συνάρτησης, `m_helperRemoteStartAddr`, που υποδεικνύει την τοποθεσία του `libcorclr.dll` στη μνήμη της διεργασίας. Αυτή η διεύθυνση χρησιμοποιείται στη συνέχεια για να ξεκινήσει η αναζήτηση του DFT και η αντικατάσταση ενός δείκτη συνάρτησης με τη διεύθυνση του shellcode.

Ο πλήρης κώδικας POC για ενσωμάτωση στο PowerShell είναι προσβάσιμος [εδώ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Αναφορές

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
