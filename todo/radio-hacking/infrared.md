# Infrared

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

## How the Infrared Works <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Το υπέρυθρο φως είναι αόρατο στους ανθρώπους**. Η μήκος κύματος IR κυμαίνεται από **0.7 έως 1000 μικρόμετρα**. Οι τηλεχειριστήρες χρησιμοποιούν ένα σήμα IR για τη μετάδοση δεδομένων και λειτουργούν στη γκάμα μήκους κύματος 0.75..1.4 μικρόμετρα. Ένας μικροελεγκτής στον τηλεχειριστήριο κάνει μια υπέρυθρη LED να αναβοσβήνει με μια συγκεκριμένη συχνότητα, μετατρέποντας το ψηφιακό σήμα σε σήμα IR.

Για να ληφθούν τα σήματα IR χρησιμοποιείται ένας **φωτοδέκτης**. Αυτός **μετατρέπει το υπέρυθρο φως σε παλμούς τάσης**, οι οποίοι είναι ήδη **ψηφιακά σήματα**. Συνήθως, υπάρχει ένα **φίλτρο σκοτεινού φωτός μέσα στον δέκτη**, το οποίο επιτρέπει **μόνο το επιθυμητό μήκος κύματος να περάσει** και κόβει τον θόρυβο.

### Variety of IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Οι πρωτόκολλοι IR διαφέρουν σε 3 παράγοντες:

* κωδικοποίηση bit
* δομή δεδομένων
* συχνότητα φορέα — συχνά στην περιοχή 36..38 kHz

#### Bit encoding ways <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Κωδικοποίηση Απόστασης Παλμού**

Τα bits κωδικοποιούνται με την τροποποίηση της διάρκειας του χώρου μεταξύ των παλμών. Το πλάτος του παλμού είναι σταθερό.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Κωδικοποίηση Πλάτους Παλμού**

Τα bits κωδικοποιούνται με την τροποποίηση του πλάτους του παλμού. Το πλάτος του χώρου μετά την έκρηξη του παλμού είναι σταθερό.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Κωδικοποίηση Φάσης**

Είναι επίσης γνωστή ως κωδικοποίηση Manchester. Η λογική τιμή καθορίζεται από την πολικότητα της μετάβασης μεταξύ της έκρηξης του παλμού και του χώρου. "Χώρος σε έκρηξη παλμού" δηλώνει λογική "0", "έκρηξη παλμού σε χώρο" δηλώνει λογική "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Συνδυασμός των προηγούμενων και άλλων εξωτικών**

{% hint style="info" %}
Υπάρχουν πρωτόκολλα IR που **προσπαθούν να γίνουν καθολικά** για διάφορους τύπους συσκευών. Τα πιο διάσημα είναι τα RC5 και NEC. Δυστυχώς, το πιο διάσημο **δεν σημαίνει το πιο κοινό**. Στο περιβάλλον μου, συνάντησα μόνο δύο τηλεχειριστήρια NEC και κανένα RC5.

Οι κατασκευαστές αγαπούν να χρησιμοποιούν τα δικά τους μοναδικά πρωτόκολλα IR, ακόμη και εντός της ίδιας γκάμας συσκευών (για παράδειγμα, TV-boxes). Επομένως, τα τηλεχειριστήρια από διαφορετικές εταιρείες και μερικές φορές από διαφορετικά μοντέλα της ίδιας εταιρείας, δεν είναι σε θέση να λειτουργήσουν με άλλες συσκευές του ίδιου τύπου.
{% endhint %}

### Exploring an IR signal

Ο πιο αξιόπιστος τρόπος για να δείτε πώς φαίνεται το σήμα IR του τηλεχειριστηρίου είναι να χρησιμοποιήσετε ένα παλμογράφο. Δεν αποδιαμορφώνει ή αναστρέφει το ληφθέν σήμα, απλά εμφανίζεται "όπως είναι". Αυτό είναι χρήσιμο για δοκιμές και αποσφαλμάτωση. Θα δείξω το αναμενόμενο σήμα με το παράδειγμα του πρωτοκόλλου IR NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Συνήθως, υπάρχει μια προάγγελος στην αρχή ενός κωδικοποιημένου πακέτου. Αυτό επιτρέπει στον δέκτη να καθορίσει το επίπεδο ενίσχυσης και το υπόβαθρο. Υπάρχουν επίσης πρωτόκολλα χωρίς προάγγελο, για παράδειγμα, Sharp.

Στη συνέχεια, μεταδίδονται τα δεδομένα. Η δομή, η προάγγελος και η μέθοδος κωδικοποίησης bit καθορίζονται από το συγκεκριμένο πρωτόκολλο.

**Το πρωτόκολλο IR NEC** περιέχει μια σύντομη εντολή και έναν κωδικό επανάληψης, ο οποίος αποστέλλεται ενώ το κουμπί είναι πατημένο. Και η εντολή και ο κωδικός επανάληψης έχουν την ίδια προάγγελο στην αρχή.

Η **εντολή NEC**, εκτός από την προάγγελο, αποτελείται από ένα byte διεύθυνσης και ένα byte αριθμού εντολής, με το οποίο η συσκευή καταλαβαίνει τι πρέπει να εκτελέσει. Τα byte διεύθυνσης και αριθμού εντολής διπλασιάζονται με αντίστροφες τιμές, για να ελέγξουν την ακεραιότητα της μετάδοσης. Υπάρχει ένα επιπλέον bit σταματήματος στο τέλος της εντολής.

Ο **κωδικός επανάληψης** έχει ένα "1" μετά την προάγγελο, το οποίο είναι ένα bit σταματήματος.

Για **λογική "0" και "1"** το NEC χρησιμοποιεί Κωδικοποίηση Απόστασης Παλμού: πρώτα, μεταδίδεται μια έκρηξη παλμού μετά την οποία υπάρχει μια παύση, το μήκος της οποίας καθορίζει την τιμή του bit.

### Air Conditioners

Σε αντίθεση με άλλους τηλεχειριστήρες, **οι κλιματιστικές μονάδες δεν μεταδίδουν απλώς τον κωδικό του πατημένου κουμπιού**. Επίσης **μεταδίδουν όλες τις πληροφορίες** όταν πατηθεί ένα κουμπί για να διασφαλίσουν ότι η **κλιματιστική μηχανή και το τηλεχειριστήριο είναι συγχρονισμένα**.\
Αυτό θα αποτρέψει το να ρυθμιστεί μια μηχανή στους 20ºC να αυξηθεί στους 21ºC με ένα τηλεχειριστήριο, και στη συνέχεια όταν χρησιμοποιηθεί ένα άλλο τηλεχειριστήριο, το οποίο έχει ακόμα τη θερμοκρασία στους 20ºC, να αυξηθεί περισσότερο η θερμοκρασία, θα "αυξηθεί" στους 21ºC (και όχι στους 22ºC νομίζοντας ότι είναι στους 21ºC).

### Attacks

You can attack Infrared with Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
