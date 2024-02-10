# Εργαλεία Ανάγνωσης Εσωτερικών Στοιχείων της Python

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Διάφορες ευπάθειες όπως οι [**Συμβολοσειρές Μορφοποίησης της Python**](bypass-python-sandboxes/#python-format-string) ή η [**Ρύπανση Κλάσεων**](class-pollution-pythons-prototype-pollution.md) μπορεί να σας επιτρέψουν να **διαβάσετε εσωτερικά δεδομένα της Python αλλά δεν θα σας επιτρέψουν να εκτελέσετε κώδικα**. Επομένως, ένας pentester θα πρέπει να εκμεταλλευτεί αυτές τις δικαιώματα ανάγνωσης για να **αποκτήσει ευαίσθητα προνόμια και να αναβαθμίσει την ευπάθεια**.

### Flask - Διάβασμα μυστικού κλειδιού

Η κύρια σελίδα μιας εφαρμογής Flask πιθανότατα θα έχει το **`app`** αντικείμενο όπου αυτό το **μυστικό έχει διαμορφωθεί**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτήν την περίπτωση είναι δυνατή η πρόσβαση σε αυτό το αντικείμενο χρησιμοποιώντας οποιοδήποτε εργαλείο για **πρόσβαση σε παγκόσμια αντικείμενα** από την [σελίδα **Παράκαμψη των αμμοθύρων της Python**](bypass-python-sandboxes/).

Στην περίπτωση όπου **η ευπάθεια βρίσκεται σε ένα διαφορετικό αρχείο python**, χρειάζεστε ένα εργαλείο για να διασχίσετε τα αρχεία και να φτάσετε στο κύριο αρχείο για να **έχετε πρόσβαση στο παγκόσμιο αντικείμενο `app.secret_key`** και να αλλάξετε το μυστικό κλειδί του Flask και να είστε σε θέση να [**αναβαθμίσετε τα δικαιώματα** γνωρίζοντας αυτό το κλειδί](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα πακέτο όπως αυτό από αυτήν την ανάλυση [από αυτό το άρθρο](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Χρησιμοποιήστε αυτό το payload για να **αλλάξετε το `app.secret_key`** (το όνομα στην εφαρμογή σας μπορεί να είναι διαφορετικό) ώστε να μπορείτε να υπογράφετε νέα και πιο προνόμια flask cookies.

### Werkzeug - machine\_id και node uuid

[**Χρησιμοποιώντας αυτό το payload από αυτό το writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) θα μπορείτε να έχετε πρόσβαση στο **machine\_id** και το **uuid** node, τα οποία είναι τα **κύρια μυστικά** που χρειάζεστε για να [**δημιουργήσετε το Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) που μπορείτε να χρησιμοποιήσετε για να έχετε πρόσβαση στην python κονσόλα στο `/console` αν ο **λειτουργικός τρόπος αποσφαλμάτωσης είναι ενεργοποιημένος:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Σημείωση ότι μπορείτε να πάρετε τη **τοπική διαδρομή του διακομιστή προς το `app.py`** δημιουργώντας κάποιο **σφάλμα** στην ιστοσελίδα που θα **σας δώσει τη διαδρομή**.
{% endhint %}

Εάν η ευπάθεια βρίσκεται σε ένα διαφορετικό αρχείο python, ελέγξτε το προηγούμενο κόλπο Flask για να έχετε πρόσβαση στα αντικείμενα από το κύριο αρχείο python.

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
