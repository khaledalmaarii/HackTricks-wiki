# Εσωτερικά Gadgets ανάγνωσης σε Python

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Βασικές Πληροφορίες

Διάφορες ευπάθειες όπως τα [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) ή η [**Ρύπανση Κλάσεων**](class-pollution-pythons-prototype-pollution.md) μπορεί να σας επιτρέψουν να **διαβάσετε εσωτερικά δεδομένα της Python αλλά δεν θα σας επιτρέψουν να εκτελέσετε κώδικα**. Συνεπώς, ένας pentester θα πρέπει να εκμεταλλευτεί αυτές τις δικαιώματα ανάγνωσης για να **αποκτήσει ευαίσθητα προνόμια και να εξελίξει την ευπάθεια**.

### Flask - Διάβασμα μυστικού κλειδιού

Η κύρια σελίδα μιας εφαρμογής Flask πιθανότατα θα έχει το **`app`** παγκόσμιο αντικείμενο όπου αυτό το **μυστικό είναι ρυθμισμένο**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτήν την περίπτωση είναι δυνατή η πρόσβαση σε αυτό το αντικείμενο χρησιμοποιώντας οποιοδήποτε gadget για **πρόσβαση σε παγκόσμια αντικείμενα** από τη [σελίδα **Παράκαμψης των αμμοθονών της Python**](bypass-python-sandboxes/).

Στην περίπτωση όπου **η ευπάθεια βρίσκεται σε διαφορετικό αρχείο Python**, χρειάζεστε ένα gadget για να διασχίσετε αρχεία και να φτάσετε στο κύριο αρχείο για **πρόσβαση στο παγκόσμιο αντικείμενο `app.secret_key`** για να αλλάξετε το μυστικό κλειδί του Flask και να είστε σε θέση να [**αναβαθμίσετε δικαιώματα** γνωρίζοντας αυτό το κλειδί](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα φορτίο όπως αυτό από αυτό το [άρθρο](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Χρησιμοποιήστε αυτό το φορτίο για **να αλλάξετε το `app.secret_key`** (το όνομα στην εφαρμογή σας μπορεί να είναι διαφορετικό) ώστε να μπορείτε να υπογράψετε νέα και περισσότερα προνόμια στα cookies του flask.

### Werkzeug - machine\_id και node uuid

[**Χρησιμοποιώντας αυτό το φορτίο από αυτήν την ανάλυση**](https://vozec.fr/writeups/tweedle-dum-dee/) θα μπορείτε να έχετε πρόσβαση στο **machine\_id** και το **uuid** node, τα οποία είναι τα **κύρια μυστικά** που χρειάζεστε για [**να δημιουργήσετε το Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) που μπορείτε να χρησιμοποιήσετε για να έχετε πρόσβαση στην python κονσόλα στο `/console` αν η **λειτουργία αποσφαλμάτωσης είναι ενεργοποιημένη:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Σημειώστε ότι μπορείτε να λάβετε τη **τοπική διαδρομή των διακομιστών προς το `app.py`** δημιουργώντας κάποιο **σφάλμα** στην ιστοσελίδα που θα **σας δώσει τη διαδρομή**.
{% endhint %}

Αν η ευπάθεια βρίσκεται σε διαφορετικό αρχείο Python, ελέγξτε το προηγούμενο κόλπο του Flask για πρόσβαση στα αντικείμενα από το κύριο αρχείο Python.

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
