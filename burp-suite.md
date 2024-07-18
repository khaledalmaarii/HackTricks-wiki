{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**Στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε τεχνικές χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}


# Βασικά Payloads

* **Απλή λίστα:** Απλά μια λίστα που περιέχει μια καταχώρηση σε κάθε γραμμή
* **Αρχείο Runtime:** Μια λίστα που διαβάζεται κατά την εκτέλεση (δεν φορτώνεται στη μνήμη). Για υποστήριξη μεγάλων λιστών.
* **Τροποποίηση περίπτωσης:** Εφαρμόστε ορισμένες αλλαγές σε μια λίστα αλφαριθμητικών (Χωρίς αλλαγή, σε πεζά, σε ΚΕΦΑΛΑΙΑ, σε Κανονικό όνομα - Πρώτο κεφαλαίο και τα υπόλοιπα σε πεζά-, σε Κανονικό όνομα -Πρώτο κεφαλαίο και τα υπόλοιπα παραμένουν τα ίδια-.
* **Αριθμοί:** Δημιουργία αριθμών από Χ έως Υ χρησιμοποιώντας βήμα Z ή τυχαία.
* **Εργαλείο Εξαναγκαστικής Εισβολής:** Σύνολο χαρακτήρων, ελάχιστο & μέγιστο μήκος.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload για εκτέλεση εντολών και ανάκτηση εξόδου μέσω αιτημάτων DNS στο burpcollab.

{% embed url="https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e" %}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
