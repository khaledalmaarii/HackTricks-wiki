# Κόλπα με ZIPs

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

**Εργαλεία γραμμής εντολών** για τη διαχείριση **αρχείων zip** είναι απαραίτητα για τη διάγνωση, επισκευή και αποκωδικοποίηση αρχείων zip. Εδώ υπάρχουν μερικά βασικά εργαλεία:

- **`unzip`**: Αποκαλύπτει γιατί ένα αρχείο zip ενδέχεται να μην αποσυμπιέσει.
- **`zipdetails -v`**: Προσφέρει λεπτομερή ανάλυση των πεδίων μορφής αρχείου zip.
- **`zipinfo`**: Καταχωρεί τα περιεχόμενα ενός αρχείου zip χωρίς να τα εξάγει.
- **`zip -F input.zip --out output.zip`** και **`zip -FF input.zip --out output.zip`**: Δοκιμάζουν να επισκευάσουν κατεστραμμένα αρχεία zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ένα εργαλείο για brute-force αποκωδικοποίηση κωδικών zip, αποτελεσματικό για κωδικούς έως περίπου 7 χαρακτήρες.

Η [προδιαγραφή μορφής αρχείου Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) παρέχει λεπτομερείς πληροφορίες σχετικά με τη δομή και τα πρότυπα των αρχείων zip.

Είναι κρίσιμο να σημειωθεί ότι τα αρχεία zip που προστατεύονται με κωδικό πρόσβασης **δεν κρυπτογραφούν τα ονόματα αρχείων ή το μέγεθος των αρχείων** μέσα σε αυτά, μια ευπάθεια ασφαλείας που δεν μοιράζονται με τα αρχεία RAR ή 7z τα οποία κρυπτογραφούν αυτές τις πληροφορίες. Επιπλέον, τα αρχεία zip που κρυπτογραφούνται με την παλαιότερη μέθοδο ZipCrypto είναι ευάλωτα σε μια **επίθεση κειμένου** αν υπάρχει διαθέσιμο ένα μη κρυπτογραφημένο αντίγραφο ενός συμπιεσμένου αρχείου. Αυτή η επίθεση εκμεταλλεύεται το γνωστό περιεχόμενο για να αποκωδικοποιήσει τον κωδικό του zip, μια ευπάθεια που αναλύεται λεπτομερώς στο [άρθρο του HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) και εξηγείται περαιτέρω σε [αυτό το ακαδημαϊκό άρθρο](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Ωστόσο, τα αρχεία zip που προστατεύονται με κρυπτογράφηση **AES-256** είναι ανθεκτικά σε αυτήν την επίθεση κειμένου, αποδεικνώντας τη σημασία της επιλογής ασφαλών μεθόδων κρυπτογράφησης για ευαίσθητα δεδομένα.

## Αναφορές
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
