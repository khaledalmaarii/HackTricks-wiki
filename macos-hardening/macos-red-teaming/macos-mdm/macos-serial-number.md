# macOS Serial Number

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Basic Information

Οι συσκευές της Apple μετά το 2010 έχουν σειριακούς αριθμούς που αποτελούνται από **12 αλφαριθμητικούς χαρακτήρες**, κάθε τμήμα μεταφέρει συγκεκριμένες πληροφορίες:

- **Πρώτοι 3 Χαρακτήρες**: Υποδεικνύουν την **τοποθεσία κατασκευής**.
- **Χαρακτήρες 4 & 5**: Δηλώνουν το **έτος και την εβδομάδα κατασκευής**.
- **Χαρακτήρες 6 έως 8**: Λειτουργούν ως **μοναδικός αναγνωριστικός αριθμός** για κάθε συσκευή.
- **Τελευταίοι 4 Χαρακτήρες**: Προσδιορίζουν τον **αριθμό μοντέλου**.

Για παράδειγμα, ο σειριακός αριθμός **C02L13ECF8J2** ακολουθεί αυτή τη δομή.

### **Τοποθεσίες Κατασκευής (Πρώτοι 3 Χαρακτήρες)**
Ορισμένοι κωδικοί αντιπροσωπεύουν συγκεκριμένα εργοστάσια:
- **FC, F, XA/XB/QP/G8**: Διάφορες τοποθεσίες στις ΗΠΑ.
- **RN**: Μεξικό.
- **CK**: Κορκ, Ιρλανδία.
- **VM**: Foxconn, Τσεχική Δημοκρατία.
- **SG/E**: Σιγκαπούρη.
- **MB**: Μαλαισία.
- **PT/CY**: Κορέα.
- **EE/QT/UV**: Ταϊβάν.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Διάφορες τοποθεσίες στην Κίνα.
- **C0, C3, C7**: Συγκεκριμένες πόλεις στην Κίνα.
- **RM**: Ανακατασκευασμένες συσκευές.

### **Έτος Κατασκευής (4ος Χαρακτήρας)**
Αυτός ο χαρακτήρας ποικίλλει από 'C' (που αντιπροσωπεύει το πρώτο εξάμηνο του 2010) έως 'Z' (δεύτερο εξάμηνο του 2019), με διαφορετικά γράμματα να υποδεικνύουν διαφορετικές περιόδους εξαμήνου.

### **Εβδομάδα Κατασκευής (5ος Χαρακτήρας)**
Οι ψηφία 1-9 αντιστοιχούν σε εβδομάδες 1-9. Τα γράμματα C-Y (εξαιρουμένων των φωνηέντων και του 'S') αντιπροσωπεύουν τις εβδομάδες 10-27. Για το δεύτερο εξάμηνο του έτους, προστίθεται το 26 σε αυτόν τον αριθμό.

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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
