# iButton

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

## Intro

iButton είναι ένα γενικό όνομα για ένα ηλεκτρονικό κλειδί ταυτοποίησης που είναι συσκευασμένο σε ένα **μεταλλικό δοχείο σε σχήμα νομίσματος**. Ονομάζεται επίσης **Dallas Touch** Memory ή επαφή μνήμης. Αν και συχνά αναφέρεται λανθασμένα ως “μαγνητικό” κλειδί, δεν υπάρχει **τίποτα μαγνητικό** σε αυτό. Στην πραγματικότητα, ένα πλήρες **μικροτσίπ** που λειτουργεί με ψηφιακό πρωτόκολλο είναι κρυμμένο μέσα του.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Συνήθως, το iButton υποδηλώνει τη φυσική μορφή του κλειδιού και του αναγνώστη - ένα στρογγυλό νόμισμα με δύο επαφές. Για το πλαίσιο που το περιβάλλει, υπάρχουν πολλές παραλλαγές από τον πιο κοινό πλαστικό κάτοχο με μια τρύπα μέχρι δαχτυλίδια, κρεμαστά κ.λπ.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Όταν το κλειδί φτάσει στον αναγνώστη, οι **επαφές έρχονται σε επαφή** και το κλειδί τροφοδοτείται για να **μεταδώσει** την ταυτότητά του. Μερικές φορές το κλειδί **δεν διαβάζεται** αμέσως επειδή το **PSD επαφής ενός θυροτηλεφώνου είναι μεγαλύτερο** από ό,τι θα έπρεπε. Έτσι, οι εξωτερικές περιγράμματα του κλειδιού και του αναγνώστη δεν μπορούσαν να αγγίξουν. Αν συμβαίνει αυτό, θα πρέπει να πιέσετε το κλειδί πάνω σε έναν από τους τοίχους του αναγνώστη.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Οι κλειδαριές Dallas ανταλλάσσουν δεδομένα χρησιμοποιώντας το πρωτόκολλο 1-wire. Με μόνο μία επαφή για τη μεταφορά δεδομένων (!!) και στις δύο κατευθύνσεις, από τον κύριο στον δούλο και αντίστροφα. Το πρωτόκολλο 1-wire λειτουργεί σύμφωνα με το μοντέλο Master-Slave. Σε αυτή την τοπολογία, ο Master πάντα ξεκινά την επικοινωνία και ο Slave ακολουθεί τις οδηγίες του.

Όταν το κλειδί (Slave) έρχεται σε επαφή με το θυροτηλέφωνο (Master), το τσιπ μέσα στο κλειδί ενεργοποιείται, τροφοδοτούμενο από το θυροτηλέφωνο, και το κλειδί αρχικοποιείται. Ακολουθώντας αυτό, το θυροτηλέφωνο ζητά την ταυτότητα του κλειδιού. Στη συνέχεια, θα εξετάσουμε αυτή τη διαδικασία πιο λεπτομερώς.

Το Flipper μπορεί να λειτουργήσει τόσο σε λειτουργία Master όσο και σε λειτουργία Slave. Στη λειτουργία ανάγνωσης κλειδιού, το Flipper λειτουργεί ως αναγνώστης, δηλαδή λειτουργεί ως Master. Και στη λειτουργία προσομοίωσης κλειδιού, το Flipper προσποιείται ότι είναι ένα κλειδί, είναι σε λειτουργία Slave.

### Dallas, Cyfral & Metakom keys

Για πληροφορίες σχετικά με το πώς λειτουργούν αυτά τα κλειδιά, ελέγξτε τη σελίδα [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

Τα iButtons μπορούν να επιτεθούν με το Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
