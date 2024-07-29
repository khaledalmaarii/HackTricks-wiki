# Weaponizing Distroless

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

## What is Distroless

Ένα distroless container είναι ένας τύπος container που **περιέχει μόνο τις απαραίτητες εξαρτήσεις για να τρέξει μια συγκεκριμένη εφαρμογή**, χωρίς κανένα επιπλέον λογισμικό ή εργαλεία που δεν απαιτούνται. Αυτά τα containers έχουν σχεδιαστεί για να είναι όσο το δυνατόν **ελαφρύτερα** και **ασφαλέστερα**, και στοχεύουν να **ελαχιστοποιήσουν την επιφάνεια επίθεσης** αφαιρώντας οποιαδήποτε περιττά στοιχεία.

Τα distroless containers χρησιμοποιούνται συχνά σε **παραγωγικά περιβάλλοντα όπου η ασφάλεια και η αξιοπιστία είναι πρωταρχικής σημασίας**.

Ορισμένα **παραδείγματα** **distroless containers** είναι:

* Παρέχονται από **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Παρέχονται από **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Ο στόχος της οπλοποίησης ενός distroless container είναι να μπορεί να **εκτελεί αυθαίρετους δυαδικούς κώδικες και payloads ακόμη και με τους περιορισμούς** που υπονοούνται από το **distroless** (έλλειψη κοινών δυαδικών κωδικών στο σύστημα) και επίσης προστασίες που συχνά βρίσκονται σε containers όπως **μόνο για ανάγνωση** ή **χωρίς εκτέλεση** στο `/dev/shm`.

### Through memory

Έρχεται κάποια στιγμή το 2023...

### Via Existing binaries

#### openssl

****[**Σε αυτή την ανάρτηση,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) εξηγείται ότι ο δυαδικός κώδικας **`openssl`** βρίσκεται συχνά σε αυτά τα containers, πιθανώς επειδή είναι **απαραίτητος** από το λογισμικό που πρόκειται να τρέξει μέσα στο container.


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
