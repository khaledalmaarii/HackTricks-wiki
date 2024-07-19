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


# SELinux σε Κοντέινερ

[Εισαγωγή και παράδειγμα από τα έγγραφα της redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) είναι ένα **σύστημα** **ετικετοποίησης**. Κάθε **διαδικασία** και κάθε **αντικείμενο** συστήματος αρχείων έχει μια **ετικέτα**. Οι πολιτικές SELinux καθορίζουν κανόνες σχετικά με το τι μπορεί να κάνει μια **ετικέτα διαδικασίας** με όλες τις άλλες ετικέτες στο σύστημα.

Οι μηχανές κοντέινερ εκκινούν **διαδικασίες κοντέινερ με μια μόνο περιορισμένη ετικέτα SELinux**, συνήθως `container_t`, και στη συνέχεια ορίζουν το κοντέινερ μέσα στο κοντέινερ να έχει την ετικέτα `container_file_t`. Οι κανόνες πολιτικής SELinux βασικά λένε ότι οι **διαδικασίες `container_t` μπορούν μόνο να διαβάζουν/γράφουν/εκτελούν αρχεία με ετικέτα `container_file_t`**. Εάν μια διαδικασία κοντέινερ διαφύγει από το κοντέινερ και προσπαθήσει να γράψει περιεχόμενο στον οικοδεσπότη, ο πυρήνας του Linux αρνείται την πρόσβαση και επιτρέπει μόνο στη διαδικασία κοντέινερ να γράψει σε περιεχόμενο με ετικέτα `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux Users

Υπάρχουν χρήστες SELinux εκτός από τους κανονικούς χρήστες Linux. Οι χρήστες SELinux είναι μέρος μιας πολιτικής SELinux. Κάθε χρήστης Linux αντιστοιχεί σε έναν χρήστη SELinux ως μέρος της πολιτικής. Αυτό επιτρέπει στους χρήστες Linux να κληρονομούν τους περιορισμούς και τους κανόνες και μηχανισμούς ασφαλείας που έχουν επιβληθεί στους χρήστες SELinux.

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
