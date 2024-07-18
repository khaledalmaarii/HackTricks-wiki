# Έλεγχος Pcap

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένας ζωντανός χώρος συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε πεδίο.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Σημείωση σχετικά με τα **PCAP** έναντι των **PCAPNG**: υπάρχουν δύο εκδόσεις του μορφή αρχείου PCAP. Το **PCAPNG είναι πιο πρόσφατο και δεν υποστηρίζεται από όλα τα εργαλεία**. Μπορεί να χρειαστεί να μετατρέψετε ένα αρχείο από PCAPNG σε PCAP χρησιμοποιώντας το Wireshark ή ένα άλλο συμβατό εργαλείο, για να μπορέσετε να το χρησιμοποιήσετε σε άλλα εργαλεία.
{% endhint %}

## Online εργαλεία για pcaps

* Αν η κεφαλίδα του pcap σας είναι **κατεστραμμένη** πρέπει να προσπαθήσετε να την **επισκευάσετε** χρησιμοποιώντας: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Εξαγωγή **πληροφοριών** και αναζήτηση για **κακόβουλο λογισμικό** μέσα σε ένα pcap στο [**PacketTotal**](https://packettotal.com)
* Αναζήτηση για **κακόβουλη δραστηριότητα** χρησιμοποιώντας το [**www.virustotal.com**](https://www.virustotal.com) και το [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Εξαγωγή Πληροφοριών

Τα παρακάτω εργαλεία είναι χρήσιμα για την εξαγωγή στατιστικών, αρχείων, κλπ.

### Wireshark

{% hint style="info" %}
**Εάν πρόκειται να αναλύσετε ένα PCAP, πρέπει ουσιαστικά να ξέρετε πώς να χρησιμοποιήσετε το Wireshark**
{% endhint %}

Μπορείτε να βρείτε μερικά κόλπα του Wireshark στο:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Πλαίσιο Xplico

Το [**Xplico** ](https://github.com/xplico/xplico)_(μόνο σε Linux)_ μπορεί να **αναλύσει** ένα **pcap** και να εξάγει πληροφορίες από αυτό. Για παράδειγμα, από ένα αρχείο pcap, το Xplico εξάγει κάθε email (πρωτόκολλα POP, IMAP και SMTP), όλο το περιεχόμενο HTTP, κάθε κλήση VoIP (SIP), FTP, TFTP, κ.λπ.

**Εγκατάσταση**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Εκτέλεση**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Πρόσβαση στο _**127.0.0.1:9876**_ με διαπιστευτήρια _**xplico:xplico**_

Στη συνέχεια δημιουργήστε ένα **νέο περιστατικό**, δημιουργήστε μια **νέα συνεδρία** μέσα στο περιστατικό και **ανεβάστε το αρχείο pcap**.

### NetworkMiner

Όπως το Xplico, είναι ένα εργαλείο για **ανάλυση και εξαγωγή αντικειμένων από pcaps**. Διαθέτει μια δωρεάν έκδοση που μπορείτε να **κατεβάσετε** [**εδώ**](https://www.netresec.com/?page=NetworkMiner). Λειτουργεί με **Windows**.\
Αυτό το εργαλείο είναι επίσης χρήσιμο για να αποκτήσετε **άλλες πληροφορίες αναλυμένες** από τα πακέτα προκειμένου να μπορείτε να γνωρίζετε τι συνέβαινε με **ταχύτερο** τρόπο.

### NetWitness Investigator

Μπορείτε να κατεβάσετε το [**NetWitness Investigator από εδώ**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Λειτουργεί σε Windows)**.\
Αυτό είναι ένα άλλο χρήσιμο εργαλείο που **αναλύει τα πακέτα** και τα ταξινομεί πληροφορίες με έναν χρήσιμο τρόπο για να **γνωρίζετε τι συμβαίνει μέσα**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Εξαγωγή και κωδικοποίηση ονομάτων χρηστών και κωδικών πρόσβασης (HTTP, FTP, Telnet, IMAP, SMTP...)
* Εξαγωγή καταλυτικών κωδικών πρόσβασης και αποκωδικοποίησή τους χρησιμοποιώντας το Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Δημιουργία οπτικού διαγράμματος δικτύου (Κόμβοι δικτύου & χρήστες)
* Εξαγωγή ερωτήσεων DNS
* Ανακατασκευή όλων των συνεδριών TCP & UDP
* Ανάκτηση αρχείων

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Αν **ψάχνετε** για **κάτι** μέσα στο αρχείο pcap μπορείτε να χρησιμοποιήσετε το **ngrep**. Εδώ υπάρχει ένα παράδειγμα χρησιμοποιώντας τα κύρια φίλτρα:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Σκαλισμός

Η χρήση συνηθισμένων τεχνικών σκαλίσματος μπορεί να είναι χρήσιμη για την εξαγωγή αρχείων και πληροφοριών από το αρχείο pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Καταγραφή διαπιστευτήριων

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) για την ανάλυση διαπιστευτηρίων από ένα αρχείο pcap ή μια ζωντανή διεπαφή.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο αποτελεί έναν ζωντανό χώρο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}

## Έλεγχος Εκμετάλλευσης/Κακόβουλου Λογισμικού

### Suricata

**Εγκατάσταση και ρύθμιση**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Έλεγχος pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) είναι ένα εργαλείο που

* Διαβάζει ένα αρχείο PCAP και εξάγει ροές Http.
* Αποσυμπιέζει gzip οποιεσδήποτε συμπιεσμένες ροές
* Σαρώνει κάθε αρχείο με το yara
* Γράφει ένα report.txt
* Αποθηκεύει προαιρετικά τα ταιριαστά αρχεία σε ένα φάκελο

### Ανάλυση Κακόβουλου Λογισμικού

Ελέγξτε αν μπορείτε να βρείτε οποιοδήποτε αποτύπωμα γνωστού κακόβουλου λογισμικού:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) είναι ένα παθητικό, ανοικτού κώδικα αναλυτής κίνησης δικτύου. Πολλοί χειριστές χρησιμοποιούν το Zeek ως Έλεγχο Ασφαλείας Δικτύου (NSM) για να υποστηρίξουν έρευνες επί ύποπτης ή κακόβουλης δραστηριότητας. Το Zeek υποστηρίζει επίσης μια ευρεία γκάμα εργασιών ανάλυσης κίνησης πέρα ​​από τον τομέα της ασφάλειας, συμπεριλαμβανομένης της μέτρησης απόδοσης και της επίλυσης προβλημάτων.

Βασικά, τα αρχεία καταγραφής που δημιουργούνται από το `zeek` δεν είναι **pcaps**. Συνεπώς, θα χρειαστείτε να χρησιμοποιήσετε **άλλα εργαλεία** για να αναλύσετε τα αρχεία καταγραφής όπου οι **πληροφορίες** σχετικά με τα pcaps βρίσκονται.
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### Πληροφορίες DNS
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## Άλλα κόλπα ανάλυσης pcap

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο αποτελεί έναν ζωντανό σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε πεδίο.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
