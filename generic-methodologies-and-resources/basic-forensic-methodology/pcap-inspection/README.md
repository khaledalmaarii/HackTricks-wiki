# Pcap Inspekcija

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljalište za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Napomena o **PCAP** vs **PCAPNG**: postoje dve verzije PCAP formata datoteka; **PCAPNG je noviji i nije podržan od svih alata**. Možda ćete morati da konvertujete datoteku iz PCAPNG u PCAP koristeći Wireshark ili neki drugi kompatibilni alat, kako biste mogli da radite s njom u nekim drugim alatima.
{% endhint %}

## Online alati za pcaps

* Ako je zaglavlje vašeg pcap-a **pokvareno**, trebali biste pokušati da ga **popravite** koristeći: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Izvucite **informacije** i tražite **malver** unutar pcap-a na [**PacketTotal**](https://packettotal.com)
* Tražite **malicioznu aktivnost** koristeći [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
* **Potpuna pcap analiza iz pregledača na** [**https://apackets.com/**](https://apackets.com/)

## Izvlačenje informacija

Sledeći alati su korisni za izvlačenje statistike, datoteka itd.

### Wireshark

{% hint style="info" %}
**Ako planirate da analizirate PCAP, osnovno je da znate kako da koristite Wireshark**
{% endhint %}

Možete pronaći neke Wireshark trikove u:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

Pcap analiza iz pregledača.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(samo linux)_ može **analizirati** **pcap** i izvući informacije iz njega. Na primer, iz pcap datoteke Xplico, izvlači svaku email poruku (POP, IMAP i SMTP protokoli), sve HTTP sadržaje, svaki VoIP poziv (SIP), FTP, TFTP, itd.

**Instalirajte**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Pokreni**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Access to _**127.0.0.1:9876**_ with credentials _**xplico:xplico**_

Then create a **new case**, create a **new session** inside the case and **upload the pcap** file.

### NetworkMiner

Kao Xplico, to je alat za **analizu i ekstrakciju objekata iz pcaps**. Ima besplatnu verziju koju možete **preuzeti** [**ovde**](https://www.netresec.com/?page=NetworkMiner). Radi na **Windows**.\
Ovaj alat je takođe koristan za dobijanje **druge analizirane informacije** iz paketa kako bi se moglo brže saznati šta se dešava.

### NetWitness Investigator

Možete preuzeti [**NetWitness Investigator odavde**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Radi na Windows)**.\
Ovo je još jedan koristan alat koji **analizira pakete** i sortira informacije na koristan način da bi se **znalo šta se dešava unutra**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Ekstrakcija i kodiranje korisničkih imena i lozinki (HTTP, FTP, Telnet, IMAP, SMTP...)
* Ekstrakcija autentifikacionih hash-ova i njihovo razbijanje koristeći Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Izrada vizuelnog dijagrama mreže (Mrežni čvorovi i korisnici)
* Ekstrakcija DNS upita
* Rekonstrukcija svih TCP i UDP sesija
* File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Ako **tražite** **nešto** unutar pcap-a, možete koristiti **ngrep**. Evo primera koji koristi glavne filtre:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Korišćenje uobičajenih tehnika carving-a može biti korisno za ekstrakciju fajlova i informacija iz pcap-a:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Capturing credentials

Možete koristiti alate kao što su [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) za parsiranje kredencijala iz pcap-a ili sa aktivnog interfejsa.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija cyberbezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljalište za profesionalce iz tehnologije i cyberbezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Check Exploits/Malware

### Suricata

**Instalirajte i postavite**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Proveri pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) je alat koji

* Čita PCAP datoteku i ekstrahuje Http tokove.
* gzip dekompresuje sve kompresovane tokove
* Skenira svaku datoteku sa yara
* Piše report.txt
* Opcionalno čuva odgovarajuće datoteke u direktorijum

### Malware Analysis

Proverite da li možete pronaći bilo koji otisak poznatog malvera:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) je pasivni, open-source analizator mrežnog saobraćaja. Mnogi operateri koriste Zeek kao Mrežni sigurnosni monitor (NSM) za podršku istragama sumnjive ili zlonamerne aktivnosti. Zeek takođe podržava širok spektar zadataka analize saobraćaja van domena sigurnosti, uključujući merenje performansi i rešavanje problema.

U suštini, logovi koje kreira `zeek` nisu **pcaps**. Stoga ćete morati da koristite **druge alate** za analizu logova gde se nalaze **informacije** o pcaps. 

### Connections Info
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
### DNS informacije
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
## Ostali trikovi analize pcap-a

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

[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljalište za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
