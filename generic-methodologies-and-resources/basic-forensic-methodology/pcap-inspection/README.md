# Pcap Inspeksie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteit-gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
'n Nota oor **PCAP** vs **PCAPNG**: daar is twee weergawes van die PCAP-lêerformaat; **PCAPNG is nuwer en nie deur al die gereedskap ondersteun nie**. Jy mag 'n lêer van PCAPNG na PCAP moet omskakel met Wireshark of 'n ander geskikte gereedskap, om daarmee te werk in ander gereedskap.
{% endhint %}

## Aanlyn gereedskap vir pcaps

* As die kop van jou pcap **beskadig** is, moet jy probeer om dit te **herstel** met: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Ontgin **inligting** en soek vir **malware** binne 'n pcap in [**PacketTotal**](https://packettotal.com)
* Soek na **skadelike aktiwiteit** deur gebruik te maak van [**www.virustotal.com**](https://www.virustotal.com) en [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Ontgin Inligting

Die volgende gereedskap is nuttig om statistieke, lêers, ens. te ontsluit.

### Wireshark

{% hint style="info" %}
**As jy 'n PCAP gaan analiseer, moet jy basies weet hoe om Wireshark te gebruik**
{% endhint %}

Jy kan 'n paar Wireshark-truuks vind in:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(slegs linux)_ kan 'n **pcap** analiseer en inligting daaruit onttrek. Byvoorbeeld, van 'n pcap-lêer onttrek Xplico elke e-pos (POP, IMAP, en SMTP-protokolle), alle HTTP-inhoud, elke VoIP-oproep (SIP), FTP, TFTP, ensovoorts.

**Installeer**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Hardloop**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Toegang tot _**127.0.0.1:9876**_ met geloofsbriewe _**xplico:xplico**_

Skep dan 'n **nuwe saak**, skep 'n **nuwe sessie** binne die saak en **laai die pcap-lêer op**.

### NetworkMiner

Soos Xplico is dit 'n instrument om **analiseer en voorwerpe uit pcaps te onttrek**. Dit het 'n gratis weergawe wat jy kan **aflaai** [**hier**](https://www.netresec.com/?page=NetworkMiner). Dit werk met **Windows**.\
Hierdie instrument is ook nuttig om **ander inligting geanaliseer** te kry uit die pakkies om te weet wat in 'n **vinniger** manier gebeur het.

### NetWitness Investigator

Jy kan [**NetWitness Investigator hier aflaai**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Dit werk in Windows)**.\
Dit is 'n ander nuttige instrument wat **die pakkies analiseer** en die inligting op 'n nuttige manier **sorteer om te weet wat binne gebeur**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Uitpak en enkodeer gebruikersname en wagwoorde (HTTP, FTP, Telnet, IMAP, SMTP...)
* Haal outentiseringshasse uit en kraak hulle met Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Bou 'n visuele netwerkdiagram (Netwerknodes & gebruikers)
* Haal DNS-navrae uit
* Herkonstrueer alle TCP- en UDP-sessies
* Lêer uitsnyding

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

As jy **iets** binne die pcap **soek**, kan jy **ngrep** gebruik. Hier is 'n voorbeeld wat die hooffilters gebruik:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Uithol

Die gebruik van algemene uithol tegnieke kan nuttig wees om lêers en inligting uit die pcap te onttrek:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Vang van geloofsbriewe

Jy kan gereedskap soos [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) gebruik om geloofsbriewe uit 'n pcap of 'n lewende koppelvlak te ontled.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Kontroleer Uitbuitings/Malware

### Suricata

**Installeer en stel op**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Kyk na pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) is 'n gereedskap wat

* 'n PCAP-lêer lees en HTTP-strome onttrek.
* gzip-deflate enige saamgedrukte strome
* Skandeer elke lêer met yara
* Skryf 'n report.txt
* Opsioneel stoor ooreenstemmende lêers na 'n Dir

### Malware-analise

Kyk of jy enige vingerafdruk van 'n bekende malware kan vind:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) is 'n passiewe, oopbron-netwerkverkeerontleder. Baie operateurs gebruik Zeek as 'n Netwerksekuriteitsmonitor (NSM) om ondersoeke van verdagte of skadelike aktiwiteit te ondersteun. Zeek ondersteun ook 'n wye reeks verkeersontledingstake buite die sekuriteitsdomein, insluitend prestasiemetings en foutoplossing.

Basies geskep deur `zeek` se logboeke is nie **pcaps** nie. Daarom sal jy **ander gereedskap** moet gebruik om die logboeke te analiseer waar die **inligting** oor die pcaps is.

### Verbindingsinligting
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
### DNS inligting
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
## Ander pcap-analise truuks

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

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
