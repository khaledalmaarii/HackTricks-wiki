# Ukaguzi wa Pcap

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa ** lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila nidhamu.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Taarifa kuhusu **PCAP** dhidi ya **PCAPNG**: kuna matoleo mawili ya muundo wa faili ya PCAP; **PCAPNG ni mpya na haitegemezwi na zana zote**. Unaweza kuhitaji kubadilisha faili kutoka PCAPNG kwenda PCAP kwa kutumia Wireshark au zana nyingine inayoweza kufanya kazi nayo kwenye zana nyingine.
{% endhint %}

## Zana za mtandaoni kwa pcaps

* Ikiwa kichwa cha pcap yako kime **haribika** unapaswa kujaribu **kusahihisha** kwa kutumia: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Chunguza **taarifa** na tafuta **programu hasidi** ndani ya pcap kwenye [**PacketTotal**](https://packettotal.com)
* Tafuta **shughuli za uovu** kwa kutumia [**www.virustotal.com**](https://www.virustotal.com) na [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Chunguza Taarifa

Zana zifuatazo ni muhimu kutoa takwimu, faili, nk.

### Wireshark

{% hint style="info" %}
**Ikiwa unataka kuchambua PCAP unapaswa kimsingi kujua jinsi ya kutumia Wireshark**
{% endhint %}

Unaweza kupata mbinu kadhaa za Wireshark katika:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(tu linux)_ inaweza **kuchambua** pcap na kutoa taarifa kutoka kwake. Kwa mfano, kutoka kwa faili ya pcap, Xplico, hutoa kila barua pepe (itifaki za POP, IMAP, na SMTP), yaliyomo yote ya HTTP, kila simu ya VoIP (SIP), FTP, TFTP, na kadhalika.

**Sakinisha**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Endesha**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Fikia _**127.0.0.1:9876**_ na sifa za _**xplico:xplico**_

Kisha tengeneza **kisa kipya**, tengeneza **kikao kipya** ndani ya kisa na **pakia faili ya pcap**.

### NetworkMiner

Kama Xplico ni chombo cha **uchambuzi na kuchimbua vitu kutoka kwa pcaps**. Ina toleo la bure ambalo unaweza **kupakua** [**hapa**](https://www.netresec.com/?page=NetworkMiner). Inafanya kazi na **Windows**.\
Chombo hiki pia ni muhimu kupata **habari nyingine zilizochambuliwa** kutoka kwa pakiti ili kuweza kujua kilichokuwa kikiendelea kwa njia **haraka**.

### NetWitness Investigator

Unaweza kupakua [**NetWitness Investigator kutoka hapa**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Inafanya kazi kwenye Windows)**.\
Hii ni chombo kingine muhimu ambacho **huchambua pakiti** na kupanga habari kwa njia inayofaa ili **kujua kinachoendelea ndani**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Kuchimbua na kuweka maneno ya mtumiaji na nywila (HTTP, FTP, Telnet, IMAP, SMTP...)
* Kuchimbua alama za uwakilishi na kuzivunja kwa kutumia Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Jenga ramani ya mtandao ya kuona (Vituo vya mtandao & watumiaji)
* Kuchimbua maswali ya DNS
* Rekebisha vikao vyote vya TCP & UDP
* Ukataji wa Faili

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Ikiwa unatafuta kitu ndani ya pcap unaweza kutumia ngrep. Hapa kuna mfano wa kutumia filters kuu:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Ukataji

Kutumia mbinu za kawaida za ukataji inaweza kuwa na manufaa kutoa faili na habari kutoka kwa pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kukamata siri

Unaweza kutumia zana kama [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) kuchambua siri kutoka kwa pcap au interface ya moja kwa moja.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa ** lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa mkutano wa joto kwa wataalamu wa teknolojia na usalama wa mtandao katika kila nidhamu.

{% embed url="https://www.rootedcon.com/" %}

## Angalia Exploits/Malware

### Suricata

**Sakinisha na weka**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Angalia pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) ni chombo ambacho

* Huisoma Faili ya PCAP na Kutoa Mtiririko wa Http.
* gzip hupunguza mtiririko wowote uliopimwa
* Inachunguza kila faili na yara
* Huiandika ripoti.txt
* Kwa hiari huihifadhi faili zinazolingana kwenye Dir

### Uchambuzi wa Programu Hasidi

Angalia ikiwa unaweza kupata alama yoyote ya programu hasidi inayojulikana:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ni mtambulishaji wa trafiki wa mtandao wa chanzo wazi na wa kupitisha. Wafanyabiashara wengi hutumia Zeek kama Mfuatiliaji wa Usalama wa Mtandao (NSM) kusaidia uchunguzi wa shughuli za shaka au zenye nia mbaya. Zeek pia inasaidia anuwai kubwa ya kazi za uchambuzi wa trafiki zaidi ya uwanja wa usalama, ikiwa ni pamoja na upimaji wa utendaji na kutatua matatizo.

Kimsingi, magogo yanayoundwa na `zeek` sio **pcaps**. Kwa hivyo utahitaji kutumia **zana zingine** kuchambua magogo ambapo **habari** kuhusu pcaps zipo.
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
### Taarifa za DNS
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
## Mbinu zingine za uchambuzi wa pcap

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

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa ** lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila nidhamu.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Jifunze & zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
