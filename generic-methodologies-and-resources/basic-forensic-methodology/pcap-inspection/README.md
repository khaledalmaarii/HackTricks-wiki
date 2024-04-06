# Ukaguzi wa Pcap

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Taarifa kuhusu **PCAP** vs **PCAPNG**: kuna toleo mbili za muundo wa faili ya PCAP; **PCAPNG ni mpya na haishikwi na zana zote**. Unaweza kuhitaji kubadilisha faili kutoka PCAPNG kwenda PCAP kwa kutumia Wireshark au zana nyingine inayofaa, ili uweze kufanya kazi nayo kwenye zana nyingine.
{% endhint %}

## Zana za mtandaoni kwa pcaps

* Ikiwa kichwa cha pcap yako kime **haribika** unapaswa kujaribu **kurekebisha** kwa kutumia: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Chambua **taarifa** na tafuta **programu hasidi** ndani ya pcap kwenye [**PacketTotal**](https://packettotal.com)
* Tafuta **shughuli mbaya** kwa kutumia [**www.virustotal.com**](https://www.virustotal.com) na [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Chambua Taarifa

Zana zifuatazo ni muhimu kuchambua takwimu, faili, nk.

### Wireshark

{% hint style="info" %}
**Ikiwa unataka kuchambua PCAP lazima ujue jinsi ya kutumia Wireshark**
{% endhint %}

Unaweza kupata mbinu za Wireshark katika:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(tu kwenye linux)_ inaweza **kuchambua** pcap na kutoa taarifa kutoka kwake. Kwa mfano, kutoka kwenye faili ya pcap, Xplico inachambua kila barua pepe (itifaki za POP, IMAP, na SMTP), yaliyomo yote ya HTTP, kila wito wa VoIP (SIP), FTP, TFTP, na kadhalika.

**Sanidi**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Chalaza**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Pata ufikiaji wa _**127.0.0.1:9876**_ na sifa za kuingia _**xplico:xplico**_

Kisha tengeneza **kesi mpya**, tengeneza **kikao kipya** ndani ya kesi na **pakia faili ya pcap**.

### NetworkMiner

Kama Xplico, ni chombo cha **uchambuzi na uchimbaji wa vitu kutoka kwenye pcap**. Ina toleo la bure ambalo unaweza **kupakua** [**hapa**](https://www.netresec.com/?page=NetworkMiner). Inafanya kazi na **Windows**.\
Chombo hiki pia ni muhimu kupata **habari nyingine zilizochambuliwa** kutoka kwenye pakiti ili kuweza kujua kilichokuwa kinaendelea kwa njia **haraka**.

### NetWitness Investigator

Unaweza kupakua [**NetWitness Investigator hapa**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Inafanya kazi kwenye Windows)**.\
Hii ni chombo kingine muhimu ambacho **huchambua pakiti** na kusorti habari kwa njia inayoweza **kujua kinachoendelea ndani**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Kuchambua na kuweka alama majina ya mtumiaji na nywila (HTTP, FTP, Telnet, IMAP, SMTP...)
* Kuchimbua alama za uwakilishi na kuzivunja kwa kutumia Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Jenga ramani ya mtandao kwa njia ya kuona (Nodi za mtandao na watumiaji)
* Chimbua maswali ya DNS
* Rekebisha vikao vyote vya TCP na UDP
* Ukata faili

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Ikiwa unatafuta kitu ndani ya pcap unaweza kutumia ngrep. Hapa kuna mfano wa kutumia vichujio kuu:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Ukataji

Kutumia mbinu za kawaida za ukataji inaweza kuwa na manufaa katika kuchimbua faili na habari kutoka kwa pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kukamata siri

Unaweza kutumia zana kama [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) kuchambua siri kutoka kwa pcap au kiolesura hai.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi barani **Ulaya**. Kwa **malengo ya kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

## Angalia Mashambulizi/Malware

### Suricata

**Sakinisha na weka**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Angalia pcap**

---

**Introduction**

**Utangulizi**

When conducting a forensic investigation, analyzing network traffic can provide valuable insights into the activities and communications of a system or user. One common method of capturing and analyzing network traffic is through the use of packet capture (pcap) files. Pcap files contain recorded network traffic data, including the source and destination IP addresses, protocols used, and the contents of the packets themselves.

Wakati wa kufanya uchunguzi wa kiforensiki, uchambuzi wa trafiki ya mtandao unaweza kutoa ufahamu muhimu juu ya shughuli na mawasiliano ya mfumo au mtumiaji. Moja ya njia za kawaida za kukamata na kuchambua trafiki ya mtandao ni kupitia matumizi ya faili za kukamata pakiti (pcap). Faili za pcap zina data iliyorekodiwa ya trafiki ya mtandao, ikiwa ni pamoja na anwani za IP za chanzo na marudio, itifaki zilizotumika, na maudhui ya pakiti yenyewe.

---

**Inspecting Pcap Files**

**Kuchunguza Faili za Pcap**

To inspect a pcap file, you can use various tools and techniques to extract and analyze the network traffic data. Here are some common methods:

Kuchunguza faili ya pcap, unaweza kutumia zana na mbinu mbalimbali ili kuchambua na kuchanganua data ya trafiki ya mtandao. Hapa kuna njia kadhaa za kawaida:

1. Wireshark: Wireshark is a popular open-source network protocol analyzer that allows you to view and analyze pcap files. It provides a graphical interface for inspecting network traffic and offers various filters and analysis options.

   Wireshark: Wireshark ni kifaa maarufu cha uchambuzi wa itifaki ya mtandao ambacho kinakuruhusu kuona na kuchambua faili za pcap. Inatoa kiolesura cha picha kwa ajili ya kuchunguza trafiki ya mtandao na inatoa filta mbalimbali na chaguo za uchambuzi.

2. Tcpdump: Tcpdump is a command-line tool that allows you to capture and analyze network traffic. It can be used to read pcap files and extract information about the captured packets.

   Tcpdump: Tcpdump ni kifaa cha amri ambacho kinakuruhusu kukamata na kuchambua trafiki ya mtandao. Inaweza kutumika kusoma faili za pcap na kuchukua habari kuhusu pakiti zilizokamatwa.

3. Tshark: Tshark is a command-line version of Wireshark that allows you to analyze pcap files without the need for a graphical interface. It provides similar functionality to Wireshark but can be used in automated scripts or remote environments.

   Tshark: Tshark ni toleo la amri la Wireshark ambalo linakuruhusu kuchambua faili za pcap bila haja ya kiolesura cha picha. Inatoa kazi sawa na Wireshark lakini inaweza kutumika katika hati za kiotomatiki au mazingira ya mbali.

4. Network Forensics Tools: There are various network forensics tools available that specialize in analyzing pcap files. These tools often provide advanced analysis capabilities and can help identify patterns, anomalies, and potential security breaches.

   Zana za Kiforensiki ya Mtandao: Kuna zana mbalimbali za kiforensiki ya mtandao zinazopatikana ambazo zinajikita katika kuchambua faili za pcap. Zana hizi mara nyingi hutoa uwezo wa uchambuzi wa juu na zinaweza kusaidia kutambua mifumo, tofauti, na ukiukwaji wa usalama unaowezekana.

---

**Conclusion**

**Hitimisho**

Inspecting pcap files can be a valuable technique in forensic investigations, allowing you to gain insights into network activities and communications. By using tools like Wireshark, Tcpdump, Tshark, or specialized network forensics tools, you can extract and analyze the data within pcap files to uncover important information and potential security issues.

Kuchunguza faili za pcap inaweza kuwa njia muhimu katika uchunguzi wa kiforensiki, ikikuruhusu kupata ufahamu kuhusu shughuli na mawasiliano ya mtandao. Kwa kutumia zana kama Wireshark, Tcpdump, Tshark, au zana maalum za kiforensiki ya mtandao, unaweza kuchukua na kuchambua data ndani ya faili za pcap ili kugundua habari muhimu na masuala ya usalama yanayowezekana.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) ni zana ambayo

* Inasoma faili ya PCAP na kuchambua mito ya Http.
* gzip inapunguza mito iliyopakiwa
* Inachunguza kila faili na yara
* Inaandika ripoti.txt
* Kwa hiari, inahifadhi faili zinazolingana kwenye Dir

### Uchambuzi wa Programu Hasidi

Angalia ikiwa unaweza kupata alama yoyote ya programu hasidi inayojulikana:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ni zana ya uchambuzi wa trafiki ya mtandao isiyo ya kuingilia. Watoa huduma wengi hutumia Zeek kama Mfuatiliaji wa Usalama wa Mtandao (NSM) kuunga mkono uchunguzi wa shughuli za shaka au zenye nia mbaya. Zeek pia inasaidia aina mbalimbali za kazi za uchambuzi wa trafiki zaidi ya uwanja wa usalama, ikiwa ni pamoja na kupima utendaji na kutatua matatizo.

Kimsingi, magogo yanayotengenezwa na `zeek` sio **pcaps**. Kwa hivyo utahitaji kutumia **zana nyingine** kuchambua magogo ambapo **habari** kuhusu pcaps zipo.

### Habari za Uunganisho
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

DNS (Domain Name System) ni mfumo unaotumiwa kubadilisha majina ya kikoa kuwa anwani za IP. Katika uchunguzi wa kiforensiki, ukaguzi wa faili za pcap unaweza kutoa habari muhimu kuhusu shughuli za DNS.

Kuchunguza faili ya pcap kunaweza kufunua maelezo kama vile:

- Anwani za IP zinazohusiana na majina ya kikoa
- Majina ya kikoa yanayotumiwa na anwani za IP
- Muda wa maombi ya DNS na majibu
- Aina za rekodi za DNS zilizotumiwa (kama vile A, CNAME, MX, nk)
- Habari za kijiografia kuhusu anwani za IP (kama vile nchi, mji, nk)

Kwa kutumia habari hizi, wachunguzi wa kiforensiki wanaweza kufuatilia shughuli za mtandao, kugundua mifumo ya ukiukaji wa usalama, au kufuatilia mawasiliano ya mtu binafsi.
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
## Mbinu nyingine za uchambuzi wa pcap

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

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi huko **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
