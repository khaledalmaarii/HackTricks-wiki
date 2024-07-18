# Wireshark tricks

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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya kutafuta inayotumiwa na **dark-web** ambayo inatoa kazi za **bure** kuangalia kama kampuni au wateja wake wamekuwa **compromised** na **stealer malwares**.

Lengo lao kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulizi ya ransomware yanayotokana na malware inayopora taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao kwa **bure** kwenye:

{% embed url="https://whiteintel.io" %}

***

## Improve your Wireshark skills

### Tutorials

Mafunzo yafuatayo ni mazuri kujifunza mbinu za msingi:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Kubofya kwenye _**Analyze** --> **Expert Information**_ utapata **muonekano** wa kile kinachotokea katika pakiti **zilizochambuliwa**:

![](<../../../.gitbook/assets/image (256).png>)

**Resolved Addresses**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata **taarifa** kadhaa ambazo zimekuwa "**resolved**" na wireshark kama port/transport hadi protocol, MAC hadi mtengenezaji, nk. Ni ya kuvutia kujua kile kinachohusika katika mawasiliano.

![](<../../../.gitbook/assets/image (893).png>)

**Protocol Hierarchy**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **protocols** **zinazo husika** katika mawasiliano na data kuhusu hizo.

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mazungumzo** katika mawasiliano na data kuhusu hizo.

![](<../../../.gitbook/assets/image (453).png>)

**Endpoints**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa endpoints** katika mawasiliano na data kuhusu kila moja yao.

![](<../../../.gitbook/assets/image (896).png>)

**DNS info**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililokamatwa.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Graph**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano.**

![](<../../../.gitbook/assets/image (992).png>)

### Filters

Hapa unaweza kupata chujio za wireshark kulingana na protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Chujio zingine za kuvutia:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP na trafiki ya mwanzo ya HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP na trafiki ya mwanzo ya HTTPS + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP na trafiki ya mwanzo ya HTTPS + TCP SYN + maombi ya DNS

### Search

Ikiwa unataka **kutafuta** **maudhui** ndani ya **pakiti** za vikao bonyeza _CTRL+f_. Unaweza kuongeza tabaka mpya kwenye bar ya habari kuu (No., Wakati, Chanzo, nk.) kwa kubonyeza kitufe cha kulia na kisha kuhariri safu.

### Free pcap labs

**Fanya mazoezi na changamoto za bure za:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Unaweza kuongeza safu inayonyesha kichwa cha HTTP cha Host:

![](<../../../.gitbook/assets/image (639).png>)

Na safu inayoongeza jina la Server kutoka kwa muunganisho wa HTTPS unaoanzisha (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

Katika Wireshark ya sasa badala ya `bootp` unahitaji kutafuta `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### From NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Bonyeza _Edit_ na ongeza data zote za server na funguo binafsi (_IP, Port, Protocol, Key file na password_)

### Decrypting https traffic with symmetric session keys

Firefox na Chrome zina uwezo wa kurekodi funguo za kikao za TLS, ambazo zinaweza kutumika na Wireshark kufungua trafiki ya TLS. Hii inaruhusu uchambuzi wa kina wa mawasiliano salama. Maelezo zaidi juu ya jinsi ya kufanya ufunguo huu yanaweza kupatikana katika mwongozo kwenye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Ili kugundua hii tafuta ndani ya mazingira kwa variable `SSLKEYLOGFILE`

Faili ya funguo zilizoshirikiwa itakuwa na muonekano huu:

![](<../../../.gitbook/assets/image (820).png>)

Ili kuingiza hii katika wireshark nenda kwa \_edit > preference > protocol > ssl > na uingize katika (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (989).png>)

## ADB communication

Toa APK kutoka kwa mawasiliano ya ADB ambapo APK ilitumwa:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya kutafuta inayotumiwa na **dark-web** ambayo inatoa kazi za **bure** kuangalia ikiwa kampuni au wateja wake wamekuwa **compromised** na **stealer malwares**.

Lengo lao kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulizi ya ransomware yanayotokana na malware inayopora taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao kwa **bure** kwenye:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
