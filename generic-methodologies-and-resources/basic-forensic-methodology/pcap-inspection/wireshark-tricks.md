# Mbinu za Wireshark

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malwares za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** hapa:

{% embed url="https://whiteintel.io" %}

---

## Boresha Ujuzi wako wa Wireshark

### Mafunzo

Mafunzo yafuatayo ni mazuri kujifunza mbinu za msingi za kuvutia:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa Zilizochambuliwa

**Taarifa za Mtaalam**

Kwa kubonyeza _**Analyze** --> **Expert Information**_ utapata **muhtasari** wa kinachoendelea kwenye pakiti zilizochambuliwa:

![](<../../../.gitbook/assets/image (253).png>)

**Anwani Zilizotatuliwa**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata taarifa kadhaa zilizotatuliwa na wireshark kama vile bandari/mtandao hadi itifaki, MAC hadi mtengenezaji, n.k. Ni muhimu kujua ni nini kinahusika katika mawasiliano.

![](<../../../.gitbook/assets/image (890).png>)

**Mfumo wa Itifaki**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **itifaki** zinazohusika katika mawasiliano na data kuhusu hizo.

![](<../../../.gitbook/assets/image (583).png>)

**Mazungumzo**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mazungumzo** katika mawasiliano na data kuhusu hayo.

![](<../../../.gitbook/assets/image (450).png>)

**Vipengele vya Mwisho**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa vipengele vya mwisho** katika mawasiliano na data kuhusu kila moja.

![](<../../../.gitbook/assets/image (893).png>)

**Taarifa za DNS**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililorekodiwa.

![](<../../../.gitbook/assets/image (1060).png>)

**Grafu ya I/O**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano.**

![](<../../../.gitbook/assets/image (989).png>)

### Vichujio

Hapa unaweza kupata kichujio cha wireshark kulingana na itifaki: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Vichujio vingine vya kuvutia:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Trafiki ya HTTP na HTTPS ya awali
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Trafiki ya HTTP na HTTPS ya awali + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Trafiki ya HTTP na HTTPS ya awali + TCP SYN + Ombi za DNS

### Tafuta

Ikiwa unataka **tafuta** **maudhui** ndani ya **pakiti** za vikao bonyeza _CTRL+f_. Unaweza kuongeza safu mpya kwenye bar ya habari kuu (Namba, Wakati, Chanzo, n.k.) kwa kubonyeza kitufe cha kulia na kisha hariri safu.

### Maabara za pcap za Bure

**Jifunze na changamoto za bure za:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Kutambua Domains

Unaweza kuongeza safu inayoonyesha Kichwa cha HTTP cha Mwenyeji:

![](<../../../.gitbook/assets/image (635).png>)

Na safu inayoongeza jina la Seva kutoka kwa uunganisho wa HTTPS wa kuanzisha (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Kutambua majina ya mwenyeji wa ndani

### Kutoka kwa DHCP

Kwenye Wireshark ya sasa badala ya `bootp` unahitaji kutafuta `DHCP`

![](<../../../.gitbook/assets/image (1010).png>)

### Kutoka kwa NBNS

![](<../../../.gitbook/assets/image (1000).png>)

## Kufichua TLS

### Kufichua trafiki ya https na ufunguo binafsi wa seva

_badilisha>mapendeleo>itifaki>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

Bonyeza _Hariri_ na ongeza data yote ya seva na ufunguo binafsi (_IP, Bandari, Itifaki, Faili la ufunguo na nenosiri_)

### Kufichua trafiki ya https na funguo za kikao za usawa

Firefox na Chrome zote zina uwezo wa kurekodi funguo za kikao za TLS, ambazo zinaweza kutumika na Wireshark kufichua trafiki ya TLS. Hii inaruhusu uchambuzi wa kina wa mawasiliano salama. Maelezo zaidi juu ya jinsi ya kufanya ufichuzi huu yanaweza kupatikana kwenye mwongozo kwenye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Ili kugundua hii, tafuta ndani ya mazingira kwa kivinjari `SSLKEYLOGFILE`

Faili ya funguo za pamoja itaonekana kama hii:

![](<../../../.gitbook/assets/image (817).png>)

Kuagiza hii kwenye wireshark enda kwa \_hariri > mapendeleo > itifaki > ssl > na iagize kwenye (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (986).png>)
## Mawasiliano ya ADB

Chambua APK kutoka kwenye mawasiliano ya ADB ambapo APK ilitumwa:
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

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malwares za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
