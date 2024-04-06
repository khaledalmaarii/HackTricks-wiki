# Mbinu za Wireshark

## Mbinu za Wireshark

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Boresha ujuzi wako wa Wireshark

### Mafunzo

Mafunzo yafuatayo ni mazuri kujifunza mbinu za msingi za kushangaza:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Taarifa Zilizochambuliwa

**Taarifa za Wataalamu**

Kwa kubonyeza _**Analyze** --> **Expert Information**_ utapata **muhtasari** wa kinachoendelea kwenye pakiti zilizochambuliwa:

![](<../../../.gitbook/assets/image (570).png>)

**Anwani Zilizotatuliwa**

Chini ya _**Statistics --> Resolved Addresses**_ unaweza kupata taarifa kadhaa ambazo zilitatuliwa na wireshark kama vile bandari/usalama hadi itifaki, MAC hadi mtengenezaji, nk. Ni muhimu kujua ni nini kinahusika katika mawasiliano.

![](<../../../.gitbook/assets/image (571).png>)

**Muundo wa Itifaki**

Chini ya _**Statistics --> Protocol Hierarchy**_ unaweza kupata **itifaki** zinazohusika katika mawasiliano na data kuhusu hizo.

![](<../../../.gitbook/assets/image (572).png>)

**Mazungumzo**

Chini ya _**Statistics --> Conversations**_ unaweza kupata **muhtasari wa mazungumzo** katika mawasiliano na data kuhusu hayo.

![](<../../../.gitbook/assets/image (573).png>)

**Vipengele vya Mwisho**

Chini ya _**Statistics --> Endpoints**_ unaweza kupata **muhtasari wa vipengele vya mwisho** katika mawasiliano na data kuhusu kila kimoja.

![](<../../../.gitbook/assets/image (575).png>)

**Taarifa za DNS**

Chini ya _**Statistics --> DNS**_ unaweza kupata takwimu kuhusu ombi la DNS lililorekodiwa.

![](<../../../.gitbook/assets/image (577).png>)

**Grafu ya I/O**

Chini ya _**Statistics --> I/O Graph**_ unaweza kupata **grafu ya mawasiliano**.

![](<../../../.gitbook/assets/image (574).png>)

### Vichujio

Hapa unaweza kupata vichujio vya wireshark kulingana na itifaki: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Vichujio vingine vya kuvutia:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Trafiki ya HTTP na HTTPS ya awali
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Trafiki ya HTTP na HTTPS ya awali + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Trafiki ya HTTP na HTTPS ya awali + TCP SYN + ombi za DNS

### Tafuta

Ikiwa unataka **kutafuta** **maudhui** ndani ya **pakiti** za vikao bonyeza _CTRL+f_. Unaweza kuongeza safu mpya kwenye mstari wa habari kuu (Nambari, Wakati, Chanzo, nk.) kwa kubonyeza kitufe cha kulia na kisha kuhariri safu.

### Maabara za pcap za bure

**Jifunze kwa vitendo na changamoto za bure za: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## Kutambua Kikoa

Unaweza kuongeza safu inayoonyesha kichwa cha mwenyeji wa HTTP:

![](<../../../.gitbook/assets/image (403).png>)

Na safu ambayo inaongeza jina la seva kutoka kwa uhusiano wa HTTPS unaosababisha (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Kutambua majina ya mwenyeji wa ndani

### Kutoka kwa DHCP

Kwenye Wireshark ya sasa badala ya `bootp` unahitaji kutafuta `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Kutoka kwa NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Kufichua TLS

### Kufichua trafiki ya https na ufunguo binafsi wa seva

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Bonyeza _Edit_ na ongeza data yote ya seva na ufunguo binafsi (_IP, Port, Itifaki, Faili ya ufunguo na nenosiri_)

### Kufichua trafiki ya https na funguo za kikao za usawa

Firefox na Chrome zote zina uwezo wa kurekodi funguo za kikao za TLS, ambazo zinaweza kutumika na Wireshark kufichua trafiki ya TLS. Hii inaruhusu uchambuzi wa kina wa mawasiliano salama. Maelezo zaidi juu ya jinsi ya kufanya ufichuzi huu yanaweza kupatikana kwenye mwongozo kwenye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Ili kugundua hii, tafuta ndani ya mazingira kwa kwenye kipengele cha `SSLKEYLOGFILE`

Faili ya funguo zilizoshirikiwa itaonekana kama hii:

![](<../../../.gitbook/assets/image (99).png>)

Ili kuimporti hii kwenye wireshark nenda kwa \_edit > preference > protocol > ssl > na iingize kwenye (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

## Mawasiliano ya ADB

Changanua APK kutoka kwa mawasiliano ya ADB ambapo APK ilitumwa:
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
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
