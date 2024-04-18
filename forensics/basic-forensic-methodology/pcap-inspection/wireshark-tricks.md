# Trikovi sa Wireshark-om

## Trikovi sa Wireshark-om

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu podataka**.

Primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## Unapredite svoje veštine sa Wireshark-om

### Tutorijali

Sledeći tutorijali su sjajni za učenje nekih cool osnovnih trikova:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizirane informacije

**Ekspertske informacije**

Klikom na _**Analyze** --> **Expert Information**_ dobićete **pregled** onoga što se dešava u analiziranim paketima:

![](<../../../.gitbook/assets/image (570).png>)

**Rešene adrese**

Pod _**Statistics --> Resolved Addresses**_ možete pronaći nekoliko **informacija** koje je Wireshark "**rešio**" kao što su port/transport do protokola, MAC do proizvođača, itd. Korisno je znati šta je uključeno u komunikaciju.

![](<../../../.gitbook/assets/image (571).png>)

**Hijerarhija protokola**

Pod _**Statistics --> Protocol Hierarchy**_ možete pronaći **protokole** koji su **učestvovali** u komunikaciji i podatke o njima.

![](<../../../.gitbook/assets/image (572).png>)

**Konverzacije**

Pod _**Statistics --> Conversations**_ možete pronaći **rezime konverzacija** u komunikaciji i podatke o njima.

![](<../../../.gitbook/assets/image (573).png>)

**Krajnje tačke**

Pod _**Statistics --> Endpoints**_ možete pronaći **rezime krajnjih tačaka** u komunikaciji i podatke o svakoj od njih.

![](<../../../.gitbook/assets/image (575).png>)

**DNS informacije**

Pod _**Statistics --> DNS**_ možete pronaći statistike o uhvaćenim DNS zahtevima.

![](<../../../.gitbook/assets/image (577).png>)

**I/O Grafikon**

Pod _**Statistics --> I/O Graph**_ možete pronaći **grafikon komunikacije**.

![](<../../../.gitbook/assets/image (574).png>)

### Filteri

Ovde možete pronaći Wireshark filtere u zavisnosti od protokola: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Drugi interesantni filteri:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP i početni HTTPS saobraćaj
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP i početni HTTPS saobraćaj + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP i početni HTTPS saobraćaj + TCP SYN + DNS zahtevi

### Pretraga

Ako želite da **pretražujete** **sadržaj** unutar **paketa** sesija pritisnite _CTRL+f_. Možete dodati nove slojeve u glavnu informacionu traku (Br., Vreme, Izvor, itd.) pritiskom na desno dugme, a zatim na uređivanje kolone.

### Besplatne pcap laboratorije

**Vežbajte sa besplatnim izazovima na: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## Identifikacija domena

Možete dodati kolonu koja prikazuje Host HTTP zaglavlje:

![](<../../../.gitbook/assets/image (403).png>)

I kolonu koja dodaje ime servera sa inicijalne HTTPS veze (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifikacija lokalnih imena hostova

### Iz DHCP-a

U trenutnom Wireshark-u umesto `bootp` treba da tražite `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Iz NBNS-a

![](<../../../.gitbook/assets/image (405).png>)

## Dekriptovanje TLS-a

### Dekriptovanje https saobraćaja sa privatnim ključem servera

_izmeni>postavke>protokol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Pritisnite _Izmeni_ i dodajte sve podatke servera i privatnog ključa (_IP, Port, Protokol, Datoteka ključa i lozinka_)

### Dekriptovanje https saobraćaja sa simetričnim sesijskim ključevima

I Firefox i Chrome imaju mogućnost da beleže TLS sesijske ključeve, koji se mogu koristiti sa Wireshark-om za dekriptovanje TLS saobraćaja. Ovo omogućava dubinsku analizu sigurnih komunikacija. Više detalja o tome kako izvršiti ovu dekripciju možete pronaći u vodiču na [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Da biste ovo otkrili, pretražite okruženje za promenljivu `SSLKEYLOGFILE`

Datoteka deljenih ključeva će izgledati ovako:

![](<../../../.gitbook/assets/image (99).png>)

Da biste ovo uvezali u Wireshark idite na \_izmeni > postavke > protokol > ssl > i uvezite u (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)
## ADB komunikacija

Izvucite APK iz ADB komunikacije gde je APK poslat:
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
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web**-om koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade informacije**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
