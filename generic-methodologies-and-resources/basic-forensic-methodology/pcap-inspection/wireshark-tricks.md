# Wireshark trikovi

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


## Poboljšajte svoje veštine u Wireshark-u

### Tutorijali

Sledeći tutorijali su sjajni za učenje nekih cool osnovnih trikova:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizirane informacije

**Expert informacije**

Klikom na _**Analiziraj** --> **Expert informacije**_ dobićete **pregled** onoga što se dešava u **analiziranim** paketima:

![](<../../../.gitbook/assets/image (256).png>)

**Rešene adrese**

Pod _**Statistika --> Rešene adrese**_ možete pronaći nekoliko **informacija** koje je Wireshark "**rešio**", kao što su port/transport do protokola, MAC do proizvođača itd. Zanimljivo je znati šta je uključeno u komunikaciju.

![](<../../../.gitbook/assets/image (893).png>)

**Hijerarhija protokola**

Pod _**Statistika --> Hijerarhija protokola**_ možete pronaći **protokole** **uključene** u komunikaciju i podatke o njima.

![](<../../../.gitbook/assets/image (586).png>)

**Razgovori**

Pod _**Statistika --> Razgovori**_ možete pronaći **rezime razgovora** u komunikaciji i podatke o njima.

![](<../../../.gitbook/assets/image (453).png>)

**Krajnje tačke**

Pod _**Statistika --> Krajnje tačke**_ možete pronaći **rezime krajnjih tačaka** u komunikaciji i podatke o svakoj od njih.

![](<../../../.gitbook/assets/image (896).png>)

**DNS informacije**

Pod _**Statistika --> DNS**_ možete pronaći statistiku o uhvaćenim DNS zahtevima.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O graf**

Pod _**Statistika --> I/O graf**_ možete pronaći **graf komunikacije.**

![](<../../../.gitbook/assets/image (992).png>)

### Filteri

Ovde možete pronaći Wireshark filtere u zavisnosti od protokola: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Ostali zanimljivi filteri:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP i inicijalni HTTPS saobraćaj
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP i inicijalni HTTPS saobraćaj + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP i inicijalni HTTPS saobraćaj + TCP SYN + DNS zahtevi

### Pretraga

Ako želite da **pretražujete** **sadržaj** unutar **paketa** sesija pritisnite _CTRL+f_. Možete dodati nove slojeve u glavnu informativnu traku (Br., Vreme, Izvor itd.) pritiskom desnog dugmeta i zatim uređivanjem kolone.

### Besplatni pcap laboratoriji

**Vežbajte sa besplatnim izazovima:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifikacija domena

Možete dodati kolonu koja prikazuje Host HTTP zaglavlje:

![](<../../../.gitbook/assets/image (639).png>)

I kolonu koja dodaje ime servera iz inicijalne HTTPS veze (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifikacija lokalnih imena hostova

### Iz DHCP

U trenutnom Wireshark-u umesto `bootp` treba da tražite `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### Iz NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Dekriptovanje TLS

### Dekriptovanje https saobraćaja sa privatnim ključem servera

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Pritisnite _Edit_ i dodajte sve podatke o serveru i privatnom ključu (_IP, Port, Protokol, Datoteka ključa i lozinka_)

### Dekriptovanje https saobraćaja sa simetričnim sesijskim ključevima

I Firefox i Chrome imaju mogućnost da beleže TLS sesijske ključeve, koji se mogu koristiti sa Wireshark-om za dekriptovanje TLS saobraćaja. Ovo omogućava dubinsku analizu sigurnih komunikacija. Više detalja o tome kako izvršiti ovo dekriptovanje može se naći u vodiču na [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Da biste to otkrili, pretražujte unutar okruženja za promenljivu `SSLKEYLOGFILE`

Datoteka deljenih ključeva će izgledati ovako:

![](<../../../.gitbook/assets/image (820).png>)

Da biste to uvezli u Wireshark, idite na _edit > preference > protocol > ssl > i uvezite to u (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (989).png>)

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
