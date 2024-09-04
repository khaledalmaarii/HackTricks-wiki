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


## Improve your Wireshark skills

### Tutorials

The following tutorials are amazing to learn some cool basic tricks:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Klikając na _**Analyze** --> **Expert Information**_ uzyskasz **przegląd** tego, co dzieje się w analizowanych pakietach:

![](<../../../.gitbook/assets/image (256).png>)

**Resolved Addresses**

Pod _**Statistics --> Resolved Addresses**_ możesz znaleźć kilka **informacji**, które zostały "**rozwiązane**" przez Wireshark, takich jak port/transport do protokołu, MAC do producenta itp. Interesujące jest wiedzieć, co jest zaangażowane w komunikację.

![](<../../../.gitbook/assets/image (893).png>)

**Protocol Hierarchy**

Pod _**Statistics --> Protocol Hierarchy**_ możesz znaleźć **protokoły** **zaangażowane** w komunikację oraz dane na ich temat.

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

Pod _**Statistics --> Conversations**_ możesz znaleźć **podsumowanie rozmów** w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (453).png>)

**Endpoints**

Pod _**Statistics --> Endpoints**_ możesz znaleźć **podsumowanie punktów końcowych** w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (896).png>)

**DNS info**

Pod _**Statistics --> DNS**_ możesz znaleźć statystyki dotyczące przechwyconego zapytania DNS.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Graph**

Pod _**Statistics --> I/O Graph**_ możesz znaleźć **wykres komunikacji.**

![](<../../../.gitbook/assets/image (992).png>)

### Filters

Tutaj możesz znaleźć filtry Wireshark w zależności od protokołu: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Inne interesujące filtry:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP i początkowy ruch HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP i początkowy ruch HTTPS + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP i początkowy ruch HTTPS + TCP SYN + zapytania DNS

### Search

Jeśli chcesz **wyszukiwać** **treść** wewnątrz **pakietów** sesji, naciśnij _CTRL+f_. Możesz dodać nowe warstwy do głównego paska informacyjnego (Nr, Czas, Źródło itp.) naciskając prawy przycisk i następnie edytując kolumnę.

### Free pcap labs

**Ćwicz z darmowymi wyzwaniami:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Możesz dodać kolumnę, która pokazuje nagłówek Host HTTP:

![](<../../../.gitbook/assets/image (639).png>)

I kolumnę, która dodaje nazwę serwera z inicjującego połączenia HTTPS (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

W obecnym Wireshark zamiast `bootp` musisz szukać `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### From NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Naciśnij _Edit_ i dodaj wszystkie dane serwera oraz klucz prywatny (_IP, Port, Protokół, Plik klucza i hasło_)

### Decrypting https traffic with symmetric session keys

Zarówno Firefox, jak i Chrome mają możliwość rejestrowania kluczy sesji TLS, które można wykorzystać z Wireshark do odszyfrowania ruchu TLS. Umożliwia to szczegółową analizę zabezpieczonej komunikacji. Więcej informacji na temat tego, jak przeprowadzić to odszyfrowanie, można znaleźć w przewodniku na stronie [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Aby to wykryć, przeszukaj środowisko w poszukiwaniu zmiennej `SSLKEYLOGFILE`

Plik z kluczami współdzielonymi będzie wyglądał tak:

![](<../../../.gitbook/assets/image (820).png>)

Aby zaimportować to do Wireshark, przejdź do _edit > preference > protocol > ssl > i zaimportuj to w (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (989).png>)

## ADB communication

Wyodrębnij APK z komunikacji ADB, gdzie APK został wysłany:
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
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
