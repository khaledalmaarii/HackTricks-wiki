# Sztuczki z Wireshark

## Sztuczki z Wireshark

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Popraw swoje umiejętności z Wireshark

### Tutoriale

Następujące tutoriale są niesamowite do nauki kilku fajnych podstawowych sztuczek:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizowane informacje

**Informacje eksperta**

Klikając na _**Analyze** --> **Expert Information**_ będziesz mieć **przegląd** tego, co dzieje się w **analizowanych** pakietach:

![](<../../../.gitbook/assets/image (253).png>)

**Rozwiązane adresy**

Pod _**Statistics --> Resolved Addresses**_ znajdziesz kilka **informacji**, które zostały "**rozwiązane**" przez Wireshark, takie jak port/transport do protokołu, MAC do producenta, itp. Ważne jest, aby wiedzieć, co jest zaangażowane w komunikacji.

![](<../../../.gitbook/assets/image (890).png>)

**Hierarchia protokołów**

Pod _**Statistics --> Protocol Hierarchy**_ znajdziesz **protokoły** zaangażowane w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (583).png>)

**Konwersacje**

Pod _**Statistics --> Conversations**_ znajdziesz **podsumowanie konwersacji** w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (450).png>)

**Punkty końcowe**

Pod _**Statistics --> Endpoints**_ znajdziesz **podsumowanie punktów końcowych** w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (893).png>)

**Informacje DNS**

Pod _**Statistics --> DNS**_ znajdziesz statystyki dotyczące przechwyconych żądań DNS.

![](<../../../.gitbook/assets/image (1060).png>)

**Wykres I/O**

Pod _**Statistics --> I/O Graph**_ znajdziesz **wykres komunikacji**.

![](<../../../.gitbook/assets/image (989).png>)

### Filtrowanie

Tutaj znajdziesz filtry Wireshark w zależności od protokołu: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Inne interesujące filtry:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Ruch HTTP i początkowy ruch HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Ruch HTTP i początkowy ruch HTTPS + SYN TCP
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Ruch HTTP i początkowy ruch HTTPS + SYN TCP + żądania DNS

### Wyszukiwanie

Jeśli chcesz **wyszukać** **treść** w **pakietach** sesji, naciśnij _CTRL+f_. Możesz dodać nowe warstwy do głównego paska informacji (Nr, Czas, Źródło, itp.) naciskając prawy przycisk, a następnie edytuj kolumnę.

### Darmowe laboratoria pcap

**Ćwicz z darmowymi wyzwaniami na:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identyfikacja domen

Możesz dodać kolumnę, która pokazuje nagłówek Host HTTP:

![](<../../../.gitbook/assets/image (635).png>)

I kolumnę, która dodaje nazwę serwera z inicjującego połączenia HTTPS (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identyfikacja nazw lokalnych hostów

### Z DHCP

W bieżącym Wiresharku zamiast `bootp` musisz szukać `DHCP`

![](<../../../.gitbook/assets/image (1010).png>)

### Z NBNS

![](<../../../.gitbook/assets/image (1000).png>)

## Deszyfrowanie TLS

### Deszyfrowanie ruchu https za pomocą prywatnego klucza serwera

_edytuj>preferencje>protokół>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

Naciśnij _Edytuj_ i dodaj wszystkie dane serwera oraz klucza prywatnego (_IP, Port, Protokół, Plik klucza i hasło_)

### Deszyfrowanie ruchu https za pomocą kluczy sesji symetrycznych

Zarówno Firefox, jak i Chrome mają możliwość rejestrowania kluczy sesji TLS, które można użyć z Wiresharkiem do deszyfrowania ruchu TLS. Pozwala to na dogłębną analizę komunikacji zabezpieczonej. Więcej szczegółów na temat wykonywania tego deszyfrowania można znaleźć w przewodniku na stronie [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Aby wykryć to, wyszukaj w środowisku zmienną `SSLKEYLOGFILE`

Plik współdzielonych kluczy będzie wyglądał tak:

![](<../../../.gitbook/assets/image (817).png>)

Aby zaimportować to do Wiresharka, przejdź do \_edytuj > preferencje > protokół > ssl > i zaimportuj to w (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (986).png>)

## Komunikacja ADB

Wyodrębnij plik APK z komunikacji ADB, w której przesłano plik APK:
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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
