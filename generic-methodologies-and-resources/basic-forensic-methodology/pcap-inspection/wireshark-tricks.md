# Sztuczki z Wiresharkiem

## Sztuczki z Wiresharkiem

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

## Popraw swoje umiejętności z Wiresharkiem

### Tutoriale

Następujące tutoriale są niesamowite do nauki kilku fajnych podstawowych sztuczek:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analizowane informacje

**Informacje eksperta**

Klikając na _**Analyze** --> **Expert Information**_ będziesz mieć **przegląd** tego, co dzieje się w analizowanych pakietach:

![](<../../../.gitbook/assets/image (570).png>)

**Rozwiązane adresy**

Pod _**Statistics --> Resolved Addresses**_ można znaleźć wiele **informacji**, które zostały "**rozwiązane**" przez Wireshark, takie jak port/transport do protokołu, MAC do producenta, itp. Ważne jest, aby wiedzieć, co jest zaangażowane w komunikację.

![](<../../../.gitbook/assets/image (571).png>)

**Hierarchia protokołów**

Pod _**Statistics --> Protocol Hierarchy**_ można znaleźć **protokoły** **zaangażowane** w komunikację oraz dane na ich temat.

![](<../../../.gitbook/assets/image (572).png>)

**Konwersacje**

Pod _**Statistics --> Conversations**_ można znaleźć **podsumowanie konwersacji** w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (573).png>)

**Punkty końcowe**

Pod _**Statistics --> Endpoints**_ można znaleźć **podsumowanie punktów końcowych** w komunikacji oraz dane na ich temat.

![](<../../../.gitbook/assets/image (575).png>)

**Informacje DNS**

Pod _**Statistics --> DNS**_ można znaleźć statystyki dotyczące przechwyconych żądań DNS.

![](<../../../.gitbook/assets/image (577).png>)

**Wykres I/O**

Pod _**Statistics --> I/O Graph**_ można znaleźć **wykres komunikacji**.

![](<../../../.gitbook/assets/image (574).png>)

### Filtrowanie

Tutaj można znaleźć filtr Wiresharka w zależności od protokołu: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Inne interesujące filtry:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Ruch HTTP i początkowy ruch HTTPS
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Ruch HTTP i początkowy ruch HTTPS + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Ruch HTTP i początkowy ruch HTTPS + TCP SYN + żądania DNS

### Wyszukiwanie

Jeśli chcesz **wyszukać** **zawartość** w **pakietach** sesji, naciśnij _CTRL+f_. Możesz dodać nowe warstwy do głównego paska informacji (Nr, Czas, Źródło, itp.) naciskając prawy przycisk myszy, a następnie przycisk edycji kolumny.

### Darmowe laboratoria pcap

**Ćwicz z darmowymi wyzwaniami na stronie: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## Identyfikowanie domen

Możesz dodać kolumnę, która pokazuje nagłówek Host HTTP:

![](<../../../.gitbook/assets/image (403).png>)

I kolumnę, która dodaje nazwę serwera z inicjującego połączenia HTTPS (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identyfikowanie lokalnych nazw hostów

### Z DHCP

W bieżącym Wiresharku zamiast `bootp` musisz wyszukać `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Z NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Odszyfrowywanie TLS

### Odszyfrowywanie ruchu https za pomocą prywatnego klucza serwera

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Naciśnij _Edit_ i dodaj wszystkie dane serwera i klucza prywatnego (_IP, Port, Protokół, Plik klucza i hasło_)

### Odszyfrowywanie ruchu https za pomocą symetrycznych kluczy sesji

Zarówno Firefox, jak i Chrome mają możliwość rejestrowania kluczy sesji TLS, które można użyć z Wiresharkiem do odszyfrowania ruchu TLS. Pozwala to na dogłębną analizę bezpiecznej komunikacji. Więcej informacji na temat wykonywania tego odszyfrowania można znaleźć w przewodniku na stronie [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Aby to wykryć, wyszukaj w środowisku zmienną `SSLKEYLOGFILE`

Plik z udostępnionymi kluczami będzie wyglądał tak:

![](<../../../.gitbook/assets/image (99).png>)

Aby zaimportować to do wiresharka, przejdź do \_edit > preference > protocol > ssl > i zaimportuj go w (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

## Komunikacja ADB

Wyodrębnij plik APK z komunikacji ADB, w której został wysłany plik APK:
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

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
