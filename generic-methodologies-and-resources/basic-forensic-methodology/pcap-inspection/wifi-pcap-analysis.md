# Analiza Pcap Wifi

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Sprawdź BSSID

Gdy otrzymasz przechwycenie, którego głównym ruchem jest Wifi, używając WireShark, możesz zacząć badanie wszystkich SSID przechwycenia za pomocą _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (103).png>)

![](<../../../.gitbook/assets/image (489).png>)

### Atak Brute Force

Jedna z kolumn na tym ekranie wskazuje, czy **znaleziono jakąkolwiek autoryzację w pliku pcap**. Jeśli tak jest, możesz spróbować jej złamać za pomocą `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Na przykład odzyska hasło WPA chroniące PSK (klucz udostępniony z góry), które będzie wymagane do późniejszego odszyfrowania ruchu.

## Dane w ramkach ogłoszeniowych / Kanał boczny

Jeśli podejrzewasz, że **dane wyciekają w ramkach ogłoszeniowych sieci Wifi**, możesz sprawdzić ramki sieciowe, używając filtru takiego jak: `wlan contains <NAZWA_SIECI>` lub `wlan.ssid == "NAZWA_SIECI"`, a następnie przeszukać przefiltrowane pakiety w poszukiwaniu podejrzanych ciągów znaków.

## Znajdź nieznane adresy MAC w sieci Wifi

Następujący link będzie przydatny do znalezienia **urządzeń wysyłających dane wewnątrz sieci Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli już znasz **adresy MAC, możesz je usunąć z wyników** dodając sprawdzenia takie jak to: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Po wykryciu **nieznanych adresów MAC** komunikujących się w sieci, możesz użyć **filtrów** takich jak ten: `wlan.addr==<ADRES_MAC> && (ftp || http || ssh || telnet)` do filtrowania ruchu. Zauważ, że filtry ftp/http/ssh/telnet są przydatne, jeśli odszyfrowałeś ruch.

## Odszyfruj ruch

Edytuj --> Preferencje --> Protokoły --> IEEE 802.11 --> Edytuj

![](<../../../.gitbook/assets/image (496).png>)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
