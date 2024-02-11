<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Sprawdź BSSID-y

Gdy otrzymasz przechwycenie, którego głównym ruchem jest Wifi, używając WireSharka, możesz rozpocząć badanie wszystkich SSID przechwycenia za pomocą _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Jedna z kolumn na tym ekranie wskazuje, czy **w pcap znaleziono jakąkolwiek autoryzację**. Jeśli tak jest, możesz spróbować jej Brute Force za pomocą `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Na przykład, można odzyskać hasło WPA chroniące PSK (klucz współdzielony), które będzie wymagane do późniejszego odszyfrowania ruchu.

# Dane w ramkach Beacon / Kanał boczny

Jeśli podejrzewasz, że **dane są wyciekane w ramkach sieci Wifi**, możesz sprawdzić ramki sieciowe używając filtru takiego jak ten: `wlan contains <NAZWAsieci>` lub `wlan.ssid == "NAZWAsieci"`, a następnie przeszukać przefiltrowane pakiety w poszukiwaniu podejrzanych ciągów znaków.

# Znajdowanie nieznanych adresów MAC w sieci Wifi

Następujący link będzie przydatny do znalezienia **urządzeń wysyłających dane w sieci Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli już znasz **adresy MAC, możesz je usunąć z wyniku** dodając takie sprawdzenia jak to: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Po wykryciu **nieznanych adresów MAC** komunikujących się w sieci, możesz użyć **filtrów** takich jak ten: `wlan.addr==<adres MAC> && (ftp || http || ssh || telnet)` do filtrowania ruchu. Należy zauważyć, że filtry ftp/http/ssh/telnet są przydatne, jeśli ruch został odszyfrowany.

# Odszyfrowywanie ruchu

Edytuj --> Preferencje --> Protokoły --> IEEE 802.11 --> Edytuj

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANy SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
