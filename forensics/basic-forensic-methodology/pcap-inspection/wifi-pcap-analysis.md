{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępnij sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}


# Sprawdź BSSIDs

Kiedy otrzymasz przechwycenie, którego głównym ruchem jest Wifi, używając WireShark, możesz zacząć badanie wszystkich SSID przechwycenia za pomocą _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Atak Brute Force

Jedna z kolumn na tym ekranie wskazuje, czy **znaleziono jakąkolwiek autoryzację w pliku pcap**. Jeśli tak jest, możesz spróbować ją złamać, używając `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Na przykład odzyska hasło WPA chroniące PSK (klucz wstępnie uzgodniony), które będzie wymagane do późniejszego odszyfrowania ruchu.

# Dane w ramkach ogłoszeniowych / Kanał boczny

Jeśli podejrzewasz, że **dane wyciekają w ramkach ogłoszeniowych sieci Wifi**, możesz sprawdzić ramki ogłoszeniowe sieci, używając filtru takiego jak: `wlan contains <NAZWA_SIECI>`, lub `wlan.ssid == "NAZWA_SIECI"`, aby wyszukać podejrzane ciągi w odfiltrowanych pakietach.

# Znajdź nieznane adresy MAC w sieci Wifi

Następujący link będzie przydatny do znalezienia **urządzeń wysyłających dane wewnątrz sieci Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli już znasz **adresy MAC**, możesz je usunąć z wyników, dodając sprawdzenia takie jak to: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Gdy wykryjesz **nieznane adresy MAC** komunikujące się w sieci, możesz użyć **filtrów** takich jak ten: `wlan.addr==<ADRES_MAC> && (ftp || http || ssh || telnet)` do filtrowania ruchu. Zauważ, że filtry ftp/http/ssh/telnet są przydatne, jeśli odszyfrowałeś ruch.

# Odszyfruj ruch

Edytuj --> Preferencje --> Protokoły --> IEEE 802.11--> Edytuj

![](<../../../.gitbook/assets/image (426).png>)
```
