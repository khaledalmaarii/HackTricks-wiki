<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


# Kontroleer BSSIDs

Wanneer jy 'n vangste ontvang waarvan die hoofverkeer Wifi is en jy gebruik WireShark, kan jy begin ondersoek instel na al die SSIDs van die vangste met _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Een van die kolomme van daardie skerm dui aan of **enige outentifikasie binne die pcap gevind is**. As dit die geval is, kan jy probeer om dit te Brute force deur `aircrack-ng` te gebruik:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Byvoorbeeld, dit sal die WPA-wagwoord herwin wat 'n PSK (vooraf gedeelde sleutel) beskerm, wat later nodig sal wees om die verkeer te ontsleutel.

# Data in Beacons / Sykanaal

As jy vermoed dat **data binne beacons van 'n WiFi-netwerk uitgelek word**, kan jy die beacons van die netwerk ondersoek deur 'n filter soos die volgende te gebruik: `wlan bevat <NAAMvanNETWERK>`, of `wlan.ssid == "NAAMvanNETWERK"` soek binne die gefiltreerde pakkies vir verdagte strings.

# Vind Onbekende MAC-adresse in 'n WiFi-netwerk

Die volgende skakel sal nuttig wees om die **toestelle wat data binne 'n WiFi-netwerk stuur** te vind:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

As jy reeds **MAC-adresse ken, kan jy dit uit die uitset verwyder** deur kontroles soos hierdie een by te voeg: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Nadat jy **onbekende MAC-adresse wat binne die netwerk kommunikeer, opgespoor het**, kan jy **filters** soos die volgende een gebruik: `wlan.addr==<MAC-adres> && (ftp || http || ssh || telnet)` om die verkeer te filtreer. Let daarop dat ftp/http/ssh/telnet-filters nuttig is as jy die verkeer ontsluit het.

# Ontsleutel Verkeer

Wysig --> Voorkeure --> Protokolle --> IEEE 802.11 --> Wysig

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
