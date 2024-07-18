{% hint style="success" %}
Leer en oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


# Kontroleer BSSIDs

Wanneer jy 'n vangs ontvang waarvan die hoofverkeer Wifi gebruik met WireShark, kan jy begin om al die SSID's van die vangs te ondersoek met _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Een van die kolomme van daardie skerm dui aan of **enige verifikasie binne die pcap gevind is**. As dit die geval is, kan jy probeer om dit te Brute force met behulp van `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Byvoorbeeld sal dit die WPA-wagwoord herwin wat 'n PSK (vooraf gedeelde sleutel) beskerm, wat later benodig sal word om die verkeer te ontsluit.

# Data in Beacons / Side Channel

As jy vermoed dat **data binne beacons van 'n Wifi-netwerk lek**, kan jy die beacons van die netwerk ondersoek deur 'n filter soos die volgende een te gebruik: `wlan bevat <NAAMvanNETWERK>`, of `wlan.ssid == "NAAMvanNETWERK"` soek binne die gefiltreerde pakkette vir verdagte strings.

# Vind Onbekende MAC-adresse in 'n Wifi-netwerk

Die volgende skakel sal nuttig wees om die **toestelle wat data binne 'n Wifi-netwerk stuur** te vind:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

As jy reeds die **MAC-adresse ken, kan jy hulle uit die uitset verwyder** deur kontroles by te voeg soos hierdie een: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sodra jy **onbekende MAC-adresse** wat binne die netwerk kommunikeer, opgespoor het, kan jy **filters** gebruik soos die volgende een: `wlan.addr==<MAC-adres> && (ftp || http || ssh || telnet)` om sy verkeer te filtreer. Let daarop dat ftp/http/ssh/telnet-filters nuttig is as jy die verkeer ontsluit het.

# Ontsleutel Verkeer

Wysig --> Voorkeure --> Protokolle --> IEEE 802.11--> Wysig

![](<../../../.gitbook/assets/image (426).png>)
```
