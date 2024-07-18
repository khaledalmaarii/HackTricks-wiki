{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


# Provera BSSID-ova

Kada primite snimak čiji je glavni saobraćaj Wifi koristeći WireShark, možete početi istraživanje svih SSID-ova snimka sa _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Jedna od kolona na tom ekranu pokazuje da li je **bilo kakva autentifikacija pronađena unutar pcap-a**. Ukoliko je to slučaj, možete pokušati da je probijete koristeći `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# Podaci u Bitovima / Bočni Kanal

Ako sumnjate da **podaci cure unutar bitova Wi-Fi mreže** možete proveriti bitove mreže koristeći filter poput sledećeg: `wlan contains <IMEmreže>`, ili `wlan.ssid == "IMEmreže"` pretražite filtrirane pakete za sumnjive niske.

# Pronalaženje Nepoznatih MAC Adresa u Wi-Fi Mreži

Sledeći link će biti koristan za pronalaženje **mašina koje šalju podatke unutar Wi-Fi mreže**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ako već znate **MAC adrese, možete ih ukloniti iz rezultata** dodavanjem provera poput ove: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Kada otkrijete **nepoznate MAC** adrese koje komuniciraju unutar mreže, možete koristiti **filtere** poput sledećeg: `wlan.addr==<MAC adresa> && (ftp || http || ssh || telnet)` da biste filtrirali njen saobraćaj. Imajte na umu da su ftp/http/ssh/telnet filteri korisni ako ste dešifrovali saobraćaj.

# Dekriptovanje Saobraćaja

Uredi --> Postavke --> Protokoli --> IEEE 802.11--> Uredi

![](<../../../.gitbook/assets/image (426).png>)
