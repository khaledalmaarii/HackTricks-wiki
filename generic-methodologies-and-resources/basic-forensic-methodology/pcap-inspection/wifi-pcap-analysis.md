# Wifi Pcap Analysis

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

## Controlla i BSSID

Quando ricevi una cattura il cui traffico principale è Wifi usando WireShark, puoi iniziare a investigare tutti gli SSID della cattura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Brute Force

Una delle colonne di quella schermata indica se **è stata trovata qualche autenticazione all'interno del pcap**. Se è così, puoi provare a forzarlo usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Per esempio, recupererà la passphrase WPA che protegge un PSK (pre shared-key), necessaria per decrittare il traffico in seguito.

## Dati nei Beacon / Canale Laterale

Se sospetti che **i dati vengano trasmessi all'interno dei beacon di una rete Wifi**, puoi controllare i beacon della rete utilizzando un filtro come il seguente: `wlan contains <NAMEofNETWORK>`, o `wlan.ssid == "NAMEofNETWORK"` cerca all'interno dei pacchetti filtrati stringhe sospette.

## Trova Indirizzi MAC Sconosciuti in una Rete Wifi

Il seguente link sarà utile per trovare le **macchine che inviano dati all'interno di una rete Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se già conosci **gli indirizzi MAC puoi rimuoverli dall'output** aggiungendo controlli come questo: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una volta che hai rilevato **indirizzi MAC sconosciuti** che comunicano all'interno della rete, puoi utilizzare **filtri** come il seguente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` per filtrare il suo traffico. Nota che i filtri ftp/http/ssh/telnet sono utili se hai decrittato il traffico.

## Decrittare il Traffico

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../.gitbook/assets/image (499).png>)

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
