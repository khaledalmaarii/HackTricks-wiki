# Análisis de Pcap Wifi

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}

## Verificar BSSIDs

Cuando recibas una captura cuyo tráfico principal es Wifi usando WireShark, puedes comenzar a investigar todos los SSIDs de la captura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Fuerza Bruta

Una de las columnas de esa pantalla indica si **se encontró alguna autenticación dentro del pcap**. Si ese es el caso, puedes intentar forzarla usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por ejemplo, recuperará la frase de paso WPA que protege una PSK (clave precompartida), que será necesaria para descifrar el tráfico más tarde.

## Datos en Beacons / Canal Secundario

Si sospechas que **se están filtrando datos dentro de los beacons de una red Wifi**, puedes revisar los beacons de la red utilizando un filtro como el siguiente: `wlan contains <NAMEofNETWORK>`, o `wlan.ssid == "NAMEofNETWORK"` busca dentro de los paquetes filtrados cadenas sospechosas.

## Encontrar Direcciones MAC Desconocidas en una Red Wifi

El siguiente enlace será útil para encontrar las **máquinas que envían datos dentro de una Red Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoces **direcciones MAC, puedes eliminarlas de la salida** añadiendo comprobaciones como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una vez que hayas detectado **direcciones MAC desconocidas** comunicándose dentro de la red, puedes usar **filtros** como el siguiente: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar su tráfico. Ten en cuenta que los filtros ftp/http/ssh/telnet son útiles si has descifrado el tráfico.

## Desencriptar Tráfico

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
