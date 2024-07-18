{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


# Verificar BSSIDs

Cuando recibes una captura cuyo tráfico principal es Wifi utilizando WireShark, puedes comenzar a investigar todos los SSID de la captura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Fuerza bruta

Una de las columnas de esa pantalla indica si **se encontró alguna autenticación dentro del pcap**. Si ese es el caso, puedes intentar forzarlo usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Por ejemplo, recuperará la frase de paso WPA que protege un PSK (clave compartida previamente), que será necesaria para descifrar el tráfico más tarde.

# Datos en Beacons / Canal Lateral

Si sospecha que **los datos se están filtrando dentro de los beacons de una red Wifi**, puede verificar los beacons de la red utilizando un filtro como el siguiente: `wlan contains <NOMBREdeRED>`, o `wlan.ssid == "NOMBREdeRED"` buscar dentro de los paquetes filtrados cadenas sospechosas.

# Encontrar Direcciones MAC Desconocidas en una Red Wifi

El siguiente enlace será útil para encontrar las **máquinas que envían datos dentro de una Red Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si ya conoce las **direcciones MAC, puede eliminarlas del resultado** agregando comprobaciones como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una vez que haya detectado direcciones MAC **desconocidas** comunicándose dentro de la red, puede usar **filtros** como el siguiente: `wlan.addr==<dirección MAC> && (ftp || http || ssh || telnet)` para filtrar su tráfico. Tenga en cuenta que los filtros ftp/http/ssh/telnet son útiles si ha descifrado el tráfico.

# Descifrar Tráfico

Editar --> Preferencias --> Protocolos --> IEEE 802.11--> Editar

![](<../../../.gitbook/assets/image (426).png>)
```
