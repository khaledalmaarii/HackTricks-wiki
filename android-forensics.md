# Análisis Forense de Android

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Dispositivo Bloqueado

Para comenzar a extraer datos de un dispositivo Android, este debe estar desbloqueado. Si está bloqueado, puedes:

* Verificar si el dispositivo tiene la depuración por USB activada.
* Buscar un posible [ataque de huellas](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf).
* Intentar con [fuerza bruta](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/).

## Adquisición de Datos

Crea una [copia de seguridad de Android usando adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) y extráela usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Si se tiene acceso root o conexión física a la interfaz JTAG

* `cat /proc/partitions` (busca la ruta a la memoria flash, generalmente la primera entrada es _mmcblk0_ y corresponde a toda la memoria flash).
* `df /data` (Descubre el tamaño del bloque del sistema).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ejecútalo con la información recopilada del tamaño del bloque).

### Memoria

Utiliza Linux Memory Extractor (LiME) para extraer la información de la RAM. Es una extensión del kernel que debe cargarse a través de adb.

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
