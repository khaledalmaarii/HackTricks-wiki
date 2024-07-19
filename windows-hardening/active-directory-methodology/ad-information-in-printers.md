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


Hay varios blogs en Internet que **destacan los peligros de dejar impresoras configuradas con LDAP con credenciales de inicio de sesión predeterminadas/débiles**.\
Esto se debe a que un atacante podría **engañar a la impresora para que se autentique contra un servidor LDAP malicioso** (típicamente un `nc -vv -l -p 444` es suficiente) y capturar las **credenciales de la impresora en texto claro**.

Además, varias impresoras contendrán **registros con nombres de usuario** o incluso podrían ser capaces de **descargar todos los nombres de usuario** del Controlador de Dominio.

Toda esta **información sensible** y la común **falta de seguridad** hacen que las impresoras sean muy interesantes para los atacantes.

Algunos blogs sobre el tema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configuración de la Impresora
- **Ubicación**: La lista de servidores LDAP se encuentra en: `Red > Configuración de LDAP > Configuración de LDAP`.
- **Comportamiento**: La interfaz permite modificaciones del servidor LDAP sin volver a ingresar credenciales, buscando la conveniencia del usuario pero planteando riesgos de seguridad.
- **Explotación**: La explotación implica redirigir la dirección del servidor LDAP a una máquina controlada y aprovechar la función "Probar Conexión" para capturar credenciales.

## Capturando Credenciales

**Para pasos más detallados, consulte la [fuente](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Método 1: Escucha de Netcat
Una simple escucha de netcat podría ser suficiente:
```bash
sudo nc -k -v -l -p 386
```
Sin embargo, el éxito de este método varía.

### Método 2: Servidor LDAP Completo con Slapd
Un enfoque más confiable implica configurar un servidor LDAP completo porque la impresora realiza un enlace nulo seguido de una consulta antes de intentar el enlace de credenciales.

1. **Configuración del Servidor LDAP**: La guía sigue los pasos de [esta fuente](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Pasos Clave**:
- Instalar OpenLDAP.
- Configurar la contraseña de administrador.
- Importar esquemas básicos.
- Establecer el nombre de dominio en la base de datos LDAP.
- Configurar LDAP TLS.
3. **Ejecución del Servicio LDAP**: Una vez configurado, el servicio LDAP se puede ejecutar usando:
```bash
slapd -d 2
```
## Referencias
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


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
