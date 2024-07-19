# Skeleton Key

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

## Ataque de Skeleton Key

El **ataque de Skeleton Key** es una técnica sofisticada que permite a los atacantes **eludir la autenticación de Active Directory** al **inyectar una contraseña maestra** en el controlador de dominio. Esto permite al atacante **autenticarse como cualquier usuario** sin su contraseña, otorgándole **acceso sin restricciones** al dominio.

Se puede realizar utilizando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Para llevar a cabo este ataque, **se requieren derechos de Administrador de Dominio**, y el atacante debe dirigirse a cada controlador de dominio para asegurar una violación completa. Sin embargo, el efecto del ataque es temporal, ya que **reiniciar el controlador de dominio erradica el malware**, lo que requiere una reimplementación para mantener el acceso.

**Ejecutar el ataque** requiere un solo comando: `misc::skeleton`.

## Mitigaciones

Las estrategias de mitigación contra tales ataques incluyen la monitorización de IDs de eventos específicos que indican la instalación de servicios o el uso de privilegios sensibles. Específicamente, buscar el ID de Evento del Sistema 7045 o el ID de Evento de Seguridad 4673 puede revelar actividades sospechosas. Además, ejecutar `lsass.exe` como un proceso protegido puede dificultar significativamente los esfuerzos de los atacantes, ya que esto requiere que empleen un controlador en modo kernel, aumentando la complejidad del ataque.

Aquí están los comandos de PowerShell para mejorar las medidas de seguridad:

- Para detectar la instalación de servicios sospechosos, use: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Específicamente, para detectar el controlador de Mimikatz, se puede utilizar el siguiente comando: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Para fortalecer `lsass.exe`, se recomienda habilitarlo como un proceso protegido: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

La verificación después de un reinicio del sistema es crucial para asegurar que las medidas de protección se hayan aplicado con éxito. Esto se puede lograr a través de: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referencias
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

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
