{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ayuda a HackTricks</summary>

* ¡Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


## smss.exe

**Administrador de Sesiones**.\
La Sesión 0 inicia **csrss.exe** y **wininit.exe** (**servicios del SO**) mientras que la Sesión 1 inicia **csrss.exe** y **winlogon.exe** (**sesión de usuario**). Sin embargo, solo deberías ver **un proceso** de ese **binario** sin hijos en el árbol de procesos.

Además, sesiones aparte de 0 y 1 pueden indicar que están ocurriendo sesiones de RDP.


## csrss.exe

**Proceso de Subsistema de Ejecución Cliente/Servidor**.\
Administra **procesos** y **hilos**, pone a disposición la **API de Windows** para otros procesos y también **asigna letras de unidad**, crea **archivos temporales** y maneja el **proceso de apagado**.

Hay uno **ejecutándose en la Sesión 0 y otro en la Sesión 1** (por lo tanto, **2 procesos** en el árbol de procesos). Se crea otro por cada nueva Sesión.


## winlogon.exe

**Proceso de Inicio de Sesión de Windows**.\
Es responsable de los **inicios**/**cierres de sesión** de usuario. Inicia **logonui.exe** para solicitar nombre de usuario y contraseña y luego llama a **lsass.exe** para verificarlos.

Luego inicia **userinit.exe** que está especificado en **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** con la clave **Userinit**.

Además, el registro anterior debería tener **explorer.exe** en la clave **Shell** o podría ser abusado como un **método de persistencia de malware**.


## wininit.exe

**Proceso de Inicialización de Windows**. \
Inicia **services.exe**, **lsass.exe** y **lsm.exe** en la Sesión 0. Debería haber solo 1 proceso.


## userinit.exe

**Aplicación de Inicio de Sesión de Usuario**.\
Carga el **ntduser.dat en HKCU** e inicializa el **entorno de usuario** y ejecuta **scripts de inicio de sesión** y **GPO**.

Inicia **explorer.exe**.


## lsm.exe

**Administrador de Sesión Local**.\
Trabaja con smss.exe para manipular sesiones de usuario: inicio/cierre de sesión, inicio de shell, bloqueo/desbloqueo de escritorio, etc.

Después de W7, lsm.exe se transformó en un servicio (lsm.dll).

Debería haber solo 1 proceso en W7 y de ellos un servicio ejecutando el DLL.


## services.exe

**Administrador de Control de Servicios**.\
**Carga** **servicios** configurados como **inicio automático** y **controladores**.

Es el proceso padre de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** y muchos más.

Los servicios están definidos en `HKLM\SYSTEM\CurrentControlSet\Services` y este proceso mantiene una base de datos en memoria de información de servicios que puede ser consultada por sc.exe.

Observa cómo **algunos** **servicios** se ejecutarán en un **proceso propio** y otros se **compartirán en un proceso svchost.exe**.

Debería haber solo 1 proceso.


## lsass.exe

**Subsistema de Autoridad de Seguridad Local**.\
Es responsable de la **autenticación de usuario** y crea los **tokens de seguridad**. Utiliza paquetes de autenticación ubicados en `HKLM\System\CurrentControlSet\Control\Lsa`.

Escribe en el **registro de eventos de seguridad** y debería haber solo 1 proceso.

Ten en cuenta que este proceso es altamente atacado para extraer contraseñas.


## svchost.exe

**Proceso de Host de Servicio Genérico**.\
Hospeda múltiples servicios DLL en un proceso compartido.

Por lo general, encontrarás que **svchost.exe** se inicia con la bandera `-k`. Esto lanzará una consulta al registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** donde habrá una clave con el argumento mencionado en -k que contendrá los servicios a iniciar en el mismo proceso.

Por ejemplo: `-k UnistackSvcGroup` lanzará: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Si también se usa la **bandera `-s`** con un argumento, entonces se le pide a svchost que **solo inicie el servicio especificado** en este argumento.

Habrá varios procesos de `svchost.exe`. Si alguno de ellos **no está utilizando la bandera `-k`**, eso es muy sospechoso. Si encuentras que **services.exe no es el proceso padre**, eso también es muy sospechoso.


## taskhost.exe

Este proceso actúa como anfitrión para procesos que se ejecutan desde DLL. También carga los servicios que se ejecutan desde DLL.

En W8 se llama taskhostex.exe y en W10 taskhostw.exe.


## explorer.exe

Este es el proceso responsable del **escritorio del usuario** y de lanzar archivos a través de extensiones de archivo.

Debería generarse solo **1** proceso por usuario conectado.

Este se ejecuta desde **userinit.exe** que debería ser terminado, por lo que **no debería aparecer ningún proceso padre** para este proceso.


# Detectando Procesos Maliciosos

* ¿Se está ejecutando desde la ruta esperada? (Ningún binario de Windows se ejecuta desde una ubicación temporal)
* ¿Se está comunicando con IPs extrañas?
* Verifica las firmas digitales (los artefactos de Microsoft deberían estar firmados)
* ¿Está escrito correctamente?
* ¿Se está ejecutando bajo el SID esperado?
* ¿El proceso padre es el esperado (si lo hay)?
* ¿Los procesos hijos son los esperados? (¿no hay cmd.exe, wscript.exe, powershell.exe..?)


{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ayuda a HackTricks</summary>

* ¡Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
