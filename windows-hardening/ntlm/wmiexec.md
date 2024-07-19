# WmiExec

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

## Cómo Funciona Explicado

Los procesos pueden abrirse en hosts donde se conoce el nombre de usuario y ya sea la contraseña o el hash a través del uso de WMI. Los comandos se ejecutan utilizando WMI mediante Wmiexec, proporcionando una experiencia de shell semi-interactiva.

**dcomexec.py:** Utilizando diferentes puntos finales de DCOM, este script ofrece un shell semi-interactivo similar a wmiexec.py, aprovechando específicamente el objeto DCOM ShellBrowserWindow. Actualmente soporta objetos de Aplicación MMC20, Ventanas de Shell y Ventana del Navegador de Shell. (fuente: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Fundamentos de WMI

### Espacio de Nombres

Estructurado en una jerarquía de estilo de directorio, el contenedor de nivel superior de WMI es \root, bajo el cual se organizan directorios adicionales, denominados espacios de nombres.  
Comandos para listar espacios de nombres:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Las clases dentro de un espacio de nombres se pueden listar usando:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Clases**

Conocer el nombre de una clase WMI, como win32\_process, y el espacio de nombres en el que reside es crucial para cualquier operación WMI.  
Comandos para listar clases que comienzan con `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocación de una clase:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Métodos

Los métodos, que son una o más funciones ejecutables de las clases WMI, se pueden ejecutar.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumeración WMI

### Estado del Servicio WMI

Comandos para verificar si el servicio WMI está operativo:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Información del Sistema y del Proceso

Recopilación de información del sistema y del proceso a través de WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Para los atacantes, WMI es una herramienta potente para enumerar datos sensibles sobre sistemas o dominios.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Consulta remota de WMI para información específica, como administradores locales o usuarios conectados, es factible con una construcción cuidadosa de comandos.

### **Consulta Remota WMI Manual**

La identificación sigilosa de administradores locales en una máquina remota y usuarios conectados se puede lograr a través de consultas WMI específicas. `wmic` también admite la lectura de un archivo de texto para ejecutar comandos en múltiples nodos simultáneamente.

Para ejecutar un proceso de forma remota a través de WMI, como desplegar un agente de Empire, se emplea la siguiente estructura de comando, con una ejecución exitosa indicada por un valor de retorno de "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Este proceso ilustra la capacidad de WMI para la ejecución remota y la enumeración del sistema, destacando su utilidad tanto para la administración del sistema como para el pentesting.

## Referencias
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Herramientas Automáticas

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

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
