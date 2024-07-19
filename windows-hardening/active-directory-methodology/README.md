# Metodología de Active Directory

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

## Visión general básica

**Active Directory** sirve como una tecnología fundamental, permitiendo a los **administradores de red** crear y gestionar de manera eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios vinculados por una estructura compartida, y un **bosque** representa la colección de múltiples árboles, interconectados a través de **relaciones de confianza**, formando la capa más alta de la estructura organizativa. Se pueden designar derechos de **acceso** y **comunicación** específicos en cada uno de estos niveles.

Los conceptos clave dentro de **Active Directory** incluyen:

1. **Directorio** – Alberga toda la información relacionada con los objetos de Active Directory.
2. **Objeto** – Denota entidades dentro del directorio, incluyendo **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como un contenedor para objetos de directorio, con la capacidad de que múltiples dominios coexistan dentro de un **bosque**, cada uno manteniendo su propia colección de objetos.
4. **Árbol** – Un agrupamiento de dominios que comparten un dominio raíz común.
5. **Bosque** – La cúspide de la estructura organizativa en Active Directory, compuesta por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una gama de servicios críticos para la gestión y comunicación centralizada dentro de una red. Estos servicios comprenden:

1. **Servicios de Dominio** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo funcionalidades de **autenticación** y **búsqueda**.
2. **Servicios de Certificado** – Supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Servicios de Directorio Ligero** – Soporta aplicaciones habilitadas para directorios a través del **protocolo LDAP**.
4. **Servicios de Federación de Directorio** – Proporciona capacidades de **inicio de sesión único** para autenticar usuarios a través de múltiples aplicaciones web en una sola sesión.
5. **Gestión de Derechos** – Ayuda a proteger material con derechos de autor regulando su distribución y uso no autorizados.
6. **Servicio DNS** – Crucial para la resolución de **nombres de dominio**.

Para una explicación más detallada, consulta: [**TechTerms - Definición de Active Directory**](https://techterms.com/definition/active\_directory)

### **Autenticación Kerberos**

Para aprender a **atacar un AD**, necesitas **entender** muy bien el **proceso de autenticación Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Hoja de trucos

Puedes visitar [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

## Reconocimiento de Active Directory (Sin credenciales/sesiones)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones, podrías:

* **Pentestear la red:**
* Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md).
* Enumerar DNS podría proporcionar información sobre servidores clave en el dominio como web, impresoras, comparticiones, vpn, medios, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Consulta la [**Metodología General de Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
* **Verifica el acceso nulo y de invitado en servicios smb** (esto no funcionará en versiones modernas de Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Una guía más detallada sobre cómo enumerar un servidor SMB se puede encontrar aquí:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Enumerar Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Una guía más detallada sobre cómo enumerar LDAP se puede encontrar aquí (presta **especial atención al acceso anónimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Envenenar la red**
* Reúne credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Accede al host [**abusando del ataque de retransmisión**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Reúne credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Extrae nombres de usuario/nombres de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos de dominio y también de los disponibles públicamente.
* Si encuentras los nombres completos de los trabajadores de la empresa, podrías intentar diferentes convenciones de **nombres de usuario de AD** ([**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NombreApellido_, _Nombre.Apellido_, _NamSur_ (3 letras de cada uno), _Nam.Sur_, _NSurname_, _N.Surname_, _ApellidoNombre_, _Apellido.Nombre_, _ApellidoN_, _Apellido.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
* Herramientas:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

* **Enumeración SMB/LDAP anónima:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enumeración Kerbrute**: Cuando se solicita un **nombre de usuario inválido**, el servidor responderá utilizando el código de error **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, lo que nos permite determinar que el nombre de usuario era inválido. **Nombres de usuario válidos** provocarán ya sea el **TGT en una respuesta AS-REP** o el error _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando que se requiere que el usuario realice una pre-autenticación.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Servidor OWA (Outlook Web Access)**

Si encuentras uno de estos servidores en la red, también puedes realizar **enumeración de usuarios contra él**. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Puedes encontrar listas de nombres de usuario en [**este repositorio de github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* y este otro ([**nombres de usuario estadísticamente probables**](https://github.com/insidetrust/statistically-likely-usernames)).

Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** del paso de reconocimiento que deberías haber realizado antes de esto. Con el nombre y apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar nombres de usuario potencialmente válidos.
{% endhint %}

### Conociendo uno o varios nombres de usuario

Bien, así que sabes que ya tienes un nombre de usuario válido pero no contraseñas... Entonces intenta:

* [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT\_REQ\_PREAUTH_ puedes **solicitar un mensaje AS\_REP** para ese usuario que contendrá algunos datos encriptados por una derivación de la contraseña del usuario.
* [**Password Spraying**](password-spraying.md): Intentemos las contraseñas más **comunes** con cada uno de los usuarios descubiertos, tal vez algún usuario esté usando una mala contraseña (¡ten en cuenta la política de contraseñas!).
* Ten en cuenta que también puedes **spray servidores OWA** para intentar acceder a los servidores de correo de los usuarios.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamiento LLMNR/NBT-NS

Podrías ser capaz de **obtener** algunos **hashes** de desafío para romper **envenenando** algunos protocolos de la **red**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relay NTML

Si has logrado enumerar el directorio activo tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar ataques de [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* para obtener acceso al entorno de AD.

### Robar Credenciales NTLM

Si puedes **acceder a otras PC o recursos compartidos** con el **usuario nulo o invitado** podrías **colocar archivos** (como un archivo SCF) que si se acceden de alguna manera **activarán una autenticación NTML contra ti** para que puedas **robar** el **desafío NTLM** y romperlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerando Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o una shell como usuario de dominio, **deberías recordar que las opciones dadas antes siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada deberías saber cuál es el **problema del doble salto de Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeración

Haber comprometido una cuenta es un **gran paso para comenzar a comprometer todo el dominio**, porque podrás comenzar la **Enumeración de Active Directory:**

Respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar cada posible usuario vulnerable, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

* Podrías usar el [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
* También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/) que será más sigiloso
* También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
* Otra herramienta increíble para reconocimiento en un directorio activo es [**BloodHound**](bloodhound.md). No es **muy sigilosa** (dependiendo de los métodos de recolección que uses), pero **si no te importa** eso, deberías probarla. Encuentra dónde los usuarios pueden RDP, encuentra rutas a otros grupos, etc.
* **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Registros DNS del AD**](ad-dns-records.md) ya que podrían contener información interesante.
* Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** del **SysInternal** Suite.
* También puedes buscar en la base de datos LDAP con **ldapsearch** para buscar credenciales en los campos _userPassword_ y _unixUserPassword_, o incluso para _Description_. cf. [Contraseña en el comentario de usuario AD en PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
* Si estás usando **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* También podrías intentar herramientas automatizadas como:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extrayendo todos los usuarios del dominio**

Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Incluso si esta sección de Enumeración parece pequeña, esta es la parte más importante de todas. Accede a los enlaces (principalmente el de cmd, powershell, powerview y BloodHound), aprende cómo enumerar un dominio y practica hasta que te sientas cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **tickets TGS** utilizados por servicios vinculados a cuentas de usuario y romper su encriptación—que se basa en contraseñas de usuario—**fuera de línea**.

Más sobre esto en:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales podrías verificar si tienes acceso a alguna **máquina**. Para ello, podrías usar **CrackMapExec** para intentar conectarte a varios servidores con diferentes protocolos, de acuerdo a tus escaneos de puertos.

### Escalación de privilegios local

Si has comprometido credenciales o una sesión como un usuario regular de dominio y tienes **acceso** con este usuario a **cualquier máquina en el dominio** deberías intentar encontrar la manera de **escalar privilegios localmente y buscar credenciales**. Esto se debe a que solo con privilegios de administrador local podrás **volcar hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**escalación de privilegios local en Windows**](../windows-local-privilege-escalation/) y una [**lista de verificación**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de sesión actuales

Es muy **improbable** que encuentres **tickets** en el usuario actual **dándote permiso para acceder** a recursos inesperados, pero podrías verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si has logrado enumerar el directorio activo, tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar ataques de NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Busca Credenciales en Recursos Compartidos de Computadora**

Ahora que tienes algunas credenciales básicas, deberías verificar si puedes **encontrar** archivos **interesantes que se compartan dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para aprender sobre herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Robar Credenciales NTLM

Si puedes **acceder a otras PC o recursos compartidos**, podrías **colocar archivos** (como un archivo SCF) que, si se accede de alguna manera, **activarán una autenticación NTML contra ti**, para que puedas **robar** el **reto NTLM** y crackearlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitió a cualquier usuario autenticado **comprometer el controlador de dominio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalación de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas, un usuario de dominio regular no es suficiente, necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de Hash

Esperemos que hayas logrado **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/).\
Luego, es hora de volcar todos los hashes en memoria y localmente.\
[**Lee esta página sobre diferentes formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pasar el Hash

**Una vez que tengas el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, para que cuando se realice cualquier **autenticación NTLM**, ese **hash será utilizado.** La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como una alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pasar el Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Este ticket robado se utiliza para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilización de Credenciales

Si tienes el **hash** o **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otras **PCs** con ello.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Nota que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.
{% endhint %}

### Abuso de MSSQL y Enlaces de Confianza

Si un usuario tiene privilegios para **acceder a instancias de MSSQL**, podría ser capaz de usarlo para **ejecutar comandos** en el host de MSSQL (si se ejecuta como SA), **robar** el **hash** de NetNTLM o incluso realizar un **ataque** de **relevo**.\
Además, si una instancia de MSSQL es confiable (enlace de base de datos) por otra instancia de MSSQL. Si el usuario tiene privilegios sobre la base de datos confiable, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas pueden encadenarse y en algún momento el usuario podría encontrar una base de datos mal configurada donde puede ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de confianzas de bosque.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegación No Restringida

Si encuentras algún objeto de Computadora con el atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) y tienes privilegios de dominio en la computadora, podrás volcar TGTs de la memoria de todos los usuarios que inicien sesión en la computadora.\
Entonces, si un **Administrador de Dominio inicia sesión en la computadora**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a la delegación restringida, incluso podrías **comprometer automáticamente un Servidor de Impresión** (esperemos que sea un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegación Restringida

Si un usuario o computadora está permitido para "Delegación Restringida", podrá **impersonar a cualquier usuario para acceder a algunos servicios en una computadora**.\
Luego, si **comprometes el hash** de este usuario/computadora, podrás **impersonar a cualquier usuario** (incluso administradores de dominio) para acceder a algunos servicios.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegación Restringida Basada en Recursos

Tener privilegio de **ESCRITURA** en un objeto de Active Directory de una computadora remota permite la obtención de ejecución de código con **privilegios elevados**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos de dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso del servicio de Cola de Impresoras

Descubrir un **servicio de Cola** escuchando dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recolectar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Usualmente los usuarios accederán al sistema a través de RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en computadoras unidas al dominio, asegurando que sea **aleatoria**, única y frecuentemente **cambiada**. Estas contraseñas se almacenan en Active Directory y el acceso se controla a través de ACLs solo para usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, se vuelve posible pivotar a otras computadoras.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Robo de Certificados

**Recolectar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso de Plantillas de Certificados

Si hay **plantillas vulnerables** configuradas, es posible abusar de ellas para escalar privilegios:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-explotación con cuenta de alto privilegio

### Volcado de Credenciales de Dominio

Una vez que obtienes privilegios de **Administrador de Dominio** o incluso mejor **Administrador de Empresa**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Más información sobre el ataque DCSync se puede encontrar aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit se puede encontrar aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como Persistencia

Algunas de las técnicas discutidas anteriormente pueden ser utilizadas para persistencia.\
Por ejemplo, podrías:

*   Hacer que los usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Hacer que los usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Otorgar privilegios de [**DCSync**](./#dcsync) a un usuario

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **ataque Silver Ticket** crea un **ticket legítimo de Servicio de Concesión de Tickets (TGS)** para un servicio específico utilizando el **hash de NTLM** (por ejemplo, el **hash de la cuenta de PC**). Este método se emplea para **acceder a los privilegios del servicio**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Un **ataque Golden Ticket** implica que un atacante obtenga acceso al **hash de NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se utiliza para firmar todos los **Tickets de Concesión de Tickets (TGTs)**, que son esenciales para la autenticación dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque Silver Ticket).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Estos son como los tickets dorados forjados de una manera que **elude los mecanismos comunes de detección de tickets dorados.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistencia de Cuentas de Certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena manera de poder persistir en la cuenta de los usuarios (incluso si cambia la contraseña):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistencia de Certificados en el Dominio**

**Usar certificados también es posible para persistir con altos privilegios dentro del dominio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de los **grupos privilegiados** (como Administradores de Dominio y Administradores de Empresa) aplicando una **Lista de Control de Acceso (ACL)** estándar a través de estos grupos para prevenir cambios no autorizados. Sin embargo, esta característica puede ser explotada; si un atacante modifica la ACL de AdminSDHolder para otorgar acceso total a un usuario regular, ese usuario obtiene un control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, destinada a proteger, puede por lo tanto volverse en contra, permitiendo un acceso no autorizado a menos que se supervise de cerca.

[**Más información sobre el Grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Dentro de cada **Controlador de Dominio (DC)**, existe una cuenta de **administrador local**. Al obtener derechos de administrador en tal máquina, el hash del Administrador local puede ser extraído usando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta del Administrador local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistencia de ACL

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre algunos objetos de dominio específicos que permitirán al usuario **escalar privilegios en el futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descriptores de Seguridad

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes **hacer** un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Alterar **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas de dominio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP Personalizado

[Aprende qué es un SSP (Proveedor de Soporte de Seguridad) aquí.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** utilizadas para acceder a la máquina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registra un **nuevo Controlador de Dominio** en el AD y lo utiliza para **empujar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** sobre las **modificaciones**. Necesitas privilegios de DA y estar dentro del **dominio raíz**.\
Nota que si usas datos incorrectos, aparecerán registros bastante feos.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistencia de LAPS

Anteriormente hemos discutido cómo escalar privilegios si tienes **suficientes permisos para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también pueden ser utilizadas para **mantener persistencia**.\
Revisa:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalación de Privilegios en el Bosque - Confianzas de Dominio

Microsoft ve el **Bosque** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría llevar potencialmente a que todo el Bosque sea comprometido**.

### Información Básica

Una [**confianza de dominio**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Esencialmente, crea un vínculo entre los sistemas de autenticación de los dos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una confianza, intercambian y retienen **claves** específicas dentro de sus **Controladores de Dominio (DCs)**, que son cruciales para la integridad de la confianza.

En un escenario típico, si un usuario pretende acceder a un servicio en un **dominio confiable**, primero debe solicitar un ticket especial conocido como un **TGT inter-realm** de su propio DC de dominio. Este TGT está cifrado con una **clave** compartida que ambos dominios han acordado. Luego, el usuario presenta este TGT al **DC del dominio confiable** para obtener un ticket de servicio (**TGS**). Tras la validación exitosa del TGT inter-realm por parte del DC del dominio confiable, emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Una **computadora cliente** en **Dominio 1** inicia el proceso utilizando su **hash de NTLM** para solicitar un **Ticket Granting Ticket (TGT)** de su **Controlador de Dominio (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica con éxito.
3. El cliente luego solicita un **TGT inter-realm** de DC1, que es necesario para acceder a recursos en **Dominio 2**.
4. El TGT inter-realm está cifrado con una **clave de confianza** compartida entre DC1 y DC2 como parte de la confianza de dominio bidireccional.
5. El cliente lleva el TGT inter-realm al **Controlador de Dominio (DC2) del Dominio 2**.
6. DC2 verifica el TGT inter-realm utilizando su clave de confianza compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en el Dominio 2 al que el cliente desea acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en el Dominio 2.

### Diferentes confianzas

Es importante notar que **una confianza puede ser unidireccional o bidireccional**. En la opción bidireccional, ambos dominios se confiarán mutuamente, pero en la relación de confianza **unidireccional**, uno de los dominios será el **confiable** y el otro el **que confía**. En este último caso, **solo podrás acceder a recursos dentro del dominio que confía desde el dominio confiable**.

Si el Dominio A confía en el Dominio B, A es el dominio que confía y B es el confiable. Además, en **Dominio A**, esto sería una **confianza saliente**; y en **Dominio B**, esto sería una **confianza entrante**.

**Diferentes relaciones de confianza**

* **Confianzas Padre-Hijo**: Esta es una configuración común dentro del mismo bosque, donde un dominio hijo tiene automáticamente una confianza bidireccional transitiva con su dominio padre. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el padre y el hijo.
* **Confianzas de Enlace Cruzado**: Conocidas como "confianzas de acceso directo", se establecen entre dominios hijos para acelerar los procesos de referencia. En bosques complejos, las referencias de autenticación generalmente tienen que viajar hasta la raíz del bosque y luego hacia abajo hasta el dominio objetivo. Al crear enlaces cruzados, el viaje se acorta, lo que es especialmente beneficioso en entornos geográficamente dispersos.
* **Confianzas Externas**: Estas se establecen entre diferentes dominios no relacionados y son no transitivas por naturaleza. Según [la documentación de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), las confianzas externas son útiles para acceder a recursos en un dominio fuera del bosque actual que no está conectado por una confianza de bosque. La seguridad se refuerza a través del filtrado de SID con confianzas externas.
* **Confianzas de Raíz de Árbol**: Estas confianzas se establecen automáticamente entre el dominio raíz del bosque y una nueva raíz de árbol añadida. Aunque no se encuentran comúnmente, las confianzas de raíz de árbol son importantes para agregar nuevos árboles de dominio a un bosque, permitiéndoles mantener un nombre de dominio único y asegurando la transitividad bidireccional. Más información se puede encontrar en [la guía de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Confianzas de Bosque**: Este tipo de confianza es una confianza bidireccional transitiva entre dos dominios raíz de bosque, también aplicando filtrado de SID para mejorar las medidas de seguridad.
* **Confianzas MIT**: Estas confianzas se establecen con dominios Kerberos que cumplen con [RFC4120](https://tools.ietf.org/html/rfc4120) y que no son de Windows. Las confianzas MIT son un poco más especializadas y se adaptan a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema de Windows.

#### Otras diferencias en **relaciones de confianza**

* Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
* Una relación de confianza puede configurarse como **confianza bidireccional** (ambos confían entre sí) o como **confianza unidireccional** (solo uno de ellos confía en el otro).

### Ruta de Ataque

1. **Enumerar** las relaciones de confianza
2. Verificar si algún **principal de seguridad** (usuario/grupo/computadora) tiene **acceso** a recursos del **otro dominio**, tal vez a través de entradas ACE o al estar en grupos del otro dominio. Busca **relaciones entre dominios** (la confianza fue creada probablemente para esto).
1. Kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que pueden **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio a través de tres mecanismos principales:

* **Membresía en Grupos Locales**: Los principales podrían ser añadidos a grupos locales en máquinas, como el grupo “Administradores” en un servidor, otorgándoles un control significativo sobre esa máquina.
* **Membresía en Grupos de Dominio Extranjero**: Los principales también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza de la confianza y el alcance del grupo.
* **Listas de Control de Acceso (ACLs)**: Los principales podrían estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de un **DACL**, proporcionándoles acceso a recursos específicos. Para aquellos que buscan profundizar en la mecánica de ACLs, DACLs y ACEs, el documento titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” es un recurso invaluable.

### Escalación de privilegios de bosque de hijo a padre
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Hay **2 claves de confianza**, una para _Hijo --> Padre_ y otra para _Padre_ --> _Hijo_.\
Puedes usar la que se utiliza en el dominio actual con:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Inyección de SID-History

Escalar como administrador de la empresa al dominio hijo/padre abusando de la confianza con la inyección de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explotar NC de Configuración escribible

Entender cómo se puede explotar el Contexto de Nombres de Configuración (NC) es crucial. El NC de Configuración sirve como un repositorio central para datos de configuración en entornos de Active Directory (AD). Estos datos se replican a cada Controlador de Dominio (DC) dentro del bosque, con DCs escribibles manteniendo una copia escribible del NC de Configuración. Para explotar esto, uno debe tener **privilegios de SYSTEM en un DC**, preferiblemente un DC hijo.

**Vincular GPO al sitio raíz de DC**

El contenedor de Sitios del NC de Configuración incluye información sobre todos los sitios de computadoras unidas al dominio dentro del bosque de AD. Al operar con privilegios de SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios raíz de DC. Esta acción compromete potencialmente el dominio raíz al manipular políticas aplicadas a estos sitios.

Para información más detallada, se puede explorar la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer cualquier gMSA en el bosque**

Un vector de ataque implica apuntar a gMSAs privilegiados dentro del dominio. La clave raíz de KDS, esencial para calcular las contraseñas de gMSAs, se almacena dentro del NC de Configuración. Con privilegios de SYSTEM en cualquier DC, es posible acceder a la clave raíz de KDS y calcular las contraseñas para cualquier gMSA en todo el bosque.

Un análisis detallado se puede encontrar en la discusión sobre [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Ataque de cambio de esquema**

Este método requiere paciencia, esperando la creación de nuevos objetos AD privilegiados. Con privilegios de SYSTEM, un atacante puede modificar el Esquema de AD para otorgar a cualquier usuario control total sobre todas las clases. Esto podría llevar a acceso no autorizado y control sobre objetos AD recién creados.

Lectura adicional está disponible sobre [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta al control sobre objetos de Infraestructura de Clave Pública (PKI) para crear una plantilla de certificado que permite la autenticación como cualquier usuario dentro del bosque. Dado que los objetos PKI residen en el NC de Configuración, comprometer un DC hijo escribible permite la ejecución de ataques ESC5.

Más detalles sobre esto se pueden leer en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios que carecen de ADCS, el atacante tiene la capacidad de configurar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio de Bosque Externo - Unidireccional (Entrante) o bidireccional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
En este escenario **tu dominio es confiable** por uno externo, dándote **permisos indeterminados** sobre él. Necesitarás encontrar **qué principales de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Dominio de Bosque Externo - Unidireccional (Saliente)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **diferentes dominios**.

Sin embargo, cuando un **dominio es confiado** por el dominio que confía, el dominio confiado **crea un usuario** con un **nombre predecible** que utiliza como **contraseña la contraseña confiada**. Lo que significa que es posible **acceder a un usuario del dominio que confía para entrar en el confiado** para enumerarlo y tratar de escalar más privilegios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Otra forma de comprometer el dominio confiado es encontrar un [**enlace SQL confiado**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza del dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina donde un **usuario del dominio confiado pueda acceder** para iniciar sesión a través de **RDP**. Luego, el atacante podría inyectar código en el proceso de sesión RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de **sesión RDP**, el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigación del abuso de confianza de dominio

### **Filtrado de SID:**

* El riesgo de ataques que aprovechan el atributo de historial de SID a través de las confianzas de bosque se mitiga mediante el Filtrado de SID, que está activado por defecto en todas las confianzas inter-forestales. Esto se basa en la suposición de que las confianzas intra-forestales son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
* Sin embargo, hay un inconveniente: el filtrado de SID podría interrumpir aplicaciones y el acceso de usuarios, lo que lleva a su desactivación ocasional.

### **Autenticación Selectiva:**

* Para las confianzas inter-forestales, emplear la Autenticación Selectiva asegura que los usuarios de los dos bosques no sean autenticados automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
* Es importante señalar que estas medidas no protegen contra la explotación del Contexto de Nombres de Configuración (NC) escribible o ataques a la cuenta de confianza.

[**Más información sobre las confianzas de dominio en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algunas Defensas Generales

[**Aprende más sobre cómo proteger credenciales aquí.**](../stealing-credentials/credentials-protections.md)\\

### **Medidas Defensivas para la Protección de Credenciales**

* **Restricciones de Administradores de Dominio**: Se recomienda que los Administradores de Dominio solo puedan iniciar sesión en Controladores de Dominio, evitando su uso en otros hosts.
* **Privilegios de Cuentas de Servicio**: Los servicios no deben ejecutarse con privilegios de Administrador de Dominio (DA) para mantener la seguridad.
* **Limitación Temporal de Privilegios**: Para tareas que requieren privilegios de DA, su duración debe ser limitada. Esto se puede lograr mediante: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementación de Técnicas de Engaño**

* Implementar el engaño implica establecer trampas, como usuarios o computadoras señuelo, con características como contraseñas que no expiran o están marcadas como Confiadas para Delegación. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos de alto privilegio.
* Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Más sobre la implementación de técnicas de engaño se puede encontrar en [Deploy-Deception en GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación del Engaño**

* **Para Objetos de Usuario**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión infrecuentes, fechas de creación y bajos conteos de contraseñas incorrectas.
* **Indicadores Generales**: Comparar atributos de objetos potencialmente señuelo con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Evasión de Sistemas de Detección**

* **Evasión de Detección de Microsoft ATA**:
* **Enumeración de Usuarios**: Evitar la enumeración de sesiones en Controladores de Dominio para prevenir la detección de ATA.
* **Suplantación de Tickets**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
* **Ataques DCSync**: Se aconseja ejecutar desde un controlador de dominio no para evitar la detección de ATA, ya que la ejecución directa desde un controlador de dominio activará alertas.

## Referencias

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

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
