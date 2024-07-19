# Writable Sys Path +Dll Hijacking Privesc

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

## Introducción

Si descubres que puedes **escribir en una carpeta de System Path** (ten en cuenta que esto no funcionará si puedes escribir en una carpeta de User Path) es posible que puedas **escalar privilegios** en el sistema.

Para hacer esto, puedes abusar de un **Dll Hijacking** donde vas a **secuestrar una biblioteca que está siendo cargada** por un servicio o proceso con **más privilegios** que los tuyos, y debido a que ese servicio está cargando una Dll que probablemente ni siquiera existe en todo el sistema, intentará cargarla desde el System Path donde puedes escribir.

Para más información sobre **qué es Dll Hijacking** consulta:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc con Dll Hijacking

### Encontrar una Dll faltante

Lo primero que necesitas es **identificar un proceso** que se esté ejecutando con **más privilegios** que tú y que esté intentando **cargar una Dll desde el System Path** en el que puedes escribir.

El problema en estos casos es que probablemente esos procesos ya estén en ejecución. Para encontrar qué Dlls faltan a los servicios, necesitas lanzar procmon lo antes posible (antes de que se carguen los procesos). Así que, para encontrar .dlls faltantes, haz lo siguiente:

* **Crea** la carpeta `C:\privesc_hijacking` y agrega la ruta `C:\privesc_hijacking` a la **variable de entorno System Path**. Puedes hacer esto **manualmente** o con **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Inicie **`procmon`** y vaya a **`Options`** --> **`Enable boot logging`** y presione **`OK`** en el aviso.
* Luego, **reinicie**. Cuando la computadora se reinicie, **`procmon`** comenzará a **grabar** eventos lo antes posible.
* Una vez que **Windows** esté **iniciado, ejecute `procmon`** nuevamente, le dirá que ha estado funcionando y le **preguntará si desea almacenar** los eventos en un archivo. Diga **sí** y **almacene los eventos en un archivo**.
* **Después** de que se **genere el archivo**, **cierre** la ventana de **`procmon`** abierta y **abra el archivo de eventos**.
* Agregue estos **filtros** y encontrará todos los Dlls que algún **proceso intentó cargar** desde la carpeta de System Path escribible:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Dlls Perdidos

Ejecutando esto en una **máquina virtual (vmware) Windows 11** gratuita, obtuve estos resultados:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

En este caso, los .exe son inútiles, así que ignórelos, los DLLs perdidos eran de:

| Servicio                         | Dll                | Línea de CMD                                                         |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Programador de tareas (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Servicio de política de diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Después de encontrar esto, encontré esta interesante publicación de blog que también explica cómo [**abusar de WptsExtensions.dll para privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Que es lo que **vamos a hacer ahora**.

### Explotación

Entonces, para **escalar privilegios**, vamos a secuestrar la biblioteca **WptsExtensions.dll**. Teniendo el **ruta** y el **nombre**, solo necesitamos **generar el dll malicioso**.

Puede [**intentar usar cualquiera de estos ejemplos**](./#creating-and-compiling-dlls). Podría ejecutar cargas útiles como: obtener un rev shell, agregar un usuario, ejecutar un beacon...

{% hint style="warning" %}
Tenga en cuenta que **no todos los servicios se ejecutan** con **`NT AUTHORITY\SYSTEM`**, algunos también se ejecutan con **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios** y **no podrá crear un nuevo usuario** abusando de sus permisos.\
Sin embargo, ese usuario tiene el privilegio **`seImpersonate`**, por lo que puede usar el [**potato suite para escalar privilegios**](../roguepotato-and-printspoofer.md). Así que, en este caso, un rev shell es una mejor opción que intentar crear un usuario.
{% endhint %}

En el momento de escribir, el servicio de **Programador de tareas** se ejecuta con **Nt AUTHORITY\SYSTEM**.

Habiendo **generado el Dll malicioso** (_en mi caso usé un rev shell x64 y obtuve un shell de vuelta, pero defender lo eliminó porque era de msfvenom_), guárdelo en la ruta de sistema escribible con el nombre **WptsExtensions.dll** y **reinicie** la computadora (o reinicie el servicio o haga lo que sea necesario para volver a ejecutar el servicio/programa afectado).

Cuando el servicio se reinicie, el **dll debería ser cargado y ejecutado** (puede **reutilizar** el truco de **procmon** para verificar si la **biblioteca se cargó como se esperaba**).

{% hint style="success" %}
Aprenda y practique Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda y practique Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoye a HackTricks</summary>

* Consulte los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síganos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparta trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
