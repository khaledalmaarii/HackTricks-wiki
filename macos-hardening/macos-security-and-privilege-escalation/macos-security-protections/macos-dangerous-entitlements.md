# macOS Dangerous Entitlements & TCC perms

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

{% hint style="warning" %}
Tenga en cuenta que los derechos que comienzan con **`com.apple`** no están disponibles para terceros, solo Apple puede otorgarlos.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

El derecho **`com.apple.rootless.install.heritable`** permite **eludir SIP**. Consulte [esto para más información](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

El derecho **`com.apple.rootless.install`** permite **eludir SIP**. Consulte [esto para más información](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente llamado `task_for_pid-allow`)**

Este derecho permite obtener el **puerto de tarea para cualquier** proceso, excepto el núcleo. Consulte [**esto para más información**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Este derecho permite a otros procesos con el derecho **`com.apple.security.cs.debugger`** obtener el puerto de tarea del proceso ejecutado por el binario con este derecho y **inyectar código en él**. Consulte [**esto para más información**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Las aplicaciones con el derecho de Herramienta de Depuración pueden llamar a `task_for_pid()` para recuperar un puerto de tarea válido para aplicaciones no firmadas y de terceros con el derecho `Get Task Allow` establecido en `true`. Sin embargo, incluso con el derecho de herramienta de depuración, un depurador **no puede obtener los puertos de tarea** de procesos que **no tienen el derecho `Get Task Allow`**, y que por lo tanto están protegidos por la Protección de Integridad del Sistema. Consulte [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Este derecho permite **cargar frameworks, plug-ins o bibliotecas sin estar firmados por Apple o firmados con el mismo Team ID** que el ejecutable principal, por lo que un atacante podría abusar de alguna carga de biblioteca arbitraria para inyectar código. Consulte [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este derecho es muy similar a **`com.apple.security.cs.disable-library-validation`** pero **en lugar de** **deshabilitar directamente** la validación de bibliotecas, permite que el proceso **llame a una llamada al sistema `csops` para deshabilitarla**.\
Consulte [**esto para más información**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este derecho permite **usar variables de entorno DYLD** que podrían usarse para inyectar bibliotecas y código. Consulte [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Según este blog**](https://objective-see.org/blog/blog\_0x4C.html) **y** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estos derechos permiten **modificar** la base de datos **TCC**.

### **`system.install.apple-software`** y **`system.install.apple-software.standar-user`**

Estos derechos permiten **instalar software sin pedir permisos** al usuario, lo que puede ser útil para una **escalada de privilegios**.

### `com.apple.private.security.kext-management`

Derecho necesario para pedir al **núcleo que cargue una extensión del núcleo**.

### **`com.apple.private.icloud-account-access`**

El derecho **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`** que proporcionará **tokens de iCloud**.

**iMovie** y **Garageband** tenían este derecho.

Para más **información** sobre el exploit para **obtener tokens de iCloud** de ese derecho, consulte la charla: [**#OBTS v5.0: "¿Qué sucede en tu Mac, se queda en iCloud de Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: No sé qué permite hacer esto

### `com.apple.private.apfs.revert-to-snapshot`

TODO: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. Si sabe cómo, envíe un PR, ¡por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **se menciona que esto podría usarse para** actualizar los contenidos protegidos por SSV después de un reinicio. Si sabe cómo, envíe un PR, ¡por favor!

### `keychain-access-groups`

Este derecho lista los grupos de **keychain** a los que la aplicación tiene acceso:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Otorga permisos de **Acceso Completo al Disco**, uno de los permisos más altos de TCC que puedes tener.

### **`kTCCServiceAppleEvents`**

Permite a la aplicación enviar eventos a otras aplicaciones que se utilizan comúnmente para **automatizar tareas**. Al controlar otras aplicaciones, puede abusar de los permisos otorgados a estas otras aplicaciones.

Como hacer que le pidan al usuario su contraseña:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

O hacer que realicen **acciones arbitrarias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre otros permisos, **escribir la base de datos TCC de los usuarios**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia la ruta de su carpeta de inicio y, por lo tanto, permite **eludir TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar archivos dentro de los paquetes de aplicaciones (dentro de app.app), lo cual está **prohibido por defecto**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Es posible verificar quién tiene este acceso en _Configuración del Sistema_ > _Privacidad y Seguridad_ > _Gestión de Aplicaciones._

### `kTCCServiceAccessibility`

El proceso podrá **abusar de las características de accesibilidad de macOS**, lo que significa que, por ejemplo, podrá presionar combinaciones de teclas. Así que podría solicitar acceso para controlar una aplicación como Finder y aprobar el diálogo con este permiso.

## Medio

### `com.apple.security.cs.allow-jit`

Este derecho permite **crear memoria que es escribible y ejecutable** al pasar la bandera `MAP_JIT` a la función del sistema `mmap()`. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este derecho permite **sobrescribir o parchear código C**, usar el obsoleto **`NSCreateObjectFileImageFromMemory`** (que es fundamentalmente inseguro), o usar el marco **DVDPlayback**. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir este derecho expone tu aplicación a vulnerabilidades comunes en lenguajes de código inseguros en memoria. Considera cuidadosamente si tu aplicación necesita esta excepción.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Este derecho permite **modificar secciones de sus propios archivos ejecutables** en disco para salir forzosamente. Consulta [**esto para más información**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
El Derecho de Desactivar la Protección de Memoria Ejecutable es un derecho extremo que elimina una protección de seguridad fundamental de tu aplicación, lo que permite a un atacante reescribir el código ejecutable de tu aplicación sin detección. Prefiere derechos más restringidos si es posible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Este derecho permite montar un sistema de archivos nullfs (prohibido por defecto). Herramienta: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Según esta publicación de blog, este permiso TCC generalmente se encuentra en la forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permitir que el proceso **pida todos los permisos de TCC**.

### **`kTCCServicePostEvent`**
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
</details>
