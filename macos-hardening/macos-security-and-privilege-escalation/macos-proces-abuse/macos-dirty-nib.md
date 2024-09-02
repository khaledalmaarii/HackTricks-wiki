# macOS Dirty NIB

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Para más detalles sobre la técnica, consulta la publicación original en:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) y la siguiente publicación de [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Aquí hay un resumen:

### ¿Qué son los archivos NIB?

Los archivos Nib (abreviatura de NeXT Interface Builder), parte del ecosistema de desarrollo de Apple, están destinados a definir **elementos de UI** y sus interacciones en aplicaciones. Incluyen objetos serializados como ventanas y botones, y se cargan en tiempo de ejecución. A pesar de su uso continuo, Apple ahora aboga por Storyboards para una visualización más completa del flujo de UI.

El archivo Nib principal se referencia en el valor **`NSMainNibFile`** dentro del archivo `Info.plist` de la aplicación y se carga mediante la función **`NSApplicationMain`** ejecutada en la función `main` de la aplicación.

### Proceso de Inyección de Dirty Nib

#### Creación y Configuración de un Archivo NIB

1. **Configuración Inicial**:
* Crea un nuevo archivo NIB usando XCode.
* Agrega un objeto a la interfaz, configurando su clase a `NSAppleScript`.
* Configura la propiedad `source` inicial a través de Atributos de Tiempo de Ejecución Definidos por el Usuario.
2. **Gadget de Ejecución de Código**:
* La configuración facilita la ejecución de AppleScript bajo demanda.
* Integra un botón para activar el objeto `Apple Script`, desencadenando específicamente el selector `executeAndReturnError:`.
3. **Pruebas**:
* Un simple Apple Script para fines de prueba:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* Prueba ejecutando en el depurador de XCode y haciendo clic en el botón.

#### Apuntando a una Aplicación (Ejemplo: Pages)

1. **Preparación**:
* Copia la aplicación objetivo (por ejemplo, Pages) en un directorio separado (por ejemplo, `/tmp/`).
* Inicia la aplicación para eludir problemas de Gatekeeper y almacenarla en caché.
2. **Sobrescribiendo el Archivo NIB**:
* Reemplaza un archivo NIB existente (por ejemplo, About Panel NIB) con el archivo DirtyNIB creado.
3. **Ejecución**:
* Desencadena la ejecución interactuando con la aplicación (por ejemplo, seleccionando el elemento del menú `About`).

#### Prueba de Concepto: Acceso a Datos del Usuario

* Modifica el AppleScript para acceder y extraer datos del usuario, como fotos, sin el consentimiento del usuario.

### Ejemplo de Código: Archivo .xib Malicioso

* Accede y revisa un [**ejemplo de un archivo .xib malicioso**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) que demuestra la ejecución de código arbitrario.

### Otro Ejemplo

En la publicación [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) puedes encontrar un tutorial sobre cómo crear un dirty nib.&#x20;

### Abordando las Restricciones de Lanzamiento

* Las restricciones de lanzamiento obstaculizan la ejecución de aplicaciones desde ubicaciones inesperadas (por ejemplo, `/tmp`).
* Es posible identificar aplicaciones que no están protegidas por restricciones de lanzamiento y apuntar a ellas para la inyección de archivos NIB.

### Otras Protecciones de macOS

Desde macOS Sonoma en adelante, las modificaciones dentro de los paquetes de aplicaciones están restringidas. Sin embargo, los métodos anteriores involucraban:

1. Copiar la aplicación a una ubicación diferente (por ejemplo, `/tmp/`).
2. Renombrar directorios dentro del paquete de la aplicación para eludir las protecciones iniciales.
3. Después de ejecutar la aplicación para registrarse con Gatekeeper, modificar el paquete de la aplicación (por ejemplo, reemplazando MainMenu.nib con Dirty.nib).
4. Renombrar los directorios de nuevo y volver a ejecutar la aplicación para ejecutar el archivo NIB inyectado.

**Nota**: Las actualizaciones recientes de macOS han mitigado este exploit al prevenir modificaciones de archivos dentro de los paquetes de aplicaciones después de la caché de Gatekeeper, lo que hace que el exploit sea ineficaz.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
