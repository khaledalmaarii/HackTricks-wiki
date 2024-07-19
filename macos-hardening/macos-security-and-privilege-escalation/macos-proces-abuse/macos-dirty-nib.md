# macOS Dirty NIB

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

**Para más detalles sobre la técnica, consulta la publicación original en: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Aquí hay un resumen:

Los archivos NIB, parte del ecosistema de desarrollo de Apple, están destinados a definir **elementos de UI** y sus interacciones en aplicaciones. Incluyen objetos serializados como ventanas y botones, y se cargan en tiempo de ejecución. A pesar de su uso continuo, Apple ahora aboga por Storyboards para una visualización más completa del flujo de UI.

### Preocupaciones de Seguridad con Archivos NIB
Es crítico notar que **los archivos NIB pueden ser un riesgo de seguridad**. Tienen el potencial de **ejecutar comandos arbitrarios**, y las alteraciones a los archivos NIB dentro de una aplicación no impiden que Gatekeeper ejecute la aplicación, lo que representa una amenaza significativa.

### Proceso de Inyección de Dirty NIB
#### Creación y Configuración de un Archivo NIB
1. **Configuración Inicial**:
- Crea un nuevo archivo NIB usando XCode.
- Agrega un objeto a la interfaz, configurando su clase a `NSAppleScript`.
- Configura la propiedad `source` inicial a través de Atributos de Tiempo de Ejecución Definidos por el Usuario.

2. **Gadget de Ejecución de Código**:
- La configuración facilita la ejecución de AppleScript bajo demanda.
- Integra un botón para activar el objeto `Apple Script`, específicamente disparando el selector `executeAndReturnError:`.

3. **Pruebas**:
- Un simple Apple Script para propósitos de prueba:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Prueba ejecutando en el depurador de XCode y haciendo clic en el botón.

#### Apuntando a una Aplicación (Ejemplo: Pages)
1. **Preparación**:
- Copia la aplicación objetivo (por ejemplo, Pages) en un directorio separado (por ejemplo, `/tmp/`).
- Inicia la aplicación para evitar problemas con Gatekeeper y almacenarla en caché.

2. **Sobrescribiendo el Archivo NIB**:
- Reemplaza un archivo NIB existente (por ejemplo, el NIB del Panel Acerca de) con el archivo DirtyNIB creado.

3. **Ejecución**:
- Dispara la ejecución interactuando con la aplicación (por ejemplo, seleccionando el elemento del menú `Acerca de`).

#### Prueba de Concepto: Acceso a Datos del Usuario
- Modifica el AppleScript para acceder y extraer datos del usuario, como fotos, sin el consentimiento del usuario.

### Ejemplo de Código: Archivo .xib Malicioso
- Accede y revisa un [**ejemplo de un archivo .xib malicioso**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) que demuestra la ejecución de código arbitrario.

### Abordando las Restricciones de Lanzamiento
- Las restricciones de lanzamiento dificultan la ejecución de aplicaciones desde ubicaciones inesperadas (por ejemplo, `/tmp`).
- Es posible identificar aplicaciones que no están protegidas por restricciones de lanzamiento y apuntar a ellas para la inyección de archivos NIB.

### Protecciones Adicionales de macOS
Desde macOS Sonoma, las modificaciones dentro de los paquetes de aplicaciones están restringidas. Sin embargo, los métodos anteriores involucraban:
1. Copiar la aplicación a una ubicación diferente (por ejemplo, `/tmp/`).
2. Renombrar directorios dentro del paquete de la aplicación para eludir las protecciones iniciales.
3. Después de ejecutar la aplicación para registrarse con Gatekeeper, modificar el paquete de la aplicación (por ejemplo, reemplazando MainMenu.nib con Dirty.nib).
4. Renombrar los directorios de nuevo y volver a ejecutar la aplicación para ejecutar el archivo NIB inyectado.

**Nota**: Las actualizaciones recientes de macOS han mitigado este exploit al prevenir modificaciones de archivos dentro de los paquetes de aplicaciones después de la caché de Gatekeeper, lo que hace que el exploit sea ineficaz.


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
