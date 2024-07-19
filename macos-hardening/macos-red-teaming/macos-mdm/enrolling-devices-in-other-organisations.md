# Inscripción de Dispositivos en Otras Organizaciones

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Introducción

Como [**se comentó anteriormente**](./#what-is-mdm-mobile-device-management)**,** para intentar inscribir un dispositivo en una organización **solo se necesita un número de serie que pertenezca a esa organización**. Una vez que el dispositivo está inscrito, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y así sucesivamente](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Por lo tanto, este podría ser un punto de entrada peligroso para los atacantes si el proceso de inscripción no está correctamente protegido.

**A continuación se presenta un resumen de la investigación [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). ¡Consúltalo para más detalles técnicos!**

## Visión General del Análisis Binario de DEP y MDM

Esta investigación profundiza en los binarios asociados con el Programa de Inscripción de Dispositivos (DEP) y la Gestión de Dispositivos Móviles (MDM) en macOS. Los componentes clave incluyen:

- **`mdmclient`**: Se comunica con los servidores MDM y activa los registros de DEP en versiones de macOS anteriores a 10.13.4.
- **`profiles`**: Gestiona los Perfiles de Configuración y activa los registros de DEP en versiones de macOS 10.13.4 y posteriores.
- **`cloudconfigurationd`**: Gestiona las comunicaciones de la API de DEP y recupera los perfiles de Inscripción de Dispositivos.

Los registros de DEP utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` del marco privado de Perfiles de Configuración para obtener el Registro de Activación, siendo `CPFetchActivationRecord` el que coordina con `cloudconfigurationd` a través de XPC.

## Ingeniería Inversa del Protocolo Tesla y Esquema Absinthe

El registro de DEP implica que `cloudconfigurationd` envíe una carga útil JSON cifrada y firmada a _iprofiles.apple.com/macProfile_. La carga útil incluye el número de serie del dispositivo y la acción "RequestProfileConfiguration". El esquema de cifrado utilizado se conoce internamente como "Absinthe". Desentrañar este esquema es complejo e implica numerosos pasos, lo que llevó a explorar métodos alternativos para insertar números de serie arbitrarios en la solicitud del Registro de Activación.

## Interceptando Solicitudes de DEP

Los intentos de interceptar y modificar solicitudes de DEP a _iprofiles.apple.com_ utilizando herramientas como Charles Proxy se vieron obstaculizados por el cifrado de la carga útil y las medidas de seguridad SSL/TLS. Sin embargo, habilitar la configuración `MCCloudConfigAcceptAnyHTTPSCertificate` permite eludir la validación del certificado del servidor, aunque la naturaleza cifrada de la carga útil aún impide la modificación del número de serie sin la clave de descifrado.

## Instrumentando Binarios del Sistema que Interactúan con DEP

Instrumentar binarios del sistema como `cloudconfigurationd` requiere deshabilitar la Protección de Integridad del Sistema (SIP) en macOS. Con SIP deshabilitado, se pueden utilizar herramientas como LLDB para adjuntarse a procesos del sistema y potencialmente modificar el número de serie utilizado en las interacciones de la API de DEP. Este método es preferible ya que evita las complejidades de los derechos y la firma de código.

**Explotando la Instrumentación Binaria:**
Modificar la carga útil de la solicitud de DEP antes de la serialización JSON en `cloudconfigurationd` resultó efectivo. El proceso implicó:

1. Adjuntar LLDB a `cloudconfigurationd`.
2. Localizar el punto donde se obtiene el número de serie del sistema.
3. Inyectar un número de serie arbitrario en la memoria antes de que la carga útil sea cifrada y enviada.

Este método permitió recuperar perfiles completos de DEP para números de serie arbitrarios, demostrando una posible vulnerabilidad.

### Automatizando la Instrumentación con Python

El proceso de explotación se automatizó utilizando Python con la API de LLDB, lo que hizo factible inyectar programáticamente números de serie arbitrarios y recuperar los perfiles de DEP correspondientes.

### Impactos Potenciales de las Vulnerabilidades de DEP y MDM

La investigación destacó preocupaciones de seguridad significativas:

1. **Divulgación de Información**: Al proporcionar un número de serie registrado en DEP, se puede recuperar información organizacional sensible contenida en el perfil de DEP.
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
