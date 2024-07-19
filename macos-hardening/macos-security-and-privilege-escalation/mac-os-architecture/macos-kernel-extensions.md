# macOS Kernel Extensions

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

## Información Básica

Las extensiones del kernel (Kexts) son **paquetes** con una extensión **`.kext`** que se **cargan directamente en el espacio del kernel de macOS**, proporcionando funcionalidad adicional al sistema operativo principal.

### Requisitos

Obviamente, esto es tan poderoso que es **complicado cargar una extensión del kernel**. Estos son los **requisitos** que una extensión del kernel debe cumplir para ser cargada:

* Al **ingresar al modo de recuperación**, las **extensiones del kernel deben ser permitidas** para ser cargadas:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* La extensión del kernel debe estar **firmada con un certificado de firma de código del kernel**, que solo puede ser **otorgado por Apple**. Quien revisará en detalle la empresa y las razones por las que se necesita.
* La extensión del kernel también debe estar **notarizada**, Apple podrá verificarla en busca de malware.
* Luego, el usuario **root** es quien puede **cargar la extensión del kernel** y los archivos dentro del paquete deben **pertenecer a root**.
* Durante el proceso de carga, el paquete debe estar preparado en una **ubicación protegida no root**: `/Library/StagedExtensions` (requiere el permiso `com.apple.rootless.storage.KernelExtensionManagement`).
* Finalmente, al intentar cargarla, el usuario [**recibirá una solicitud de confirmación**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) y, si se acepta, la computadora debe ser **reiniciada** para cargarla.

### Proceso de carga

En Catalina fue así: Es interesante notar que el proceso de **verificación** ocurre en **userland**. Sin embargo, solo las aplicaciones con el permiso **`com.apple.private.security.kext-management`** pueden **solicitar al kernel que cargue una extensión**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** el proceso de **verificación** para cargar una extensión
* Hablará con **`kextd`** enviando usando un **servicio Mach**.
2. **`kextd`** verificará varias cosas, como la **firma**
* Hablará con **`syspolicyd`** para **verificar** si la extensión puede ser **cargada**.
3. **`syspolicyd`** **preguntará** al **usuario** si la extensión no ha sido cargada previamente.
* **`syspolicyd`** informará el resultado a **`kextd`**
4. **`kextd`** finalmente podrá **decirle al kernel que cargue** la extensión

Si **`kextd`** no está disponible, **`kextutil`** puede realizar las mismas verificaciones.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
