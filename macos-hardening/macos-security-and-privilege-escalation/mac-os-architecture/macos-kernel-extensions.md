# Extensões do Kernel do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Extensões do kernel (Kexts) são **pacotes** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidades adicionais ao sistema operacional principal.

### Requisitos

Obviamente, isso é tão poderoso que é **complicado carregar uma extensão do kernel**. Estes são os **requisitos** que uma extensão do kernel deve cumprir para ser carregada:

* Ao **entrar no modo de recuperação**, as extensões do kernel **devem ser permitidas** para serem carregadas:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* A extensão do kernel deve ser **assinada com um certificado de assinatura de código do kernel**, que só pode ser **concedido pela Apple**. A Apple revisará detalhadamente a empresa e os motivos pelos quais é necessária.
* A extensão do kernel também deve ser **notarizada**, permitindo que a Apple a verifique quanto a malware.
* Então, o usuário **root** é quem pode **carregar a extensão do kernel** e os arquivos dentro do pacote devem **pertencer ao root**.
* Durante o processo de carregamento, o pacote deve ser preparado em uma **localização protegida não-root**: `/Library/StagedExtensions` (requer a permissão `com.apple.rootless.storage.KernelExtensionManagement`).
* Finalmente, ao tentar carregá-la, o usuário receberá [**um pedido de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) e, se aceito, o computador deve ser **reiniciado** para carregá-la.

### Processo de Carregamento

Em Catalina era assim: É interessante notar que o processo de **verificação** ocorre no **userland**. No entanto, apenas aplicações com a permissão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel para carregar uma extensão**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. A CLI **`kextutil`** **inicia** o processo de **verificação** para carregar uma extensão
* Ela se comunicará com o **`kextd`** enviando um serviço **Mach**.
2. **`kextd`** verificará várias coisas, como a **assinatura**
* Ele se comunicará com o **`syspolicyd`** para **verificar** se a extensão pode ser **carregada**.
3. **`syspolicyd`** irá **solicitar** ao **usuário** se a extensão ainda não foi carregada anteriormente.
* **`syspolicyd`** informará o resultado ao **`kextd`**.
4. **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extensão

Se **`kextd`** não estiver disponível, **`kextutil`** pode realizar as mesmas verificações.

## Referências

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
