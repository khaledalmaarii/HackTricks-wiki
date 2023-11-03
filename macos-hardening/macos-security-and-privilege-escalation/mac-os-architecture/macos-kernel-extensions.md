# Extensões de Kernel do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações básicas

As extensões de kernel (Kexts) são **pacotes** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidades adicionais ao sistema operacional principal.

### Requisitos

Obviamente, isso é tão poderoso que é **complicado carregar uma extensão de kernel**. Estes são os **requisitos** que uma extensão de kernel deve atender para ser carregada:

* Ao **entrar no modo de recuperação**, as **extensões de kernel devem ser permitidas** para serem carregadas:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* A extensão de kernel deve ser **assinada com um certificado de assinatura de código do kernel**, que só pode ser **concedido pela Apple**. A Apple irá revisar detalhadamente a empresa e as razões pelas quais ela é necessária.
* A extensão de kernel também deve ser **notarizada**, a Apple poderá verificá-la em busca de malware.
* Em seguida, o usuário **root** é aquele que pode **carregar a extensão de kernel** e os arquivos dentro do pacote devem **pertencer ao root**.
* Durante o processo de carregamento, o pacote deve ser preparado em um **local protegido não-root**: `/Library/StagedExtensions` (requer a concessão `com.apple.rootless.storage.KernelExtensionManagement`).
* Por fim, ao tentar carregá-la, o usuário receberá uma [**solicitação de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) e, se aceita, o computador deve ser **reiniciado** para carregá-la.

### Processo de carregamento

No Catalina era assim: É interessante notar que o processo de **verificação** ocorre em **userland**. No entanto, apenas aplicativos com a concessão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel que carregue uma extensão**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. O cli **`kextutil`** **inicia** o processo de **verificação** para carregar uma extensão
* Ele irá se comunicar com o **`kextd`** enviando usando um **serviço Mach**.
2. O **`kextd`** verificará várias coisas, como a **assinatura**
* Ele irá se comunicar com o **`syspolicyd`** para **verificar** se a extensão pode ser **carregada**.
3. O **`syspolicyd`** irá **solicitar** ao **usuário** se a extensão não tiver sido carregada anteriormente.
* O **`syspolicyd`** irá relatar o resultado ao **`kextd`**
4. O **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extensão

Se o **`kextd`** não estiver disponível, o **`kextutil`** pode realizar as mesmas verificações.

## Referências

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
