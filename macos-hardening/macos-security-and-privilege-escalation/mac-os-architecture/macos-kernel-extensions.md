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

## Informações Básicas

As extensões de kernel (Kexts) são **pacotes** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidade adicional ao sistema operacional principal.

### Requisitos

Obviamente, isso é tão poderoso que é **complicado carregar uma extensão de kernel**. Estes são os **requisitos** que uma extensão de kernel deve atender para ser carregada:

* Ao **entrar no modo de recuperação**, as **extensões de kernel devem ser permitidas** para serem carregadas:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* A extensão de kernel deve ser **assinada com um certificado de assinatura de código de kernel**, que só pode ser **concedido pela Apple**. Quem revisará em detalhes a empresa e as razões pelas quais é necessário.
* A extensão de kernel também deve ser **notarizada**, a Apple poderá verificá-la em busca de malware.
* Então, o usuário **root** é quem pode **carregar a extensão de kernel** e os arquivos dentro do pacote devem **pertencer ao root**.
* Durante o processo de upload, o pacote deve ser preparado em um **local protegido não-root**: `/Library/StagedExtensions` (requer a concessão `com.apple.rootless.storage.KernelExtensionManagement`).
* Finalmente, ao tentar carregá-la, o usuário [**receberá um pedido de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceito, o computador deve ser **reiniciado** para carregá-la.

### Processo de Carregamento

Em Catalina era assim: É interessante notar que o processo de **verificação** ocorre em **userland**. No entanto, apenas aplicativos com a concessão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel que carregue uma extensão**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** o processo de **verificação** para carregar uma extensão
* Ele se comunicará com **`kextd`** enviando usando um **serviço Mach**.
2. **`kextd`** verificará várias coisas, como a **assinatura**
* Ele se comunicará com **`syspolicyd`** para **verificar** se a extensão pode ser **carregada**.
3. **`syspolicyd`** **pedirá** ao **usuário** se a extensão não foi carregada anteriormente.
* **`syspolicyd`** relatará o resultado para **`kextd`**
4. **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extensão

Se **`kextd`** não estiver disponível, **`kextutil`** pode realizar as mesmas verificações.

## Referências

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
