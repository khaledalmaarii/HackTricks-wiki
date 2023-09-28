# Extensões de Kernel do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS e HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Compartilhe suas dicas de hacking enviando um PR para** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações básicas

As extensões de kernel (Kexts) são **pacotes** com a extensão **`.kext`** que são **carregados diretamente no espaço do kernel** do macOS, fornecendo funcionalidades adicionais ao sistema operacional principal.

### Requisitos

Obviamente, isso é tão poderoso que é complicado carregar uma extensão de kernel. Estes são os requisitos que uma extensão de kernel deve atender para ser carregada:

* Ao entrar no **modo de recuperação**, as extensões de kernel devem estar **habilitadas para carregamento**:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* A extensão de kernel deve estar **assinada com um certificado de assinatura de código de kernel**, que só pode ser concedido pela **Apple**. Eles revisarão detalhadamente a **empresa** e as **razões** pelas quais é necessária.
* A extensão de kernel também deve ser **notarizada**, a Apple poderá verificá-la em busca de malware.
* Em seguida, o **usuário root** é quem pode carregar a extensão de kernel e os arquivos dentro do pacote devem pertencer ao root.
* Durante o processo de carregamento, o pacote deve ser preparado em uma localização protegida sem raiz: `/Library/StagedExtensions` (requer a concessão `com.apple.rootless.storage.KernelExtensionManagement`)
* Por fim, ao tentar carregá-lo, o [**usuário receberá uma solicitação de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) e, se aceita, o computador deve ser **reiniciado** para carregá-lo.

### Processo de carregamento

No Catalina, era assim: É interessante notar que o processo de **verificação** ocorre no **userland**. No entanto, apenas aplicativos com a concessão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel** que **carregue uma extensão:** kextcache, kextload, kextutil, kextd, syspolicyd

1. O cli **`kextutil`** inicia o processo de verificação para carregar uma extensão

* Ele se comunica com o **`kextd`** usando um serviço Mach

2. O **`kextd`** verifica várias coisas, como a assinatura

* Ele se comunica com o **`syspolicyd`** para verificar se a extensão pode ser carregada

3. O **`syspolicyd`** **pergunta** ao **usuário** se a extensão não foi carregada anteriormente

* O **`syspolicyd`** informa o resultado ao **`kextd`**

4. O **`kextd`** finalmente pode instruir o **kernel a carregar a extensão**

Se o kextd não estiver disponível, o kextutil pode realizar as mesmas verificações.

## Referências

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS e HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Compartilhe suas técnicas de hacking enviando um PR para** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
