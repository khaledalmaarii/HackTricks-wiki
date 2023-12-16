# macOS Entitlements Perigosos e Permissões TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Observe que as permissões que começam com **`com.apple`** não estão disponíveis para terceiros, apenas a Apple pode concedê-las.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

A permissão **`com.apple.rootless.install.heritable`** permite **burlar o SIP**. Verifique [isso para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

A permissão **`com.apple.rootless.install`** permite **burlar o SIP**. Verifique [isso para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente chamado de `task_for_pid-allow`)**

Essa permissão permite obter a **porta da tarefa para qualquer** processo, exceto o kernel. Verifique [**isso para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Essa permissão permite que outros processos com a permissão **`com.apple.security.cs.debugger`** obtenham a porta da tarefa do processo executado pelo binário com essa permissão e **injetem código nele**. Verifique [**isso para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplicativos com a Permissão da Ferramenta de Depuração podem chamar `task_for_pid()` para recuperar uma porta de tarefa válida para aplicativos não assinados e de terceiros com a permissão `Get Task Allow` definida como `true`. No entanto, mesmo com a permissão da ferramenta de depuração, um depurador **não pode obter as portas de tarefa** de processos que **não possuem a permissão `Get Task Allow`**, e que portanto estão protegidos pela Proteção de Integridade do Sistema. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Essa permissão permite **carregar frameworks, plug-ins ou bibliotecas sem serem assinados pela Apple ou assinados com o mesmo ID de equipe** que o executável principal, portanto, um invasor pode abusar de alguma carga de biblioteca arbitrária para injetar código. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Essa permissão é muito semelhante a **`com.apple.security.cs.disable-library-validation`**, mas **em vez disso** de **desabilitar diretamente** a validação da biblioteca, ela permite que o processo **chame uma chamada de sistema `csops` para desabilitá-la**.\
Verifique [**isso para mais informações**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Essa permissão permite **usar variáveis de ambiente DYLD** que podem ser usadas para injetar bibliotecas e código. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), essas permissões permitem **modificar** o **banco de dados TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Essas permissões permitem **instalar software sem solicitar permissões** ao usuário, o que pode ser útil para uma **elevação de privilégios**.

### `com.apple.private.security.kext-management`

Permissão necessária para solicitar ao **kernel que carregue uma extensão de kernel**.

### **`com.apple.private.icloud-account-access`**

A permissão **`com.apple.private.icloud-account-access`** permite comunicar-se com o serviço XPC **`com.apple.iCloudHelper`**, que fornecerá tokens do iCloud.

**iMovie** e **Garageband** tinham essa permissão.

Para mais **informações** sobre a exploração para **obter tokens do iCloud** dessa permissão, confira a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)
### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Neste [**relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) é mencionado que isso poderia ser usado para atualizar o conteúdo protegido pelo SSV após uma reinicialização. Se você souber como fazer isso, envie um PR, por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Neste [**relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) é mencionado que isso poderia ser usado para atualizar o conteúdo protegido pelo SSV após uma reinicialização. Se você souber como fazer isso, envie um PR, por favor!

### `keychain-access-groups`

Esta lista de permissões **keychain** agrupa os grupos aos quais o aplicativo tem acesso:
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

Concede permissões de **Acesso Total ao Disco**, uma das permissões mais altas do TCC que você pode ter.

### **`kTCCServiceAppleEvents`**

Permite que o aplicativo envie eventos para outras aplicações que são comumente usadas para **automatizar tarefas**. Controlando outros aplicativos, ele pode abusar das permissões concedidas a esses outros aplicativos.

Como fazer com que eles peçam a senha do usuário:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ou fazendo-os executar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC do usuário**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário que altera o caminho da pasta inicial e, portanto, permite **burlar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro do pacote do aplicativo (dentro do app.app), o que é **desativado por padrão**.

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Configurações do Sistema_ > _Privacidade e Segurança_ > _Gerenciamento de Aplicativos._

## Médio

### `com.apple.security.cs.allow-jit`

Essa permissão permite **criar memória que pode ser gravada e executada** passando a flag `MAP_JIT` para a função de sistema `mmap()`. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Essa permissão permite **sobrescrever ou corrigir código C**, usar o framework **DVDPlayback** ou usar o **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro). Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir essa permissão expõe seu aplicativo a vulnerabilidades comuns em linguagens de código inseguro em memória. Considere cuidadosamente se seu aplicativo precisa dessa exceção.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Essa permissão permite **modificar seções de seus próprios arquivos executáveis** no disco para sair forçadamente. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
A permissão de Desabilitar Proteção de Memória Executável é uma permissão extrema que remove uma proteção de segurança fundamental do seu aplicativo, tornando possível que um invasor reescreva o código executável do seu aplicativo sem detecção. Prefira permissões mais restritas, se possível.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Essa permissão permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com este post do blog, essa permissão do TCC geralmente é encontrada na forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permita que o processo **solicite todas as permissões do TCC**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
