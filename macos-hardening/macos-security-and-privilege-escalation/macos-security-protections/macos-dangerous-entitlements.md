# Permissões Perigosas do macOS & Permissões TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Observe que permissões começando com **`com.apple`** não estão disponíveis para terceiros, apenas a Apple pode concedê-las.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

A permissão **`com.apple.rootless.install.heritable`** permite **bypass no SIP**. Verifique [isto para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

A permissão **`com.apple.rootless.install`** permite **bypass no SIP**. Verifique [isto para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente chamado `task_for_pid-allow`)**

Esta permissão permite obter o **task port para qualquer** processo, exceto o kernel. Verifique [**isto para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Esta permissão permite que outros processos com a permissão **`com.apple.security.cs.debugger`** obtenham o task port do processo executado pelo binário com esta permissão e **injetem código nele**. Verifique [**isto para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplicativos com a permissão de Ferramenta de Depuração podem chamar `task_for_pid()` para recuperar um task port válido para aplicativos não assinados e de terceiros com a permissão `Get Task Allow` definida como `true`. No entanto, mesmo com a permissão de ferramenta de depuração, um depurador **não pode obter os task ports** de processos que **não têm a permissão `Get Task Allow`**, e que, portanto, são protegidos pela Proteção de Integridade do Sistema. Verifique [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Esta permissão permite **carregar frameworks, plug-ins ou bibliotecas sem serem assinados pela Apple ou assinados com o mesmo ID de Equipe** que o executável principal, então um atacante poderia abusar de algum carregamento de biblioteca arbitrário para injetar código. Verifique [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Esta permissão é muito semelhante a **`com.apple.security.cs.disable-library-validation`** mas **em vez** de **desabilitar diretamente** a validação de biblioteca, permite que o processo **chame uma chamada de sistema `csops` para desabilitá-la**.\
Verifique [**isto para mais informações**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Esta permissão permite **usar variáveis de ambiente DYLD** que poderiam ser usadas para injetar bibliotecas e código. Verifique [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estas permissões permitem **modificar** o banco de dados **TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Estas permissões permitem **instalar software sem pedir permissões** ao usuário, o que pode ser útil para uma **escalada de privilégios**.

### `com.apple.private.security.kext-management`

Permissão necessária para solicitar ao **kernel para carregar uma extensão de kernel**.

### **`com.apple.private.icloud-account-access`**

Com a permissão **`com.apple.private.icloud-account-access`** é possível se comunicar com o serviço XPC **`com.apple.iCloudHelper`** que fornecerá **tokens do iCloud**.

**iMovie** e **Garageband** tinham essa permissão.

Para mais **informações** sobre o exploit para **obter tokens do iCloud** a partir dessa permissão, confira a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar o conteúdo protegido por SSV após um reinício. Se você souber como, por favor envie um PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar o conteúdo protegido por SSV após um reinício. Se você souber como, por favor envie um PR!

### `keychain-access-groups`

Esta permissão lista grupos de **keychain** aos quais o aplicativo tem acesso:
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

Concede permissões de **Acesso Total ao Disco**, uma das maiores permissões do TCC que você pode ter.

### **`kTCCServiceAppleEvents`**

Permite que o aplicativo envie eventos para outros aplicativos que são comumente usados para **automatizar tarefas**. Controlando outros aplicativos, ele pode abusar das permissões concedidas a esses outros aplicativos.

Como fazê-los pedir a senha do usuário:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ou fazendo-os executar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC do usuário**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário que muda o caminho da sua pasta home e, portanto, permite **burlar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro do pacote de aplicativos (dentro de app.app), o que é **proibido por padrão**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Configurações do Sistema_ > _Privacidade & Segurança_ > _Gerenciamento de Aplicativos._

### `kTCCServiceAccessibility`

O processo poderá **abusar dos recursos de acessibilidade do macOS**, o que significa que, por exemplo, ele poderá pressionar teclas. Então, ele poderia solicitar acesso para controlar um aplicativo como o Finder e aprovar o diálogo com essa permissão.

## Médio

### `com.apple.security.cs.allow-jit`

Este privilégio permite **criar memória que é gravável e executável** passando a flag `MAP_JIT` para a função do sistema `mmap()`. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Este privilégio permite **substituir ou corrigir código C**, usar o há muito obsoleto **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro), ou usar o framework **DVDPlayback**. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir este privilégio expõe seu aplicativo a vulnerabilidades comuns em linguagens de código de memória insegura. Considere cuidadosamente se seu aplicativo precisa dessa exceção.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Este privilégio permite **modificar seções de seus próprios arquivos executáveis** no disco para sair à força. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
O privilégio de Desabilitar Proteção de Página Executável é um privilégio extremo que remove uma proteção de segurança fundamental do seu aplicativo, possibilitando que um atacante reescreva o código executável do seu aplicativo sem detecção. Prefira privilégios mais restritos se possível.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Este privilégio permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com este post de blog, essa permissão TCC geralmente é encontrada na forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permitir que o processo **peça todas as permissões do TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
