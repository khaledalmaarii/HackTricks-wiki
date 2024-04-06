# macOS Dangerous Entitlements & TCC perms

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

{% hint style="warning" %}
Observe que as permissões que começam com **`com.apple`** não estão disponíveis para terceiros, apenas a Apple pode concedê-las.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

A permissão **`com.apple.rootless.install.heritable`** permite **burlar o SIP**. Verifique [este para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

A permissão **`com.apple.rootless.install`** permite **burlar o SIP**. Verifique [este para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente chamado `task_for_pid-allow`)**

Essa permissão permite obter a **porta de tarefa para qualquer** processo, exceto o kernel. Verifique [**este para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Essa permissão permite que outros processos com a permissão **`com.apple.security.cs.debugger`** obtenham a porta de tarefa do processo executado pelo binário com essa permissão e **injetem código nele**. Verifique [**este para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplicativos com a Permissão da Ferramenta de Depuração podem chamar `task_for_pid()` para recuperar uma porta de tarefa válida para aplicativos não assinados e de terceiros com a permissão `Get Task Allow` definida como `true`. No entanto, mesmo com a permissão da ferramenta de depuração, um depurador **não pode obter as portas de tarefa** de processos que **não têm a permissão `Get Task Allow`**, e que portanto são protegidos pela Proteção da Integridade do Sistema. Verifique [**este para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Essa permissão permite **carregar frameworks, plug-ins ou bibliotecas sem serem assinados pela Apple ou assinados com o mesmo ID de equipe** que o executável principal, então um atacante poderia abusar de alguma carga de biblioteca arbitrária para injetar código. Verifique [**este para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Essa permissão é muito semelhante a **`com.apple.security.cs.disable-library-validation`** mas **em vez de desativar diretamente** a validação da biblioteca, ela permite que o processo **chame uma chamada de sistema `csops` para desativá-la**.\
Verifique [**este para mais informações**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Essa permissão permite **usar variáveis de ambiente DYLD** que podem ser usadas para injetar bibliotecas e código. Verifique [**este para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), essas permissões permitem **modificar** o **banco de dados TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Essas permissões permitem **instalar software sem pedir permissão** ao usuário, o que pode ser útil para uma **escalada de privilégios**.

### `com.apple.private.security.kext-management`

Permissão necessária para solicitar ao **kernel para carregar uma extensão de kernel**.

### **`com.apple.private.icloud-account-access`**

A permissão **`com.apple.private.icloud-account-access`** permite comunicar com o serviço XPC **`com.apple.iCloudHelper`** que **fornecerá tokens do iCloud**.

**iMovie** e **Garageband** tinham essa permissão.

Para mais **informações** sobre a exploração para **obter tokens do iCloud** dessa permissão, confira a palestra: [**#OBTS v5.0: "O que acontece no seu Mac, fica no iCloud da Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar os conteúdos protegidos por SSV após um reinício. Se você souber como, envie um PR, por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar os conteúdos protegidos por SSV após um reinício. Se você souber como, envie um PR, por favor!

### `keychain-access-groups`

Esta lista de permissões os grupos de **keychain** aos quais o aplicativo tem acesso:

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

Como fazê-los solicitar a senha do usuário:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ou fazê-los realizar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC dos usuários**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário que altera o caminho de sua pasta pessoal e, portanto, permite **burlar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro dos pacotes de aplicativos (dentro do app.app), o que é **desativado por padrão**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Configurações do Sistema_ > _Privacidade e Segurança_ > _Gerenciamento de Aplicativos_.

### `kTCCServiceAccessibility`

O processo poderá **abusar dos recursos de acessibilidade do macOS**, o que significa que, por exemplo, ele poderá pressionar teclas. Assim, ele poderia solicitar acesso para controlar um aplicativo como o Finder e aprovar o diálogo com essa permissão.

## Médio

### `com.apple.security.cs.allow-jit`

Esta permissão permite **criar memória que é gravável e executável** passando a flag `MAP_JIT` para a função do sistema `mmap()`. Verifique [**este link para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Esta permissão permite **sobrescrever ou corrigir código C**, usar o longamente obsoleto **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro), ou usar o framework **DVDPlayback**. Verifique [**este link para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir esta permissão expõe seu aplicativo a vulnerabilidades comuns em linguagens de código inseguras em relação à memória. Considere cuidadosamente se seu aplicativo precisa dessa exceção.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Esta permissão permite **modificar seções de seus próprios arquivos executáveis** no disco para sair forçadamente. Verifique [**este link para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
A Permissão de Desabilitar Proteção de Memória Executável é uma permissão extrema que remove uma proteção de segurança fundamental do seu aplicativo, tornando possível para um atacante reescrever o código executável do seu aplicativo sem detecção. Prefira permissões mais restritas, se possível.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Esta permissão permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com este post de blog, esta permissão do TCC geralmente é encontrada na forma:

```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```

Permitir que o processo **solicite todas as permissões do TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
