# Permissões Perigosas do macOS & Permissões TCC

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

{% hint style="warning" %}
Note que permissões começando com **`com.apple`** não estão disponíveis para terceiros, apenas a Apple pode concedê-las.
{% endhint %}

## Alto

### `com.apple.rootless.install.heritable`

A permissão **`com.apple.rootless.install.heritable`** permite **bypassar o SIP**. Confira [isto para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

A permissão **`com.apple.rootless.install`** permite **bypassar o SIP**. Confira [isto para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente chamado `task_for_pid-allow`)**

Esta permissão permite obter o **task port para qualquer** processo, exceto o kernel. Confira [**isto para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Esta permissão permite que outros processos com a permissão **`com.apple.security.cs.debugger`** obtenham o task port do processo executado pelo binário com esta permissão e **injetem código nele**. Confira [**isto para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplicativos com a permissão de Ferramenta de Depuração podem chamar `task_for_pid()` para recuperar um task port válido para aplicativos não assinados e de terceiros com a permissão `Get Task Allow` definida como `true`. No entanto, mesmo com a permissão de ferramenta de depuração, um depurador **não pode obter os task ports** de processos que **não possuem a permissão `Get Task Allow`**, e que, portanto, são protegidos pela Proteção de Integridade do Sistema. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Esta permissão permite **carregar frameworks, plug-ins ou bibliotecas sem serem assinados pela Apple ou assinados com o mesmo ID de Equipe** que o executável principal, então um atacante poderia abusar de algum carregamento arbitrário de biblioteca para injetar código. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Esta permissão é muito semelhante a **`com.apple.security.cs.disable-library-validation`** mas **em vez** de **desabilitar diretamente** a validação de biblioteca, ela permite que o processo **chame uma chamada de sistema `csops` para desabilitá-la**.\
Confira [**isto para mais informações**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Esta permissão permite **usar variáveis de ambiente DYLD** que poderiam ser usadas para injetar bibliotecas e código. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), estas permissões permitem **modificar** o banco de dados **TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Estas permissões permitem **instalar software sem pedir permissões** ao usuário, o que pode ser útil para uma **escalada de privilégios**.

### `com.apple.private.security.kext-management`

Permissão necessária para solicitar ao **kernel que carregue uma extensão de kernel**.

### **`com.apple.private.icloud-account-access`**

Com a permissão **`com.apple.private.icloud-account-access`** é possível se comunicar com o serviço XPC **`com.apple.iCloudHelper`** que fornecerá **tokens do iCloud**.

**iMovie** e **Garageband** tinham essa permissão.

Para mais **informações** sobre o exploit para **obter tokens do iCloud** a partir dessa permissão, confira a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar o conteúdo protegido por SSV após um reboot. Se você sabe como, por favor envie um PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar o conteúdo protegido por SSV após um reboot. Se você sabe como, por favor envie um PR!

### `keychain-access-groups`

Esta permissão lista os grupos **keychain** aos quais o aplicativo tem acesso:
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
### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC do usuário**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário que muda o caminho da sua pasta home e, portanto, permite **burlar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro do pacote de aplicativos (dentro de app.app), o que é **proibido por padrão**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Configurações do Sistema_ > _Privacidade & Segurança_ > _Gerenciamento de Aplicativos._

### `kTCCServiceAccessibility`

O processo poderá **abusar dos recursos de acessibilidade do macOS**, o que significa que, por exemplo, ele poderá pressionar teclas. Assim, ele poderia solicitar acesso para controlar um aplicativo como o Finder e aprovar o diálogo com essa permissão.

## Médio

### `com.apple.security.cs.allow-jit`

Esse privilégio permite **criar memória que é gravável e executável** passando a flag `MAP_JIT` para a função do sistema `mmap()`. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Esse privilégio permite **substituir ou corrigir código C**, usar o há muito tempo descontinuado **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro), ou usar o framework **DVDPlayback**. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir esse privilégio expõe seu aplicativo a vulnerabilidades comuns em linguagens de código de memória insegura. Considere cuidadosamente se seu aplicativo precisa dessa exceção.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Esse privilégio permite **modificar seções de seus próprios arquivos executáveis** no disco para sair forçadamente. Confira [**isto para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

{% hint style="danger" %}
O privilégio de Desabilitar Proteção de Página Executável é um privilégio extremo que remove uma proteção de segurança fundamental do seu aplicativo, possibilitando que um atacante reescreva o código executável do seu aplicativo sem detecção. Prefira privilégios mais restritos se possível.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Esse privilégio permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com este post de blog, essa permissão TCC geralmente é encontrada na forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permitir que o processo **solicite todas as permissões do TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
