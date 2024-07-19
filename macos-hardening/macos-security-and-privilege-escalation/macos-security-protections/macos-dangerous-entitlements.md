# macOS Dangerous Entitlements & TCC perms

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

{% hint style="warning" %}
Note that entitlements starting with **`com.apple`** are not available to third-parties, only Apple can grant them.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

A concessão **`com.apple.rootless.install.heritable`** permite **contornar o SIP**. Confira [isso para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

A concessão **`com.apple.rootless.install`** permite **contornar o SIP**. Confira [isso para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente chamada `task_for_pid-allow`)**

Essa concessão permite obter o **port de tarefa para qualquer** processo, exceto o kernel. Confira [**isso para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Essa concessão permite que outros processos com a concessão **`com.apple.security.cs.debugger`** obtenham o port de tarefa do processo executado pelo binário com essa concessão e **injete código nele**. Confira [**isso para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplicativos com a Concessão de Ferramenta de Depuração podem chamar `task_for_pid()` para recuperar um port de tarefa válido para aplicativos não assinados e de terceiros com a concessão `Get Task Allow` definida como `true`. No entanto, mesmo com a concessão da ferramenta de depuração, um depurador **não pode obter os ports de tarefa** de processos que **não têm a concessão `Get Task Allow`**, e que, portanto, estão protegidos pela Proteção de Integridade do Sistema. Confira [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Essa concessão permite **carregar frameworks, plug-ins ou bibliotecas sem serem assinados pela Apple ou assinados com o mesmo ID de Equipe** que o executável principal, então um atacante poderia abusar de algum carregamento arbitrário de biblioteca para injetar código. Confira [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Essa concessão é muito semelhante à **`com.apple.security.cs.disable-library-validation`**, mas **em vez** de **desabilitar diretamente** a validação de biblioteca, permite que o processo **chame uma chamada de sistema `csops` para desabilitá-la**.\
Confira [**isso para mais informações**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Essa concessão permite **usar variáveis de ambiente DYLD** que poderiam ser usadas para injetar bibliotecas e código. Confira [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog\_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), essas concessões permitem **modificar** o banco de dados **TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Essas concessões permitem **instalar software sem pedir permissões** ao usuário, o que pode ser útil para uma **elevação de privilégio**.

### `com.apple.private.security.kext-management`

Concessão necessária para solicitar ao **kernel que carregue uma extensão de kernel**.

### **`com.apple.private.icloud-account-access`**

A concessão **`com.apple.private.icloud-account-access`** permite comunicar-se com o serviço XPC **`com.apple.iCloudHelper`**, que fornecerá **tokens do iCloud**.

**iMovie** e **Garageband** tinham essa concessão.

Para mais **informações** sobre a exploração para **obter tokens do iCloud** dessa concessão, confira a palestra: [**#OBTS v5.0: "O que acontece no seu Mac, fica no iCloud da Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: No [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar os conteúdos protegidos por SSV após uma reinicialização. Se você souber como, envie um PR, por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: No [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isso poderia ser usado para** atualizar os conteúdos protegidos por SSV após uma reinicialização. Se você souber como, envie um PR, por favor!

### `keychain-access-groups`

Essa concessão lista os grupos de **keychain** aos quais o aplicativo tem acesso:
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

Concede permissões de **Acesso Completo ao Disco**, uma das permissões mais altas do TCC que você pode ter.

### **`kTCCServiceAppleEvents`**

Permite que o aplicativo envie eventos para outros aplicativos que são comumente usados para **automatizar tarefas**. Controlando outros aplicativos, ele pode abusar das permissões concedidas a esses outros aplicativos.

Como fazê-los pedir a senha do usuário:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ou fazê-los realizar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC dos usuários**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário que muda o caminho da sua pasta inicial e, portanto, permite **contornar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro do pacote de aplicativos (dentro de app.app), o que é **proibido por padrão**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Configurações do Sistema_ > _Privacidade e Segurança_ > _Gerenciamento de Aplicativos._

### `kTCCServiceAccessibility`

O processo poderá **abusar das funcionalidades de acessibilidade do macOS**, o que significa que, por exemplo, ele poderá pressionar teclas. Assim, ele poderia solicitar acesso para controlar um aplicativo como o Finder e aprovar o diálogo com essa permissão.

## Médio

### `com.apple.security.cs.allow-jit`

Essa permissão permite **criar memória que é gravável e executável** passando a flag `MAP_JIT` para a função de sistema `mmap()`. Confira [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Essa permissão permite **substituir ou corrigir código C**, usar o **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro) ou usar o framework **DVDPlayback**. Confira [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir essa permissão expõe seu aplicativo a vulnerabilidades comuns em linguagens de código inseguro em memória. Considere cuidadosamente se seu aplicativo precisa dessa exceção.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Essa permissão permite **modificar seções de seus próprios arquivos executáveis** no disco para forçar a saída. Confira [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
A Permissão de Desativação da Proteção de Memória Executável é uma permissão extrema que remove uma proteção de segurança fundamental do seu aplicativo, tornando possível que um atacante reescreva o código executável do seu aplicativo sem detecção. Prefira permissões mais restritas, se possível.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Essa permissão permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

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
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
</details>
