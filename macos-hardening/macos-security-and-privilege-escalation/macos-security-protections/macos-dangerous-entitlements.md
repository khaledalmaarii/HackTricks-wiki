# Entitlements Perigosos do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Observe que as entitlements que começam com **`com.apple`** não estão disponíveis para terceiros, apenas a Apple pode concedê-las.
{% endhint %}

## Alto

### `com.apple.security.get-task-allow`

Essa entitlement permite obter a porta da tarefa do processo executado pelo binário com essa entitlement e **injetar código nele**. Verifique [**isso para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### **`com.apple.system-task-ports` (anteriormente chamado de `task_for_pid-allow`)**

Essa entitlement permite obter a **porta da tarefa para qualquer** processo, exceto o kernel. Verifique [**isso para mais informações**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplicativos com a Entitlement da Ferramenta de Depuração podem chamar `task_for_pid()` para recuperar uma porta de tarefa válida para aplicativos não assinados e de terceiros com a entitlement `Get Task Allow` definida como `true`. No entanto, mesmo com a entitlement da ferramenta de depuração, um depurador não pode obter as portas de tarefa de processos que não possuem a entitlement `Get Task Allow` e, portanto, são protegidos pela Proteção de Integridade do Sistema. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Essa entitlement permite **carregar frameworks, plug-ins ou bibliotecas sem serem assinados pela Apple ou assinados com o mesmo ID de equipe** que o executável principal, portanto, um invasor pode abusar de algum carregamento arbitrário de biblioteca para injetar código. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.security.cs.allow-dyld-environment-variables`

Essa entitlement permite **usar variáveis de ambiente DYLD** que podem ser usadas para injetar bibliotecas e código. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

## Médio

### `com.apple.security.cs.allow-jit`

Essa entitlement permite **criar memória que pode ser gravada e executada** passando a flag `MAP_JIT` para a função de sistema `mmap()`. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Essa entitlement permite **substituir ou corrigir código C**, usar o **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro) ou usar o framework **DVDPlayback**. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Incluir essa entitlement expõe seu aplicativo a vulnerabilidades comuns em linguagens de código não seguras em memória. Considere cuidadosamente se seu aplicativo precisa dessa exceção.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Essa entitlement permite **modificar seções de seus próprios arquivos executáveis** no disco para sair forçadamente. Verifique [**isso para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
A Entitlement de Desativação da Proteção de Memória Executável é uma entitlement extrema que remove uma proteção de segurança fundamental do seu aplicativo, tornando possível que um invasor reescreva o código executável do seu aplicativo sem detecção. Prefira entitlements mais restritas, se possível.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).
