# Sandbox do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

O Sandbox do macOS (inicialmente chamado Seatbelt) **limita as aplicações** em execução dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o aplicativo está sendo executado. Isso ajuda a garantir que **o aplicativo acesse apenas os recursos esperados**.

Qualquer aplicativo com a **permissão** **`com.apple.security.app-sandbox`** será executado dentro do sandbox. **Binários da Apple** geralmente são executados dentro de um Sandbox e, para publicar na **App Store**, **essa permissão é obrigatória**. Portanto, a maioria dos aplicativos será executada dentro do sandbox.

Para controlar o que um processo pode ou não fazer, o **Sandbox possui ganchos** em todas as **chamadas de sistema** em todo o kernel. **Dependendo** das **permissões** do aplicativo, o Sandbox irá **permitir** certas ações.

Alguns componentes importantes do Sandbox são:

* A **extensão de kernel** `/System/Library/Extensions/Sandbox.kext`
* O **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Um **daemon** em userland `/usr/libexec/sandboxd`
* Os **containers** `~/Library/Containers`

Dentro da pasta containers, você pode encontrar **uma pasta para cada aplicativo executado em sandbox** com o nome do identificador do pacote:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Dentro de cada pasta de identificação do pacote, você pode encontrar o **plist** e o **diretório de Dados** do aplicativo:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Note que mesmo que os links simbólicos estejam lá para "escapar" do Sandbox e acessar outras pastas, o aplicativo ainda precisa **ter permissões** para acessá-los. Essas permissões estão dentro do arquivo **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Tudo criado/modificado por um aplicativo Sandboxed receberá o **atributo de quarentena**. Isso impedirá um espaço de sandbox ao acionar o Gatekeeper se o aplicativo sandbox tentar executar algo com **`open`**.
{% endhint %}

### Perfis de Sandbox

Os perfis de Sandbox são arquivos de configuração que indicam o que será **permitido/proibido** naquele **Sandbox**. Ele utiliza a **Linguagem de Perfil de Sandbox (SBPL)**, que usa a linguagem de programação [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Aqui você pode encontrar um exemplo:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Verifique esta [**pesquisa**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para verificar mais ações que podem ser permitidas ou negadas.**
{% endhint %}

**Serviços do sistema** importantes também são executados dentro de seus próprios **perfis de sandbox** personalizados, como o serviço `mdnsresponder`. Você pode visualizar esses **perfis de sandbox personalizados** em:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Outros perfis de sandbox podem ser verificados em [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Os aplicativos da **App Store** usam o **perfil** **`/System/Library/Sandbox/Profiles/application.sb`**. Você pode verificar neste perfil como as autorizações, como **`com.apple.security.network.server`**, permitem que um processo use a rede.

O SIP é um perfil de Sandbox chamado platform\_profile em /System/Library/Sandbox/rootless.conf

### Exemplos de Perfil de Sandbox

Para iniciar um aplicativo com um **perfil de sandbox específico**, você pode usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Note que o **software** **desenvolvido pela Apple** que roda no **Windows** **não possui precauções de segurança adicionais**, como a aplicação de sandbox.
{% endhint %}

Exemplos de bypass:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (eles conseguem escrever arquivos fora da sandbox cujo nome começa com `~$`).

### Perfis de Sandbox do MacOS

O macOS armazena os perfis de sandbox do sistema em dois locais: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

E se um aplicativo de terceiros possuir a concessão _**com.apple.security.app-sandbox**_, o sistema aplicará o perfil **/System/Library/Sandbox/Profiles/application.sb** a esse processo.

### **Perfil de Sandbox do iOS**

O perfil padrão é chamado **container** e não temos a representação de texto SBPL. Na memória, essa sandbox é representada como uma árvore binária de Permitir/Negar para cada permissão da sandbox.

### Depurar e Bypass de Sandbox

No macOS, ao contrário do iOS, onde os processos são colocados em sandbox desde o início pelo kernel, **os processos devem optar pela sandbox por conta própria**. Isso significa que no macOS, um processo não é restrito pela sandbox até que decida ativamente entrar nela.

Os processos são automaticamente colocados em sandbox a partir do espaço do usuário quando iniciam se possuírem a concessão: `com.apple.security.app-sandbox`. Para uma explicação detalhada desse processo, verifique:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Verificar Privilégios do PID**

[**De acordo com isso**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), o **`sandbox_check`** (é um `__mac_syscall`), pode verificar **se uma operação é permitida ou não** pela sandbox em um determinado PID.

A [**ferramenta sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) pode verificar se um PID pode realizar uma determinada ação:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### SBPL personalizado em aplicativos da App Store

Pode ser possível para empresas fazer seus aplicativos rodarem **com perfis de Sandbox personalizados** (em vez do padrão). Elas precisam usar a permissão **`com.apple.security.temporary-exception.sbpl`** que precisa ser autorizada pela Apple.

É possível verificar a definição dessa permissão em **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Isso irá **avaliar a string após esse privilégio** como um perfil de Sandbox.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
