# Arquivos, Pastas, Binários e Memória do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Layout da hierarquia de arquivos

* **/Applications**: Os aplicativos instalados devem estar aqui. Todos os usuários poderão acessá-los.
* **/bin**: Binários da linha de comando
* **/cores**: Se existir, é usado para armazenar despejos de núcleo
* **/dev**: Tudo é tratado como um arquivo, então você pode ver dispositivos de hardware armazenados aqui.
* **/etc**: Arquivos de configuração
* **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Uma pasta Library existe na raiz e em cada diretório do usuário.
* **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório privado.
* **/sbin**: Binários essenciais do sistema (relacionados à administração)
* **/System**: Arquivo para fazer o OS X funcionar. Você deve encontrar principalmente arquivos específicos da Apple aqui (não de terceiros).
* **/tmp**: Arquivos são excluídos após 3 dias (é um link simbólico para /private/tmp)
* **/Users**: Diretório pessoal dos usuários.
* **/usr**: Configurações e binários do sistema
* **/var**: Arquivos de log
* **/Volumes**: As unidades montadas aparecerão aqui.
* **/.vol**: Ao executar `stat a.txt`, você obtém algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, onde o primeiro número é o número de ID do volume onde o arquivo existe e o segundo é o número de inode. Você pode acessar o conteúdo deste arquivo através de /.vol/ com essas informações executando `cat /.vol/16777223/7545753`

### Pastas de Aplicativos

* Os **aplicativos do sistema** estão localizados em `/System/Applications`
* Os aplicativos **instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
* Os **dados do aplicativo** podem ser encontrados em `/Library/Application Support` para os aplicativos em execução como root e `~/Library/Application Support` para aplicativos em execução como o usuário.
* Os **daemons** de aplicativos de terceiros que **precisam ser executados como root** geralmente estão localizados em `/Library/PrivilegedHelperTools/`
* Os aplicativos **sandboxed** são mapeados na pasta `~/Library/Containers`. Cada aplicativo tem uma pasta com o nome do ID do pacote do aplicativo (`com.apple.Safari`).
* O **kernel** está localizado em `/System/Library/Kernels/kernel`
* As **extensões de kernel da Apple** estão localizadas em `/System/Library/Extensions`
* As **extensões de kernel de terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com Informações Sensíveis

O macOS armazena informações como senhas em vários locais:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Instaladores pkg Vulneráveis

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensões Específicas do OS X

* **`.dmg`**: Arquivos de Imagem de Disco da Apple são muito frequentes para instaladores.
* **`.kext`**: Deve seguir uma estrutura específica e é a versão do OS X de um driver. (é um pacote)
* **`.plist`**: Também conhecido como lista de propriedades, armazena informações em formato XML ou binário.
* Pode ser XML ou binário. Os binários podem ser lidos com:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplicativos da Apple que seguem a estrutura de diretórios (é um pacote).
* **`.dylib`**: Bibliotecas dinâmicas (como arquivos DLL do Windows)
* **`.pkg`**: São iguais aos arquivos xar (formato de arquivo extensível). O comando installer pode ser usado para instalar o conteúdo desses arquivos.
* **`.DS_Store`**: Este arquivo está em cada diretório, ele salva os atributos e personalizações do diretório.
* **`.Spotlight-V100`**: Esta pasta aparece no diretório raiz de cada volume no sistema.
* **`.metadata_never_index`**: Se este arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
* **`.noindex`**: Arquivos e pastas com essa extensão não serão indexados pelo Spotlight.
### Pacotes macOS

Basicamente, um pacote é uma **estrutura de diretórios** dentro do sistema de arquivos. Curiosamente, por padrão, esse diretório **parece ser um único objeto no Finder** (como `.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache Compartilhado do Dyld

No macOS (e iOS), todas as bibliotecas compartilhadas do sistema, como frameworks e dylibs, são **combinadas em um único arquivo**, chamado **cache compartilhado do dyld**. Isso melhora o desempenho, pois o código pode ser carregado mais rapidamente.

Semelhante ao cache compartilhado do dyld, o kernel e as extensões do kernel também são compilados em um cache do kernel, que é carregado durante a inicialização.

Para extrair as bibliotecas do arquivo único de cache compartilhado do dylib, era possível usar o binário [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip), que pode não estar funcionando atualmente, mas você também pode usar o [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

Em versões mais antigas, você pode encontrar o **cache compartilhado** em **`/System/Library/dyld/`**.

No iOS, você pode encontrá-los em **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Observe que mesmo que a ferramenta `dyld_shared_cache_util` não funcione, você pode passar o **binário compartilhado do dyld para o Hopper** e o Hopper será capaz de identificar todas as bibliotecas e permitir que você **selecione qual** deseja investigar:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Permissões Especiais de Arquivos

### Permissões de Pasta

Em uma **pasta**, **leitura** permite **listá-la**, **escrita** permite **excluir** e **escrever** arquivos nela, e **execução** permite **navegar** pelo diretório. Portanto, por exemplo, um usuário com **permissão de leitura sobre um arquivo** dentro de um diretório onde ele **não tem permissão de execução** **não poderá ler** o arquivo.

### Modificadores de Sinalizador

Existem alguns sinalizadores que podem ser definidos nos arquivos e que farão com que o arquivo se comporte de maneira diferente. Você pode **verificar os sinalizadores** dos arquivos dentro de um diretório com `ls -lO /caminho/diretório`

* **`uchg`**: Conhecido como sinalizador **uchange**, impedirá qualquer ação de alterar ou excluir o **arquivo**. Para defini-lo, faça: `chflags uchg arquivo.txt`
* O usuário root pode **remover o sinalizador** e modificar o arquivo
* **`restricted`**: Esse sinalizador faz com que o arquivo seja **protegido pelo SIP** (você não pode adicionar esse sinalizador a um arquivo).
* **`Sticky bit`**: Se um diretório tiver o sticky bit, **apenas** o **proprietário do diretório ou o root podem renomear ou excluir** arquivos. Normalmente, isso é definido no diretório /tmp para impedir que usuários comuns excluam ou movam arquivos de outros usuários.

### **ACLs de Arquivo**

As ACLs de arquivo contêm ACEs (Entradas de Controle de Acesso) onde permissões mais **granulares** podem ser atribuídas a diferentes usuários.

É possível conceder a uma **pasta** essas permissões: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a um **arquivo**: `read`, `write`, `append`, `execute`.

Quando o arquivo contém ACLs, você encontrará um "+" ao listar as permissões, como em:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Você pode **ler as ACLs** do arquivo com:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Você pode encontrar **todos os arquivos com ACLs** com (isso é muuuito lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Recursos Forks | Fluxos de Dados Alternativos do macOS

Esta é uma maneira de obter **Fluxos de Dados Alternativos no macOS**. Você pode salvar conteúdo dentro de um atributo estendido chamado **com.apple.ResourceFork** dentro de um arquivo, salvando-o em **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Você pode **encontrar todos os arquivos que contêm esse atributo estendido** com:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Binários universais e** Formato Mach-o

Os binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar várias arquiteturas no mesmo arquivo**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Despejo de memória do macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Arquivos de Categoria de Risco do Mac OS

Os arquivos `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contêm o risco associado aos arquivos dependendo da extensão do arquivo.

As possíveis categorias incluem as seguintes:

* **LSRiskCategorySafe**: **Totalmente** **seguro**; o Safari será aberto automaticamente após o download
* **LSRiskCategoryNeutral**: Sem aviso, mas **não é aberto automaticamente**
* **LSRiskCategoryUnsafeExecutable**: **Aciona** um **aviso** "Este arquivo é um aplicativo..."
* **LSRiskCategoryMayContainUnsafeExecutable**: Isso é para coisas como arquivos compactados que contêm um executável. Ele **aciona um aviso a menos que o Safari possa determinar que todo o conteúdo é seguro ou neutro**.

## Arquivos de log

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
* **`/var/log/system.log`**: Log principal dos sistemas OSX. com.apple.syslogd.plist é responsável pela execução do syslogging (você pode verificar se está desativado procurando por "com.apple.syslogd" em `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Estes são os Logs do Sistema Apple que podem conter informações interessantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente através do "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Armazena itens para iniciar durante a inicialização do sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: Arquivo de log para o aplicativo DiskUtility (informações sobre unidades, incluindo USBs).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de daemons desativados.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
