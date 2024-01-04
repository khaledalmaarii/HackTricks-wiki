# Arquivos, Pastas, Binários e Memória do macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Layout da hierarquia de arquivos

* **/Applications**: Os aplicativos instalados devem estar aqui. Todos os usuários poderão acessá-los.
* **/bin**: Binários da linha de comando
* **/cores**: Se existir, é usado para armazenar dumps de núcleo
* **/dev**: Tudo é tratado como um arquivo, então você pode ver dispositivos de hardware armazenados aqui.
* **/etc**: Arquivos de configuração
* **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Uma pasta Library existe na raiz e no diretório de cada usuário.
* **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório privado.
* **/sbin**: Binários essenciais do sistema (relacionados à administração)
* **/System**: Arquivo para fazer o OS X funcionar. Você deve encontrar principalmente apenas arquivos específicos da Apple aqui (não de terceiros).
* **/tmp**: Os arquivos são excluídos após 3 dias (é um link simbólico para /private/tmp)
* **/Users**: Diretório inicial para usuários.
* **/usr**: Configuração e binários do sistema
* **/var**: Arquivos de log
* **/Volumes**: As unidades montadas aparecerão aqui.
* **/.vol**: Executando `stat a.txt`, você obtém algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, onde o primeiro número é o número de identificação do volume onde o arquivo existe e o segundo é o número do inode. Você pode acessar o conteúdo deste arquivo através de /.vol/ com essa informação executando `cat /.vol/16777223/7545753`

### Pastas de Aplicativos

* **Aplicativos do sistema** estão localizados em `/System/Applications`
* **Aplicativos instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
* **Dados de aplicativos** podem ser encontrados em `/Library/Application Support` para os aplicativos executados como root e `~/Library/Application Support` para aplicativos executados como o usuário.
* **Daemons** de aplicativos de terceiros que **precisam ser executados como root** geralmente estão localizados em `/Library/PrivilegedHelperTools/`
* Aplicativos **Sandboxed** são mapeados para a pasta `~/Library/Containers`. Cada aplicativo tem uma pasta nomeada de acordo com o ID do pacote do aplicativo (`com.apple.Safari`).
* O **kernel** está localizado em `/System/Library/Kernels/kernel`
* **Extensões de kernel da Apple** estão localizadas em `/System/Library/Extensions`
* **Extensões de kernel de terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com Informações Sensíveis

O MacOS armazena informações como senhas em vários lugares:

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
* Pode ser XML ou binário. Binários podem ser lidos com:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplicativos da Apple que seguem a estrutura de diretórios (É um pacote).
* **`.dylib`**: Bibliotecas dinâmicas (como arquivos DLL do Windows)
* **`.pkg`**: São o mesmo que xar (formato de Arquivo Extensível). O comando de instalação pode ser usado para instalar o conteúdo desses arquivos.
* **`.DS_Store`**: Este arquivo está em cada diretório, ele salva os atributos e personalizações do diretório.
* **`.Spotlight-V100`**: Esta pasta aparece no diretório raiz de cada volume no sistema.
* **`.metadata_never_index`**: Se este arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
* **`.noindex`**: Arquivos e pastas com esta extensão não serão indexados pelo Spotlight.

### Pacotes macOS

Basicamente, um pacote é uma **estrutura de diretório** dentro do sistema de arquivos. Curiosamente, por padrão, este diretório **parece um único objeto no Finder** (como `.app`).&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache Compartilhado Dyld

No macOS (e iOS) todas as bibliotecas compartilhadas do sistema, como frameworks e dylibs, são **combinadas em um único arquivo**, chamado **cache compartilhado dyld**. Isso melhora o desempenho, já que o código pode ser carregado mais rapidamente.

Semelhante ao cache compartilhado dyld, o kernel e as extensões de kernel também são compilados em um cache de kernel, que é carregado no momento da inicialização.

Para extrair as bibliotecas do arquivo único de cache compartilhado dylib, era possível usar o binário [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) que pode não estar funcionando atualmente, mas você também pode usar [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

Em versões mais antigas, você pode ser capaz de encontrar o **cache compartilhado** em **`/System/Library/dyld/`**.

No iOS, você pode encontrá-los em **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Observe que mesmo que a ferramenta `dyld_shared_cache_util` não funcione, você pode passar o **binário dyld compartilhado para o Hopper** e o Hopper será capaz de identificar todas as bibliotecas e permitir que você **selecione qual** deseja investigar:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Permissões Especiais de Arquivos

### Permissões de Pasta

Em uma **pasta**, **ler** permite **listá-la**, **escrever** permite **deletar** e **escrever** arquivos nela, e **executar** permite **atravessar** o diretório. Então, por exemplo, um usuário com **permissão de leitura sobre um arquivo** dentro de um diretório onde ele **não tem permissão de execução** **não será capaz de ler** o arquivo.

### Modificadores de Flag

Existem algumas flags que podem ser definidas nos arquivos que farão o arquivo se comportar de maneira diferente. Você pode **verificar as flags** dos arquivos dentro de um diretório com `ls -lO /caminho/diretório`

* **`uchg`**: Conhecida como flag **uchange**, irá **prevenir qualquer ação** de alterar ou deletar o **arquivo**. Para definir, faça: `chflags uchg arquivo.txt`
* O usuário root pode **remover a flag** e modificar o arquivo
* **`restricted`**: Esta flag faz com que o arquivo seja **protegido pelo SIP** (você não pode adicionar esta flag a um arquivo).
* **`Sticky bit`**: Se um diretório com sticky bit, **apenas** o **proprietário do diretório ou root pode renomear ou deletar** arquivos. Tipicamente, isso é definido no diretório /tmp para prevenir que usuários comuns deletem ou movam arquivos de outros usuários.

### **ACLs de Arquivo**

As **ACLs** de arquivo contêm **ACE** (Entradas de Controle de Acesso) onde permissões mais **granulares** podem ser atribuídas a diferentes usuários.

É possível conceder a um **diretório** estas permissões: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a um **arquivo**: `read`, `write`, `append`, `execute`.

Quando o arquivo contém ACLs, você encontrará um "+" ao listar as permissões como em:
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
### Forks de Recursos | macOS ADS

Esta é uma maneira de obter **Alternate Data Streams no MacOS**. Você pode salvar conteúdo dentro de um atributo estendido chamado **com.apple.ResourceFork** dentro de um arquivo, salvando-o em **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Você pode **encontrar todos os arquivos que contêm este atributo estendido** com:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Binários universais &** Formato Mach-o

Binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar múltiplas arquiteturas no mesmo arquivo**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumping de memória no macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Arquivos de Categoria de Risco no Mac OS

Os arquivos `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contêm o risco associado a arquivos dependendo da extensão do arquivo.

As possíveis categorias incluem:

* **LSRiskCategorySafe**: **Totalmente** **seguro**; Safari irá abrir automaticamente após o download
* **LSRiskCategoryNeutral**: Sem aviso, mas **não é aberto automaticamente**
* **LSRiskCategoryUnsafeExecutable**: **Aciona** um **aviso** “Este arquivo é um aplicativo...”
* **LSRiskCategoryMayContainUnsafeExecutable**: Para coisas como arquivos que contêm um executável. **Aciona um aviso a menos que o Safari possa determinar que todo o conteúdo é seguro ou neutro**.

## Arquivos de log

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
* **`/var/log/system.log`**: Log principal dos sistemas OSX. com.apple.syslogd.plist é responsável pela execução do syslogging (você pode verificar se está desativado procurando por "com.apple.syslogd" em `launchctl list`.
* **`/private/var/log/asl/*.asl`**: São os Apple System Logs que podem conter informações interessantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente pelo "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Armazena itens para serem lançados na inicialização do sistema
* **`$HOME/Library/Logs/DiskUtility.log`**: Arquivo de log do aplicativo DiskUtility (informações sobre drives, incluindo USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de daemons desativados.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
