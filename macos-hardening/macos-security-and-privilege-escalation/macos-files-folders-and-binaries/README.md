# Arquivos, Pastas, Binários e Memória do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Layout da hierarquia de arquivos

- **/Applications**: Os aplicativos instalados devem estar aqui. Todos os usuários poderão acessá-los.
- **/bin**: Binários da linha de comando
- **/cores**: Se existir, é usado para armazenar despejos de núcleo
- **/dev**: Tudo é tratado como um arquivo, então você pode ver dispositivos de hardware armazenados aqui.
- **/etc**: Arquivos de configuração
- **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Uma pasta Library existe na raiz e em cada diretório de usuário.
- **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório privado.
- **/sbin**: Binários essenciais do sistema (relacionados à administração)
- **/System**: Arquivo para fazer o OS X funcionar. Você deve encontrar principalmente apenas arquivos específicos da Apple aqui (não de terceiros).
- **/tmp**: Arquivos são excluídos após 3 dias (é um link simbólico para /private/tmp)
- **/Users**: Diretório doméstico para usuários.
- **/usr**: Binários de configuração e sistema
- **/var**: Arquivos de log
- **/Volumes**: As unidades montadas aparecerão aqui.
- **/.vol**: Executando `stat a.txt` você obtém algo como `16777223 7545753 -rw-r--r-- 1 nome de usuário wheel ...` onde o primeiro número é o número de identificação do volume onde o arquivo existe e o segundo é o número de inode. Você pode acessar o conteúdo deste arquivo através de /.vol/ com essa informação executando `cat /.vol/16777223/7545753`

### Pastas de Aplicativos

- Os **aplicativos do sistema** estão localizados em `/System/Applications`
- Os **aplicativos instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
- Os **dados do aplicativo** podem ser encontrados em `/Library/Application Support` para os aplicativos em execução como root e `~/Library/Application Support` para aplicativos em execução como o usuário.
- Os **daemons de aplicativos de terceiros** que **precisam ser executados como root** geralmente estão localizados em `/Library/PrivilegedHelperTools/`
- Os aplicativos **sandboxed** são mapeados na pasta `~/Library/Containers`. Cada aplicativo tem uma pasta nomeada de acordo com o ID do pacote do aplicativo (`com.apple.Safari`).
- O **kernel** está localizado em `/System/Library/Kernels/kernel`
- As **extensões de kernel da Apple** estão localizadas em `/System/Library/Extensions`
- As **extensões de kernel de terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com Informações Sensíveis

O macOS armazena informações como senhas em vários lugares:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Instaladores pkg Vulneráveis

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensões Específicas do OS X

- **`.dmg`**: Arquivos de Imagem de Disco da Apple são muito frequentes para instaladores.
- **`.kext`**: Deve seguir uma estrutura específica e é a versão do OS X de um driver. (é um pacote)
- **`.plist`**: Também conhecido como lista de propriedades, armazena informações em formato XML ou binário.
- Pode ser XML ou binário. Os binários podem ser lidos com:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Aplicativos da Apple que seguem a estrutura de diretório (é um pacote).
- **`.dylib`**: Bibliotecas dinâmicas (como arquivos DLL do Windows)
- **`.pkg`**: São iguais a xar (formato de arquivo de arquivo extensível). O comando installer pode ser usado para instalar o conteúdo desses arquivos.
- **`.DS_Store`**: Este arquivo está em cada diretório, ele salva os atributos e personalizações do diretório.
- **`.Spotlight-V100`**: Esta pasta aparece no diretório raiz de cada volume no sistema.
- **`.metadata_never_index`**: Se este arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
- **`.noindex`**: Arquivos e pastas com esta extensão não serão indexados pelo Spotlight.
- **`.sdef`**: Arquivos dentro de pacotes especificando como é possível interagir com o aplicativo a partir de um AppleScript.

### Pacotes do macOS

Um pacote é um **diretório** que **parece um objeto no Finder** (um exemplo de pacote são os arquivos `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache de Biblioteca Compartilhada Dyld (SLC)

No macOS (e iOS) todas as bibliotecas compartilhadas do sistema, como frameworks e dylibs, são **combinadas em um único arquivo**, chamado **cache de biblioteca compartilhada dyld**. Isso melhora o desempenho, pois o código pode ser carregado mais rapidamente.

Isso está localizado no macOS em `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` e em versões mais antigas você pode encontrar o **cache compartilhado** em **`/System/Library/dyld/`**.\
No iOS você pode encontrá-los em **`/System/Library/Caches/com.apple.dyld/`**.

Assim como o cache de biblioteca compartilhada dyld, o kernel e as extensões do kernel também são compilados em um cache de kernel, que é carregado na inicialização.

Para extrair as bibliotecas do arquivo único de cache de biblioteca compartilhada dylib, era possível usar o binário [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) que pode não estar funcionando atualmente, mas você também pode usar [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

{% hint style="success" %}
Note que mesmo que a ferramenta `dyld_shared_cache_util` não funcione, você pode passar o **binário dyld compartilhado para o Hopper** e o Hopper será capaz de identificar todas as bibliotecas e permitir que você **selecione qual** deseja investigar:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1149).png" alt="" width="563"><figcaption></figcaption></figure>

Alguns extratores não funcionarão, pois as dylibs são pré-linkadas com endereços codificados e, portanto, podem estar saltando para endereços desconhecidos.

{% hint style="success" %}
Também é possível baixar o Cache de Biblioteca Compartilhada de outros dispositivos \*OS no macOS usando um emulador no Xcode. Eles serão baixados em: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<versão>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### Mapeando SLC

**`dyld`** usa a chamada de sistema **`shared_region_check_np`** para saber se o SLC foi mapeado (que retorna o endereço) e **`shared_region_map_and_slide_np`** para mapear o SLC.

Note que mesmo que o SLC seja deslizado na primeira utilização, todos os **processos** usam a **mesma cópia**, o que **elimina a proteção ASLR** se o atacante conseguir executar processos no sistema. Isso foi realmente explorado no passado e corrigido com o pager de região compartilhada.

Os pools de branches são pequenas dylibs Mach-O que criam pequenos espaços entre mapeamentos de imagens, tornando impossível interpor as funções.

### Substituindo SLCs

Usando as variáveis de ambiente:

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</caminho/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Isso permitirá carregar um novo cache de biblioteca compartilhada
* **`DYLD_SHARED_CACHE_DIR=avoid`** e substituir manualmente as bibliotecas por links simbólicos para o cache compartilhado com os reais (você precisará extraí-los)

## Permissões Especiais de Arquivos

### Permissões de Pasta

Em uma **pasta**, **ler** permite **listá-la**, **escrever** permite **excluir** e **escrever** arquivos nela, e **executar** permite **atravessar** o diretório. Portanto, por exemplo, um usuário com **permissão de leitura sobre um arquivo** dentro de um diretório onde ele **não tem permissão de execução** **não poderá ler** o arquivo.

### Modificadores de Flag

Existem algumas flags que podem ser definidas nos arquivos que farão o arquivo se comportar de maneira diferente. Você pode **verificar as flags** dos arquivos dentro de um diretório com `ls -lO /caminho/diretório`

* **`uchg`**: Conhecida como **flag uchange** irá **impedir qualquer ação** de alterar ou excluir o **arquivo**. Para defini-la faça: `chflags uchg arquivo.txt`
* O usuário root poderia **remover a flag** e modificar o arquivo
* **`restricted`**: Esta flag faz com que o arquivo seja **protegido pelo SIP** (você não pode adicionar essa flag a um arquivo).
* **`Bit pegajoso`**: Se um diretório tiver o bit pegajoso, **apenas** o **dono dos diretórios ou root pode renomear ou excluir** arquivos. Tipicamente isso é definido no diretório /tmp para impedir que usuários comuns excluam ou movam arquivos de outros usuários.

Todas as flags podem ser encontradas no arquivo `sys/stat.h` (encontre-o usando `mdfind stat.h | grep stat.h`) e são:

* `UF_SETTABLE` 0x0000ffff: Máscara de flags alteráveis pelo proprietário.
* `UF_NODUMP` 0x00000001: Não fazer dump do arquivo.
* `UF_IMMUTABLE` 0x00000002: Arquivo não pode ser alterado.
* `UF_APPEND` 0x00000004: Gravações no arquivo só podem ser anexadas.
* `UF_OPAQUE` 0x00000008: Diretório é opaco em relação à união.
* `UF_COMPRESSED` 0x00000020: Arquivo está comprimido (alguns sistemas de arquivos).
* `UF_TRACKED` 0x00000040: Sem notificações para exclusões/renomeações para arquivos com isso definido.
* `UF_DATAVAULT` 0x00000080: Entitlement necessário para leitura e escrita.
* `UF_HIDDEN` 0x00008000: Dica de que este item não deve ser exibido em uma GUI.
* `SF_SUPPORTED` 0x009f0000: Máscara de flags suportadas pelo superusuário.
* `SF_SETTABLE` 0x3fff0000: Máscara de flags alteráveis pelo superusuário.
* `SF_SYNTHETIC` 0xc0000000: Máscara de flags sintéticas somente leitura do sistema.
* `SF_ARCHIVED` 0x00010000: Arquivo está arquivado.
* `SF_IMMUTABLE` 0x00020000: Arquivo não pode ser alterado.
* `SF_APPEND` 0x00040000: Gravações no arquivo só podem ser anexadas.
* `SF_RESTRICTED` 0x00080000: Entitlement necessário para escrita.
* `SF_NOUNLINK` 0x00100000: Item não pode ser removido, renomeado ou montado.
* `SF_FIRMLINK` 0x00800000: Arquivo é um firmlink.
* `SF_DATALESS` 0x40000000: Arquivo é um objeto sem dados.

### **ACLs de Arquivo**

As **ACLs de arquivo** contêm **ACE** (Entradas de Controle de Acesso) onde permissões mais **granulares** podem ser atribuídas a diferentes usuários.

É possível conceder a um **diretório** essas permissões: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a um **arquivo**: `read`, `write`, `append`, `execute`.

Quando o arquivo contém ACLs, você encontrará um "+" ao listar as permissões como em:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Você pode **ler os ACLs** do arquivo com:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Você pode encontrar **todos os arquivos com ACLs** com (isso é muuuito lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Atributos Estendidos

Atributos estendidos têm um nome e um valor desejado, e podem ser vistos usando `ls -@` e manipulados usando o comando `xattr`. Alguns atributos estendidos comuns são:

- `com.apple.resourceFork`: Compatibilidade com o recurso de fork. Também visível como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Mecanismo de quarentena do Gatekeeper (III/6)
- `metadata:*`: MacOS: vários metadados, como `_backup_excludeItem`, ou `kMD*`
- `com.apple.lastuseddate` (#PS): Data de último uso do arquivo
- `com.apple.FinderInfo`: MacOS: Informações do Finder (por exemplo, Tags de cor)
- `com.apple.TextEncoding`: Especifica a codificação de texto de arquivos de texto ASCII
- `com.apple.logd.metadata`: Usado pelo logd em arquivos em `/var/db/diagnostics`
- `com.apple.genstore.*`: Armazenamento geracional (`/.DocumentRevisions-V100` na raiz do sistema de arquivos)
- `com.apple.rootless`: MacOS: Usado pela Proteção de Integridade do Sistema para rotular arquivos (III/10)
- `com.apple.uuidb.boot-uuid`: Marcadores de boot epochs do logd com UUID único
- `com.apple.decmpfs`: MacOS: Compressão de arquivo transparente (II/7)
- `com.apple.cprotect`: \*OS: Dados de criptografia por arquivo (III/11)
- `com.apple.installd.*`: \*OS: Metadados usados pelo installd, por exemplo, `installType`, `uniqueInstallID`

### Recursos de Fork | ADS do macOS

Esta é uma maneira de obter **fluxos de dados alternativos no MacOS**. Você pode salvar conteúdo dentro de um atributo estendido chamado **com.apple.ResourceFork** dentro de um arquivo salvando-o em **file/..namedfork/rsrc**.
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

### decmpfs

O atributo estendido `com.apple.decmpfs` indica que o arquivo está armazenado criptografado, `ls -l` irá relatar um **tamanho de 0** e os dados comprimidos estão dentro deste atributo. Sempre que o arquivo é acessado, ele será descriptografado na memória.

Este atributo pode ser visto com `ls -lO` indicado como comprimido porque arquivos comprimidos também são marcados com a flag `UF_COMPRESSED`. Se um arquivo comprimido for removido, esta flag com `chflags nocompressed </caminho/para/arquivo>`, o sistema não saberá que o arquivo estava comprimido e, portanto, não será capaz de descomprimir e acessar os dados (ele pensará que está vazio na verdade).

A ferramenta afscexpand pode ser usada para forçar a descompressão de um arquivo.

## **Binários Universais &** Formato Mach-o

Os binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar múltiplas arquiteturas no mesmo arquivo**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Despejo de memória do macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Arquivos de Categoria de Risco do Mac OS

O diretório `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` é onde as informações sobre o **risco associado a diferentes extensões de arquivo são armazenadas**. Este diretório categoriza arquivos em vários níveis de risco, influenciando como o Safari lida com esses arquivos ao serem baixados. As categorias são as seguintes:

* **LSRiskCategorySafe**: Arquivos nesta categoria são considerados **totalmente seguros**. O Safari abrirá automaticamente esses arquivos após serem baixados.
* **LSRiskCategoryNeutral**: Esses arquivos não vêm com avisos e **não são abertos automaticamente** pelo Safari.
* **LSRiskCategoryUnsafeExecutable**: Arquivos nesta categoria **disparam um aviso** indicando que o arquivo é um aplicativo. Isso serve como uma medida de segurança para alertar o usuário.
* **LSRiskCategoryMayContainUnsafeExecutable**: Esta categoria é para arquivos, como arquivos compactados, que podem conter um executável. O Safari **disparará um aviso** a menos que possa verificar que todo o conteúdo é seguro ou neutro.

## Arquivos de Log

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
* **`/var/log/system.log`**: Log principal dos sistemas OSX. com.apple.syslogd.plist é responsável pela execução do syslog (você pode verificar se está desativado procurando por "com.apple.syslogd" em `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Estes são os Logs do Sistema Apple que podem conter informações interessantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente através do "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Armazena itens para serem iniciados durante a inicialização do sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: Arquivo de log para o aplicativo DiskUtility (informações sobre unidades, incluindo USBs).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de daemons desativados.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
