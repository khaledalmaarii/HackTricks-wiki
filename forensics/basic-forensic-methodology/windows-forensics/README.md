# Artefatos do Windows

## Artefatos do Windows

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Artefatos Genéricos do Windows

### Notificações do Windows 10

No caminho `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` você pode encontrar o banco de dados `appdb.dat` (antes do aniversário do Windows) ou `wpndatabase.db` (após o aniversário do Windows).

Dentro deste banco de dados SQLite, você pode encontrar a tabela `Notification` com todas as notificações (em formato XML) que podem conter dados interessantes.

### Linha do Tempo

A Linha do Tempo é uma característica do Windows que fornece um **histórico cronológico** de páginas da web visitadas, documentos editados e aplicativos executados.

O banco de dados fica no caminho `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Este banco de dados pode ser aberto com uma ferramenta SQLite ou com a ferramenta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que gera 2 arquivos que podem ser abertos com a ferramenta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Arquivos baixados podem conter o **ADS Zone.Identifier** indicando **como** foi **baixado** da intranet, internet, etc. Alguns softwares (como navegadores) geralmente colocam até **mais** **informações**, como a **URL** de onde o arquivo foi baixado.

## **Backups de Arquivos**

### Lixeira

No Vista/Win7/Win8/Win10, a **Lixeira** pode ser encontrada na pasta **`$Recycle.bin`** na raiz do disco (`C:\$Recycle.bin`).\
Quando um arquivo é excluído nesta pasta, 2 arquivos específicos são criados:

* `$I{id}`: Informações do arquivo (data de quando foi excluído)
* `$R{id}`: Conteúdo do arquivo

![](<../../../.gitbook/assets/image (486).png>)

Tendo esses arquivos, você pode usar a ferramenta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obter o endereço original dos arquivos excluídos e a data em que foram excluídos (use `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
```markdown
### Cópias de Sombra de Volume

Shadow Copy é uma tecnologia incluída no Microsoft Windows que pode criar **cópias de backup** ou snapshots de arquivos de computador ou volumes, mesmo quando estão em uso.

Esses backups geralmente estão localizados em `\System Volume Information` na raiz do sistema de arquivos e o nome é composto por **UIDs** mostrados na seguinte imagem:

![](<../../../.gitbook/assets/image (520).png>)

Montando a imagem forense com o **ArsenalImageMounter**, a ferramenta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) pode ser usada para inspecionar uma cópia de sombra e até mesmo **extrair os arquivos** dos backups de cópia de sombra.

![](<../../../.gitbook/assets/image (521).png>)

A entrada de registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contém os arquivos e chaves **para não fazer backup**:

![](<../../../.gitbook/assets/image (522).png>)

O registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` também contém informações de configuração sobre as `Cópias de Sombra de Volume`.

### Arquivos AutoSalvados do Office

Você pode encontrar os arquivos autosalvados do office em: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Itens de Shell

Um item de shell é um item que contém informações sobre como acessar outro arquivo.

### Documentos Recentes (LNK)

O Windows **cria automaticamente** esses **atalhos** quando o usuário **abre, usa ou cria um arquivo** em:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando uma pasta é criada, um link para a pasta, para a pasta pai e para a pasta avó também é criado.

Esses arquivos de link criados automaticamente **contêm informações sobre a origem** como se é um **arquivo** ou uma **pasta**, **tempos MAC** daquele arquivo, **informações de volume** de onde o arquivo está armazenado e **pasta do arquivo alvo**. Essas informações podem ser úteis para recuperar esses arquivos caso tenham sido removidos.

Além disso, a **data de criação do arquivo de link** é a primeira **vez** que o arquivo original foi **usado** e a **data de modificação** do arquivo de link é a **última vez** que o arquivo de origem foi usado.

Para inspecionar esses arquivos, você pode usar [**LinkParser**](http://4discovery.com/our-tools/).

Nessas ferramentas, você encontrará **2 conjuntos** de timestamps:

* **Primeiro Conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Segundo Conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

O primeiro conjunto de timestamp refere-se aos **timestamps do próprio arquivo**. O segundo conjunto refere-se aos **timestamps do arquivo vinculado**.

Você pode obter as mesmas informações executando a ferramenta CLI do Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Neste caso, as informações serão salvas dentro de um arquivo CSV.

### Jumplists

Estas são os arquivos recentes que são indicados por aplicativo. É a lista de **arquivos recentes usados por um aplicativo** que você pode acessar em cada aplicativo. Eles podem ser criados **automaticamente ou ser personalizados**.

As **jumplists** criadas automaticamente são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. As jumplists são nomeadas seguindo o formato `{id}.autmaticDestinations-ms` onde o ID inicial é o ID do aplicativo.

As jumplists personalizadas são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e são criadas pelo aplicativo geralmente porque algo **importante** aconteceu com o arquivo (talvez marcado como favorito)

O **tempo de criação** de qualquer jumplist indica **a primeira vez que o arquivo foi acessado** e o **tempo modificado a última vez**.

Você pode inspecionar as jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Observe que os carimbos de data/hora fornecidos pelo JumplistExplorer estão relacionados ao próprio arquivo da jumplist_)

### Shellbags

[**Siga este link para aprender o que são os shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USBs no Windows

É possível identificar que um dispositivo USB foi usado graças à criação de:

* Pasta Recente do Windows
* Pasta Recente do Microsoft Office
* Jumplists

Observe que alguns arquivos LNK, em vez de apontar para o caminho original, apontam para a pasta WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

Os arquivos na pasta WPDNSE são uma cópia dos originais, então não sobreviverão a uma reinicialização do PC e o GUID é retirado de um shellbag.

### Informações do Registro

[Verifique esta página para aprender](interesting-windows-registry-keys.md#usb-information) quais chaves de registro contêm informações interessantes sobre dispositivos USB conectados.

### setupapi

Verifique o arquivo `C:\Windows\inf\setupapi.dev.log` para obter os carimbos de data/hora sobre quando a conexão USB foi realizada (procure por `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem.

![](<../../../.gitbook/assets/image (483).png>)

### Limpeza de Plug and Play

A tarefa agendada conhecida como 'Limpeza de Plug and Play' é projetada principalmente para a remoção de versões antigas de drivers. Ao contrário de seu propósito especificado de reter a versão mais recente do pacote de drivers, fontes online sugerem que ela também visa drivers que estiveram inativos por 30 dias. Consequentemente, drivers para dispositivos removíveis não conectados nos últimos 30 dias podem ser sujeitos à exclusão.

A tarefa está localizada no seguinte caminho:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Uma captura de tela mostrando o conteúdo da tarefa é fornecida:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes e Configurações Chave da Tarefa:**
- **pnpclean.dll**: Esta DLL é responsável pelo processo de limpeza real.
- **UseUnifiedSchedulingEngine**: Definido como `TRUE`, indicando o uso do motor genérico de agendamento de tarefas.
- **MaintenanceSettings**:
- **Período ('P1M')**: Direciona o Agendador de Tarefas para iniciar a tarefa de limpeza mensalmente durante a manutenção Automática regular.
- **Prazo ('P2M')**: Instrui o Agendador de Tarefas, se a tarefa falhar por dois meses consecutivos, a executar a tarefa durante a manutenção Automática de emergência.

Esta configuração garante manutenção e limpeza regulares dos drivers, com disposições para tentar novamente a tarefa em caso de falhas consecutivas.

**Para mais informações, verifique:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Emails contêm **2 partes interessantes: Os cabeçalhos e o conteúdo** do email. Nos **cabeçalhos** você pode encontrar informações como:

* **Quem** enviou os emails (endereço de email, IP, servidores de email que redirecionaram o email)
* **Quando** o email foi enviado

Também, dentro dos cabeçalhos `References` e `In-Reply-To` você pode encontrar o ID das mensagens:

![](<../../../.gitbook/assets/image (484).png>)

### Aplicativo de Email do Windows

Este aplicativo salva emails em HTML ou texto. Você pode encontrar os emails dentro de subpastas em `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Os emails são salvos com a extensão `.dat`.

Os **metadados** dos emails e os **contatos** podem ser encontrados dentro do **banco de dados EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Mude a extensão** do arquivo de `.vol` para `.edb` e você pode usar a ferramenta [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) para abri-lo. Dentro da tabela `Message` você pode ver os emails.

### Microsoft Outlook

Quando servidores Exchange ou clientes Outlook são usados, vão existir alguns cabeçalhos MAPI:

* `Mapi-Client-Submit-Time`: Horário do sistema quando o email foi enviado
* `Mapi-Conversation-Index`: Número de mensagens filhas do tópico e carimbo de data/hora de cada mensagem do tópico
* `Mapi-Entry-ID`: Identificador da mensagem.
* `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: Informações sobre o cliente MAPI (mensagem lida? não lida? respondida? redirecionada? fora do escritório?)

No cliente Microsoft Outlook, todas as mensagens enviadas/recebidas, dados de contatos e dados do calendário são armazenados em um arquivo PST em:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

O caminho do registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica o arquivo que está sendo usado.

Você pode abrir o arquivo PST usando a ferramenta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

Quando o Microsoft Outlook é configurado **usando** **IMAP** ou usando um servidor **Exchange**, ele gera um arquivo **OST** que armazena quase as mesmas informações que o arquivo PST. Ele mantém o arquivo sincronizado com o servidor pelos **últimos 12 meses**, com um **tamanho máximo de arquivo de 50GB** e na **mesma pasta onde o arquivo PST é salvo**. Você pode inspecionar este arquivo usando [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperando Anexos

Você pode ser capaz de encontrá-los na pasta:

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird** armazena as informações em **arquivos MBOX** na pasta `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`

## Miniaturas

Quando um usuário acessa uma pasta e a organiza usando miniaturas, então um arquivo `thumbs.db` é criado. Este banco de dados **armazena as miniaturas das imagens** da pasta mesmo que sejam excluídas. No WinXP e Win 8-8.1 este arquivo é criado automaticamente. No Win7/Win10, é criado automaticamente se for acessado via um caminho UNC (\IP\pasta...).

É possível ler este arquivo com a ferramenta [**Thumbsviewer**](https://thumbsviewer.github.io).

### Thumbcache

A partir do Windows Vista, **as pré-visualizações de miniaturas são armazenadas em um local centralizado no sistema**. Isso fornece ao sistema acesso às imagens independentemente de sua localização e aborda questões com a localidade dos arquivos Thumbs.db. O cache é armazenado em **`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`** como vários arquivos com o rótulo **thumbcache\_xxx.db** (numerados pelo tamanho); bem como um índice usado para encontrar miniaturas em cada banco de dados de tamanho.

* Thumbcache\_32.db -> pequeno
* Thumbcache\_96.db -> médio
* Thumbcache\_256.db -> grande
* Thumbcache\_1024.db -> extra grande

Você pode ler este arquivo usando [**ThumbCache Viewer**](https://thumbcacheviewer.github.io).

## Registro do Windows

O Registro do Windows contém muitas **informações** sobre o **sistema e as ações dos usuários**.

Os arquivos que contêm o registro estão localizados em:

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

A partir do Windows Vista e Windows 2008 Server para cima existem alguns backups dos arquivos de registro `HKEY_LOCAL_MACHINE` em **`%Windir%\System32\Config\RegBack\`**.

Também a partir dessas versões, o arquivo de registro **`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`** é criado salvando informações sobre execuções de programas.

### Ferramentas

Algumas ferramentas são úteis para analisar os arquivos de registro:

* **Editor de Registro**: Está instalado no Windows. É uma GUI para navegar pelo registro do Windows da sessão atual.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite carregar o arquivo de registro e navegar por eles com uma GUI. Também contém Bookmarks destacando chaves com informações interessantes.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Novamente, tem uma GUI que permite navegar pelo registro carregado e também contém plugins que destacam informações interessantes dentro do registro carregado.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Outra aplicação GUI capaz de extrair as informações importantes do registro carregado.

### Recuperando Elemento Excluído

Quando uma chave é excluída, ela é marcada como tal, mas até que o espaço que está ocupando seja necessário, ela não será removida. Portanto, usando ferramentas como **Registry Explorer** é possível recuperar essas chaves excluídas.

### Último Tempo de Escrita

Cada Chave-Valor contém um **carimbo de data/hora** indicando a última vez que foi modificado.

### SAM

O arquivo/zona **SAM** contém os **usuários, grupos e hashes das senhas dos usuários** do sistema.

Em `SAM\Domains\Account\Users` você pode obter o nome de usuário, o RID, último login, último logon falhado, contador de login, política de senha e quando a conta foi criada. Para obter os **hashes** você também **precisa** do arquivo/zona **SYSTEM**.

### Entradas Interessantes no Registro do Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programas Executados

### Processos Básicos do Windows

Na página a seguir, você pode aprender sobre os processos básicos do Windows para detectar comportamentos suspeitos:

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### APPs Recentes do Windows

Dentro do registro `NTUSER.DAT` no caminho `Software\Microsoft\Current Version\Search\RecentApps` você pode encontrar subchaves com informações sobre o **aplicativo executado**, **última vez** que foi executado e **número de vezes** que foi lançado.

### BAM (Moderador de Atividade em Segundo Plano)

Você pode abrir o arquivo `SYSTEM` com um editor de registro e dentro do caminho `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` você pode encontrar informações sobre os **aplicativos executados por cada usuário** (note o `{SID}` no caminho) e em **que horário** foram executados (o horário está dentro do valor de Dados do registro).

### Prefetch do Windows

Prefetching é uma técnica que permite a um computador buscar silenciosamente **os recursos necessários para exibir conteúdo** que um usuário **pode acessar em um futuro próximo** para que os recursos possam ser acessados mais rapidamente.

O prefetch do Windows consiste em criar **caches dos programas executados** para poder carregá-los mais rapidamente. Esses caches são criados como arquivos `.pf` dentro do caminho: `C:\Windows\Prefetch`. Há um limite de 128 arquivos no XP/VISTA/WIN7 e 1024 arquivos no Win8/Win10.

O nome do arquivo é criado como `{program_name}-{hash}.pf` (o hash é baseado no caminho e argumentos do executável). No W10 esses arquivos são comprimidos. Note que a mera presença do arquivo indica que **o programa foi executado** em algum momento.

O arquivo `C:\Windows\Prefetch\Layout.ini` contém os **nomes das pastas dos arquivos que são prefetchados**. Este arquivo contém **informações sobre o número de execuções**, **datas** de execução e **arquivos** **abertos** pelo programa.

Para inspecionar esses arquivos, você pode usar a ferramenta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
```markdown
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** tem o mesmo objetivo que o prefetch, **carregar programas mais rapidamente** ao prever o que será carregado a seguir. No entanto, não substitui o serviço de prefetch.
Este serviço irá gerar arquivos de banco de dados em `C:\Windows\Prefetch\Ag*.db`.

Nesses bancos de dados, você pode encontrar o **nome** do **programa**, **número** de **execuções**, **arquivos** **abertos**, **volume** **acessado**, **caminho** **completo**, **intervalos** de **tempo** e **timestamps**.

Você pode acessar essas informações usando a ferramenta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitora** os **recursos** **consumidos** **por um processo**. Apareceu no W8 e armazena os dados em um banco de dados ESE localizado em `C:\Windows\System32\sru\SRUDB.dat`.

Ele fornece as seguintes informações:

* AppID e Caminho
* Usuário que executou o processo
* Bytes Enviados
* Bytes Recebidos
* Interface de Rede
* Duração da Conexão
* Duração do Processo

Essas informações são atualizadas a cada 60 minutos.

Você pode obter a data deste arquivo usando a ferramenta [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**, também conhecido como **AppCompatCache**, é um componente do **Banco de Dados de Compatibilidade de Aplicativos**, criado pela **Microsoft** e usado pelo sistema operacional para identificar problemas de compatibilidade de aplicativos.

O cache armazena vários metadados de arquivos, dependendo do sistema operacional, como:

* Caminho Completo do Arquivo
* Tamanho do Arquivo
* **$Standard\_Information** (SI) Última modificação
* Última atualização do ShimCache
* Flag de Execução de Processo

Essas informações podem ser encontradas no registro em:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 entradas)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 entradas)
* 2008/2012/2016 Win7/Win8/Win10 (1024 entradas)

Você pode usar a ferramenta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) para analisar essas informações.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

O arquivo **Amcache.hve** é um arquivo de registro que armazena informações de aplicativos executados. Está localizado em `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** registra os processos recentes que foram executados e lista o caminho dos arquivos que são executados, o que pode ser usado para encontrar o programa executado. Ele também registra o SHA1 do programa.

Você pode analisar essas informações com a ferramenta [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
O arquivo CVS mais interessante gerado é o `Amcache_Unassociated file entries`.

### RecentFileCache

Este artefato só pode ser encontrado no W7 em `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` e contém informações sobre a execução recente de alguns binários.

Você pode usar a ferramenta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analisar o arquivo.

### Tarefas agendadas

Você pode extraí-las de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` e lê-las como XML.

### Serviços

Você pode encontrá-los no registro em `SYSTEM\ControlSet001\Services`. Você pode ver o que será executado e quando.

### **Windows Store**

As aplicações instaladas podem ser encontradas em `\ProgramData\Microsoft\Windows\AppRepository\`\
Este repositório tem um **log** com **cada aplicação instalada** no sistema dentro do banco de dados **`StateRepository-Machine.srd`**.

Dentro da tabela de Aplicações deste banco de dados, é possível encontrar as colunas: "Application ID", "PackageNumber" e "Display Name". Estas colunas têm informações sobre aplicações pré-instaladas e instaladas e pode-se descobrir se algumas aplicações foram desinstaladas porque os IDs das aplicações instaladas devem ser sequenciais.

Também é possível **encontrar aplicações instaladas** no caminho do registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
E **aplicações desinstaladas** em: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos do Windows

Informações que aparecem nos eventos do Windows são:

* O que aconteceu
* Carimbo de data/hora (UTC + 0)
* Usuários envolvidos
* Hosts envolvidos (nome do host, IP)
* Ativos acessados (arquivos, pastas, impressoras, serviços)

Os logs estão localizados em `C:\Windows\System32\config` antes do Windows Vista e em `C:\Windows\System32\winevt\Logs` após o Windows Vista. Antes do Windows Vista, os logs de eventos estavam em formato binário e depois, estão em **formato XML** e usam a extensão **.evtx**.

A localização dos arquivos de eventos pode ser encontrada no registro SYSTEM em **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Eles podem ser visualizados a partir do Visualizador de Eventos do Windows (**`eventvwr.msc`**) ou com outras ferramentas como [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Segurança

Este registra os eventos de acesso e fornece informações sobre a configuração de segurança que podem ser encontradas em `C:\Windows\System32\winevt\Security.evtx`.

O **tamanho máximo** do arquivo de evento é configurável, e ele começará a sobrescrever eventos antigos quando o tamanho máximo for atingido.

Eventos que são registrados como:

* Login/Logoff
* Ações do usuário
* Acesso a arquivos, pastas e ativos compartilhados
* Modificação da configuração de segurança

Eventos relacionados à autenticação do usuário:

| EventID   | Descrição                     |
| --------- | ---------------------------- |
| 4624      | Autenticação bem-sucedida     |
| 4625      | Erro de autenticação          |
| 4634/4647 | log off                       |
| 4672      | Login com permissões de admin |

Dentro do EventID 4634/4647 existem subtipos interessantes:

* **2 (interativo)**: O login foi interativo usando o teclado ou software como VNC ou `PSexec -U-`
* **3 (rede)**: Conexão a uma pasta compartilhada
* **4 (Batch)**: Processo executado
* **5 (serviço)**: Serviço iniciado pelo Gerenciador de Controle de Serviço
* **6 (proxy):** Login via Proxy
* **7 (Desbloqueio)**: Tela desbloqueada usando senha
* **8 (texto claro de rede)**: Usuário autenticado enviando senhas em texto claro. Este evento costumava vir do IIS
* **9 (novas credenciais)**: É gerado quando o comando `RunAs` é usado ou o usuário acessa um serviço de rede com credenciais diferentes.
* **10 (interativo remoto)**: Autenticação via Serviços de Terminal ou RDP
* **11 (cache interativo)**: Acesso usando as últimas credenciais em cache porque não foi possível contatar o controlador de domínio
* **12 (cache interativo remoto)**: Login remoto com credenciais em cache (uma combinação de 10 e 11).
* **13 (desbloqueio em cache)**: Desbloqueio de uma máquina travada com credenciais em cache.

Neste post, você pode encontrar como imitar todos esses tipos de login e em quais deles você poderá despejar credenciais da memória: [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

As informações de Status e Substatus dos eventos podem indicar mais detalhes sobre as causas do evento. Por exemplo, veja os seguintes Códigos de Status e Substatus do Event ID 4625:

![](<../../../.gitbook/assets/image (455).png>)

### Recuperando Eventos do Windows

É altamente recomendável desligar o PC suspeito **desconectando-o** para maximizar a probabilidade de recuperar os Eventos do Windows. Caso tenham sido excluídos, uma ferramenta que pode ser útil para tentar recuperá-los é [**Bulk_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) indicando a extensão **evtx**.

## Identificando Ataques Comuns com Eventos do Windows

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### Ataque de Força Bruta

Um ataque de força bruta pode ser facilmente identificável porque **vários EventIDs 4625 aparecerão**. Se o ataque foi **bem-sucedido**, após os EventIDs 4625, **um EventID 4624 aparecerá**.

### Mudança de Hora

Isso é terrível para a equipe de forense, pois todos os carimbos de data/hora serão modificados. Este evento é registrado pelo EventID 4616 dentro do log de Eventos de Segurança.

### Dispositivos USB

Os seguintes EventIDs do Sistema são úteis:

* 20001 / 20003 / 10000: Primeira vez que foi usado
* 10100: Atualização de driver

O EventID 112 do DeviceSetupManager contém o carimbo de data/hora de cada dispositivo USB inserido.

### Desligar / Ligar

O ID 6005 do serviço "Event Log" indica que o PC foi ligado. O ID 6006 indica que foi desligado.

### Exclusão de Logs

O EventID 1102 de Segurança indica que os logs foram excluídos.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
