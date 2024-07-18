# Windows Artifacts

## Windows Artifacts

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

## Generic Windows Artifacts

### Windows 10 Notifications

No caminho `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` você pode encontrar o banco de dados `appdb.dat` (antes do aniversário do Windows) ou `wpndatabase.db` (após o aniversário do Windows).

Dentro deste banco de dados SQLite, você pode encontrar a tabela `Notification` com todas as notificações (em formato XML) que podem conter dados interessantes.

### Timeline

Timeline é uma característica do Windows que fornece **histórico cronológico** de páginas da web visitadas, documentos editados e aplicativos executados.

O banco de dados reside no caminho `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Este banco de dados pode ser aberto com uma ferramenta SQLite ou com a ferramenta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que gera 2 arquivos que podem ser abertos com a ferramenta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Arquivos baixados podem conter o **ADS Zone.Identifier** indicando **como** foi **baixado** da intranet, internet, etc. Alguns softwares (como navegadores) geralmente colocam até **mais** **informações** como a **URL** de onde o arquivo foi baixado.

## **File Backups**

### Recycle Bin

No Vista/Win7/Win8/Win10 a **Lixeira** pode ser encontrada na pasta **`$Recycle.bin`** na raiz da unidade (`C:\$Recycle.bin`).\
Quando um arquivo é excluído nesta pasta, 2 arquivos específicos são criados:

* `$I{id}`: Informações do arquivo (data de quando foi excluído)
* `$R{id}`: Conteúdo do arquivo

![](<../../../.gitbook/assets/image (1029).png>)

Tendo esses arquivos, você pode usar a ferramenta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obter o endereço original dos arquivos excluídos e a data em que foram excluídos (use `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Cópias de Sombra de Volume

Cópia de Sombra é uma tecnologia incluída no Microsoft Windows que pode criar **cópias de backup** ou instantâneas de arquivos ou volumes de computador, mesmo quando estão em uso.

Esses backups geralmente estão localizados em `\System Volume Information` na raiz do sistema de arquivos e o nome é composto por **UIDs** mostrados na imagem a seguir:

![](<../../../.gitbook/assets/image (94).png>)

Montando a imagem forense com o **ArsenalImageMounter**, a ferramenta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) pode ser usada para inspecionar uma cópia de sombra e até mesmo **extrair os arquivos** dos backups de cópia de sombra.

![](<../../../.gitbook/assets/image (576).png>)

A entrada do registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contém os arquivos e chaves **para não fazer backup**:

![](<../../../.gitbook/assets/image (254).png>)

O registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` também contém informações de configuração sobre as `Cópias de Sombra de Volume`.

### Arquivos AutoSalvos do Office

Você pode encontrar os arquivos auto-salvos do office em: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Itens de Shell

Um item de shell é um item que contém informações sobre como acessar outro arquivo.

### Documentos Recentes (LNK)

O Windows **cria automaticamente** esses **atalhos** quando o usuário **abre, usa ou cria um arquivo** em:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando uma pasta é criada, um link para a pasta, para a pasta pai e a pasta avó também é criado.

Esses arquivos de link criados automaticamente **contêm informações sobre a origem** como se é um **arquivo** **ou** uma **pasta**, **tempos MAC** desse arquivo, **informações de volume** de onde o arquivo está armazenado e **pasta do arquivo de destino**. Essas informações podem ser úteis para recuperar esses arquivos caso tenham sido removidos.

Além disso, a **data de criação do link** é a primeira **vez** que o arquivo original foi **usado pela primeira vez** e a **data** **modificada** do arquivo de link é a **última** **vez** que o arquivo de origem foi usado.

Para inspecionar esses arquivos, você pode usar [**LinkParser**](http://4discovery.com/our-tools/).

Nesta ferramenta, você encontrará **2 conjuntos** de timestamps:

* **Primeiro Conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Segundo Conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

O primeiro conjunto de timestamps refere-se aos **timestamps do próprio arquivo**. O segundo conjunto refere-se aos **timestamps do arquivo vinculado**.

Você pode obter as mesmas informações executando a ferramenta CLI do Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Neste caso, as informações serão salvas dentro de um arquivo CSV.

### Jumplists

Estes são os arquivos recentes que são indicados por aplicativo. É a lista de **arquivos recentes usados por um aplicativo** que você pode acessar em cada aplicativo. Eles podem ser criados **automaticamente ou ser personalizados**.

Os **jumplists** criados automaticamente são armazenados em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Os jumplists são nomeados seguindo o formato `{id}.autmaticDestinations-ms`, onde o ID inicial é o ID do aplicativo.

Os jumplists personalizados são armazenados em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e são criados pelo aplicativo geralmente porque algo **importante** aconteceu com o arquivo (talvez marcado como favorito).

O **tempo de criação** de qualquer jumplist indica **a primeira vez que o arquivo foi acessado** e o **tempo modificado a última vez**.

Você pode inspecionar os jumplists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (168).png>)

(_Observe que os timestamps fornecidos pelo JumplistExplorer estão relacionados ao próprio arquivo jumplist_)

### Shellbags

[**Siga este link para aprender o que são os shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USBs do Windows

É possível identificar que um dispositivo USB foi usado graças à criação de:

* Pasta Recentes do Windows
* Pasta Recentes do Microsoft Office
* Jumplists

Observe que alguns arquivos LNK, em vez de apontar para o caminho original, apontam para a pasta WPDNSE:

![](<../../../.gitbook/assets/image (218).png>)

Os arquivos na pasta WPDNSE são uma cópia dos originais, portanto, não sobreviverão a uma reinicialização do PC e o GUID é retirado de um shellbag.

### Informações do Registro

[Verifique esta página para aprender](interesting-windows-registry-keys.md#usb-information) quais chaves de registro contêm informações interessantes sobre dispositivos USB conectados.

### setupapi

Verifique o arquivo `C:\Windows\inf\setupapi.dev.log` para obter os timestamps sobre quando a conexão USB foi produzida (procure por `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem.

![](<../../../.gitbook/assets/image (452).png>)

### Limpeza de Plug and Play

A tarefa agendada conhecida como 'Limpeza de Plug and Play' é projetada principalmente para a remoção de versões de driver desatualizadas. Ao contrário de seu propósito especificado de reter a versão mais recente do pacote de driver, fontes online sugerem que ela também visa drivers que estiveram inativos por 30 dias. Consequentemente, drivers para dispositivos removíveis não conectados nos últimos 30 dias podem ser sujeitos à exclusão.

A tarefa está localizada no seguinte caminho: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Uma captura de tela mostrando o conteúdo da tarefa é fornecida: ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Componentes e Configurações Principais da Tarefa:**

* **pnpclean.dll**: Este DLL é responsável pelo processo de limpeza real.
* **UseUnifiedSchedulingEngine**: Definido como `TRUE`, indicando o uso do mecanismo de agendamento de tarefas genérico.
* **MaintenanceSettings**:
* **Period ('P1M')**: Direciona o Agendador de Tarefas a iniciar a tarefa de limpeza mensalmente durante a manutenção automática regular.
* **Deadline ('P2M')**: Instruções ao Agendador de Tarefas, se a tarefa falhar por dois meses consecutivos, para executar a tarefa durante a manutenção automática de emergência.

Esta configuração garante manutenção e limpeza regulares dos drivers, com disposições para reattemptar a tarefa em caso de falhas consecutivas.

**Para mais informações, verifique:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Os emails contêm **2 partes interessantes: Os cabeçalhos e o conteúdo** do email. Nos **cabeçalhos** você pode encontrar informações como:

* **Quem** enviou os emails (endereço de email, IP, servidores de email que redirecionaram o email)
* **Quando** o email foi enviado

Além disso, dentro dos cabeçalhos `References` e `In-Reply-To`, você pode encontrar o ID das mensagens:

![](<../../../.gitbook/assets/image (593).png>)

### Aplicativo de Email do Windows

Este aplicativo salva emails em HTML ou texto. Você pode encontrar os emails dentro de subpastas em `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Os emails são salvos com a extensão `.dat`.

Os **metadados** dos emails e os **contatos** podem ser encontrados dentro do **banco de dados EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Mude a extensão** do arquivo de `.vol` para `.edb` e você pode usar a ferramenta [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) para abri-lo. Dentro da tabela `Message`, você pode ver os emails.

### Microsoft Outlook

Quando servidores Exchange ou clientes Outlook são usados, haverá alguns cabeçalhos MAPI:

* `Mapi-Client-Submit-Time`: Hora do sistema quando o email foi enviado
* `Mapi-Conversation-Index`: Número de mensagens filhas do thread e timestamp de cada mensagem do thread
* `Mapi-Entry-ID`: Identificador da mensagem.
* `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: Informações sobre o cliente MAPI (mensagem lida? não lida? respondida? redirecionada? fora do escritório?)

No cliente Microsoft Outlook, todas as mensagens enviadas/recebidas, dados de contatos e dados de calendário são armazenados em um arquivo PST em:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

O caminho do registro `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica o arquivo que está sendo usado.

Você pode abrir o arquivo PST usando a ferramenta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (498).png>)

### Arquivos OST do Microsoft Outlook

Um **arquivo OST** é gerado pelo Microsoft Outlook quando está configurado com **IMAP** ou um servidor **Exchange**, armazenando informações semelhantes a um arquivo PST. Este arquivo é sincronizado com o servidor, retendo dados por **12 meses** até um **tamanho máximo de 50GB**, e está localizado no mesmo diretório que o arquivo PST. Para visualizar um arquivo OST, o [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) pode ser utilizado.

### Recuperando Anexos

Anexos perdidos podem ser recuperáveis de:

* Para **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* Para **IE11 e acima**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Arquivos MBOX do Thunderbird

**Thunderbird** utiliza **arquivos MBOX** para armazenar dados, localizados em `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturas de Imagem

* **Windows XP e 8-8.1**: Acessar uma pasta com miniaturas gera um arquivo `thumbs.db` armazenando pré-visualizações de imagem, mesmo após a exclusão.
* **Windows 7/10**: `thumbs.db` é criado quando acessado através de uma rede via caminho UNC.
* **Windows Vista e versões mais recentes**: Pré-visualizações de miniaturas são centralizadas em `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` com arquivos nomeados **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) e [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) são ferramentas para visualizar esses arquivos.

### Informações do Registro do Windows

O Registro do Windows, armazenando extensos dados de atividade do sistema e do usuário, está contido em arquivos em:

* `%windir%\System32\Config` para várias subchaves de `HKEY_LOCAL_MACHINE`.
* `%UserProfile%{User}\NTUSER.DAT` para `HKEY_CURRENT_USER`.
* Windows Vista e versões posteriores fazem backup dos arquivos de registro de `HKEY_LOCAL_MACHINE` em `%Windir%\System32\Config\RegBack\`.
* Além disso, informações sobre a execução de programas são armazenadas em `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` a partir do Windows Vista e Windows 2008 Server.

### Ferramentas

Algumas ferramentas são úteis para analisar os arquivos de registro:

* **Editor do Registro**: Está instalado no Windows. É uma GUI para navegar pelo registro do Windows da sessão atual.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite carregar o arquivo de registro e navegar por ele com uma GUI. Também contém Favoritos destacando chaves com informações interessantes.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Novamente, possui uma GUI que permite navegar pelo registro carregado e também contém plugins que destacam informações interessantes dentro do registro carregado.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Outro aplicativo GUI capaz de extrair informações importantes do registro carregado.

### Recuperando Elemento Excluído

Quando uma chave é excluída, ela é marcada como tal, mas até que o espaço que está ocupando seja necessário, não será removida. Portanto, usando ferramentas como **Registry Explorer**, é possível recuperar essas chaves excluídas.

### Último Tempo de Escrita

Cada Par-Chave contém um **timestamp** indicando a última vez que foi modificado.

### SAM

O arquivo/hive **SAM** contém os **hashes de senhas de usuários, grupos e usuários** do sistema.

Em `SAM\Domains\Account\Users`, você pode obter o nome de usuário, o RID, o último login, o último logon falhado, o contador de logins, a política de senhas e quando a conta foi criada. Para obter os **hashes**, você também **precisa** do arquivo/hive **SYSTEM**.

### Entradas Interessantes no Registro do Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programas Executados

### Processos Básicos do Windows

Neste [post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), você pode aprender sobre os processos comuns do Windows para detectar comportamentos suspeitos.

### Aplicativos Recentes do Windows

Dentro do registro `NTUSER.DAT` no caminho `Software\Microsoft\Current Version\Search\RecentApps`, você pode subchaves com informações sobre o **aplicativo executado**, **última vez** que foi executado e **número de vezes** que foi iniciado.

### BAM (Moderador de Atividade em Segundo Plano)

Você pode abrir o arquivo `SYSTEM` com um editor de registro e dentro do caminho `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` você pode encontrar informações sobre os **aplicativos executados por cada usuário** (note o `{SID}` no caminho) e **a que horas** foram executados (a hora está dentro do valor de Dados do registro).

### Windows Prefetch

Prefetching é uma técnica que permite que um computador silenciosamente **busque os recursos necessários para exibir conteúdo** que um usuário **pode acessar em um futuro próximo**, para que os recursos possam ser acessados mais rapidamente.

O prefetch do Windows consiste em criar **caches dos programas executados** para poder carregá-los mais rápido. Esses caches são criados como arquivos `.pf` dentro do caminho: `C:\Windows\Prefetch`. Há um limite de 128 arquivos no XP/VISTA/WIN7 e 1024 arquivos no Win8/Win10.

O nome do arquivo é criado como `{program_name}-{hash}.pf` (o hash é baseado no caminho e argumentos do executável). No W10, esses arquivos são comprimidos. Observe que a mera presença do arquivo indica que **o programa foi executado** em algum momento.

O arquivo `C:\Windows\Prefetch\Layout.ini` contém os **nomes das pastas dos arquivos que são pré-carregados**. Este arquivo contém **informações sobre o número de execuções**, **datas** da execução e **arquivos** **abertos** pelo programa.

Para inspecionar esses arquivos, você pode usar a ferramenta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** tem o mesmo objetivo que o prefetch, **carregar programas mais rápido** prevendo o que será carregado a seguir. No entanto, não substitui o serviço de prefetch.\
Este serviço gerará arquivos de banco de dados em `C:\Windows\Prefetch\Ag*.db`.

Nestes bancos de dados, você pode encontrar o **nome** do **programa**, **número** de **execuções**, **arquivos** **abertos**, **volume** **acessado**, **caminho** **completo**, **períodos** e **timestamps**.

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
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

O **AppCompatCache**, também conhecido como **ShimCache**, faz parte do **Banco de Dados de Compatibilidade de Aplicações** desenvolvido pela **Microsoft** para lidar com problemas de compatibilidade de aplicações. Este componente do sistema registra várias peças de metadados de arquivos, que incluem:

* Caminho completo do arquivo
* Tamanho do arquivo
* Hora da Última Modificação sob **$Standard\_Information** (SI)
* Hora da Última Atualização do ShimCache
* Sinalizador de Execução do Processo

Esses dados são armazenados no registro em locais específicos com base na versão do sistema operacional:

* Para XP, os dados são armazenados em `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` com capacidade para 96 entradas.
* Para Server 2003, bem como para as versões do Windows 2008, 2012, 2016, 7, 8 e 10, o caminho de armazenamento é `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, acomodando 512 e 1024 entradas, respectivamente.

Para analisar as informações armazenadas, a ferramenta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) é recomendada para uso.

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

O arquivo **Amcache.hve** é essencialmente um hive de registro que registra detalhes sobre aplicações que foram executadas em um sistema. Ele é tipicamente encontrado em `C:\Windows\AppCompat\Programas\Amcache.hve`.

Este arquivo é notável por armazenar registros de processos recentemente executados, incluindo os caminhos para os arquivos executáveis e seus hashes SHA1. Essas informações são inestimáveis para rastrear a atividade de aplicações em um sistema.

Para extrair e analisar os dados do **Amcache.hve**, a ferramenta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) pode ser usada. O seguinte comando é um exemplo de como usar o AmcacheParser para analisar o conteúdo do arquivo **Amcache.hve** e gerar os resultados em formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre os arquivos CSV gerados, o `Amcache_Unassociated file entries` é particularmente notável devido às ricas informações que fornece sobre entradas de arquivos não associadas.

O arquivo CVS mais interessante gerado é o `Amcache_Unassociated file entries`.

### RecentFileCache

Este artefato só pode ser encontrado no W7 em `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` e contém informações sobre a execução recente de alguns binários.

Você pode usar a ferramenta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analisar o arquivo.

### Tarefas agendadas

Você pode extraí-las de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` e lê-las como XML.

### Serviços

Você pode encontrá-los no registro em `SYSTEM\ControlSet001\Services`. Você pode ver o que será executado e quando.

### **Windows Store**

Os aplicativos instalados podem ser encontrados em `\ProgramData\Microsoft\Windows\AppRepository\`\
Este repositório possui um **log** com **cada aplicativo instalado** no sistema dentro do banco de dados **`StateRepository-Machine.srd`**.

Dentro da tabela de Aplicativos deste banco de dados, é possível encontrar as colunas: "Application ID", "PackageNumber" e "Display Name". Essas colunas têm informações sobre aplicativos pré-instalados e instalados e pode-se verificar se alguns aplicativos foram desinstalados, pois os IDs dos aplicativos instalados devem ser sequenciais.

É também possível **encontrar aplicativos instalados** dentro do caminho do registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
E **aplicativos desinstalados** em: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos do Windows

As informações que aparecem nos eventos do Windows são:

* O que aconteceu
* Timestamp (UTC + 0)
* Usuários envolvidos
* Hosts envolvidos (nome do host, IP)
* Ativos acessados (arquivos, pastas, impressora, serviços)

Os logs estão localizados em `C:\Windows\System32\config` antes do Windows Vista e em `C:\Windows\System32\winevt\Logs` após o Windows Vista. Antes do Windows Vista, os logs de eventos estavam em formato binário e, após, estão em **formato XML** e usam a extensão **.evtx**.

A localização dos arquivos de eventos pode ser encontrada no registro do SYSTEM em **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Eles podem ser visualizados a partir do Visualizador de Eventos do Windows (**`eventvwr.msc`**) ou com outras ferramentas como [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Compreendendo o Registro de Eventos de Segurança do Windows

Eventos de acesso são registrados no arquivo de configuração de segurança localizado em `C:\Windows\System32\winevt\Security.evtx`. O tamanho deste arquivo é ajustável e, quando sua capacidade é atingida, eventos mais antigos são sobrescritos. Eventos registrados incluem logins e logoffs de usuários, ações de usuários e alterações nas configurações de segurança, bem como acesso a arquivos, pastas e ativos compartilhados.

### IDs de Evento Chave para Autenticação de Usuário:

* **EventID 4624**: Indica que um usuário se autenticou com sucesso.
* **EventID 4625**: Sinaliza uma falha de autenticação.
* **EventIDs 4634/4647**: Representam eventos de logoff de usuário.
* **EventID 4672**: Denota login com privilégios administrativos.

#### Subtipos dentro do EventID 4634/4647:

* **Interativo (2)**: Login direto do usuário.
* **Rede (3)**: Acesso a pastas compartilhadas.
* **Lote (4)**: Execução de processos em lote.
* **Serviço (5)**: Lançamentos de serviços.
* **Proxy (6)**: Autenticação proxy.
* **Desbloquear (7)**: Tela desbloqueada com uma senha.
* **Texto Claro da Rede (8)**: Transmissão de senha em texto claro, muitas vezes do IIS.
* **Novas Credenciais (9)**: Uso de credenciais diferentes para acesso.
* **Interativo Remoto (10)**: Login em serviços de desktop remoto ou terminal.
* **Cache Interativo (11)**: Login com credenciais em cache sem contato com o controlador de domínio.
* **Cache Interativo Remoto (12)**: Login remoto com credenciais em cache.
* **Desbloqueio em Cache (13)**: Desbloqueio com credenciais em cache.

#### Códigos de Status e Substatus para EventID 4625:

* **0xC0000064**: Nome de usuário não existe - Pode indicar um ataque de enumeração de nome de usuário.
* **0xC000006A**: Nome de usuário correto, mas senha errada - Possível tentativa de adivinhação de senha ou força bruta.
* **0xC0000234**: Conta de usuário bloqueada - Pode seguir um ataque de força bruta resultando em múltiplos logins falhados.
* **0xC0000072**: Conta desativada - Tentativas não autorizadas de acessar contas desativadas.
* **0xC000006F**: Logon fora do horário permitido - Indica tentativas de acesso fora do horário de login definido, um possível sinal de acesso não autorizado.
* **0xC0000070**: Violação das restrições de estação de trabalho - Pode ser uma tentativa de login de um local não autorizado.
* **0xC0000193**: Expiração da conta - Tentativas de acesso com contas de usuário expiradas.
* **0xC0000071**: Senha expirada - Tentativas de login com senhas desatualizadas.
* **0xC0000133**: Problemas de sincronização de tempo - Grandes discrepâncias de tempo entre cliente e servidor podem indicar ataques mais sofisticados, como pass-the-ticket.
* **0xC0000224**: Mudança obrigatória de senha necessária - Mudanças obrigatórias frequentes podem sugerir uma tentativa de desestabilizar a segurança da conta.
* **0xC0000225**: Indica um bug do sistema em vez de um problema de segurança.
* **0xC000015b**: Tipo de logon negado - Tentativa de acesso com tipo de logon não autorizado, como um usuário tentando executar um logon de serviço.

#### EventID 4616:

* **Mudança de Hora**: Modificação do horário do sistema, pode obscurecer a linha do tempo dos eventos.

#### EventID 6005 e 6006:

* **Inicialização e Desligamento do Sistema**: EventID 6005 indica que o sistema está iniciando, enquanto o EventID 6006 marca seu desligamento.

#### EventID 1102:

* **Exclusão de Log**: Logs de segurança sendo limpos, o que é frequentemente um sinal de alerta para encobrir atividades ilícitas.

#### EventIDs para Rastreamento de Dispositivos USB:

* **20001 / 20003 / 10000**: Primeira conexão do dispositivo USB.
* **10100**: Atualização do driver USB.
* **EventID 112**: Hora da inserção do dispositivo USB.

Para exemplos práticos sobre como simular esses tipos de login e oportunidades de despejo de credenciais, consulte o [guia detalhado da Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Os detalhes do evento, incluindo códigos de status e substatus, fornecem mais insights sobre as causas dos eventos, particularmente notáveis no Event ID 4625.

### Recuperando Eventos do Windows

Para aumentar as chances de recuperar Eventos do Windows excluídos, é aconselhável desligar o computador suspeito desconectando-o diretamente. **Bulk\_extractor**, uma ferramenta de recuperação que especifica a extensão `.evtx`, é recomendada para tentar recuperar tais eventos.

### Identificando Ataques Comuns via Eventos do Windows

Para um guia abrangente sobre como utilizar os IDs de Evento do Windows na identificação de ataques cibernéticos comuns, visite [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Ataques de Força Bruta

Identificáveis por múltiplos registros de EventID 4625, seguidos por um EventID 4624 se o ataque for bem-sucedido.

#### Mudança de Hora

Registrada pelo EventID 4616, mudanças no horário do sistema podem complicar a análise forense.

#### Rastreamento de Dispositivos USB

IDs de Evento do Sistema úteis para rastreamento de dispositivos USB incluem 20001/20003/10000 para uso inicial, 10100 para atualizações de driver e EventID 112 do DeviceSetupManager para timestamps de inserção.

#### Eventos de Energia do Sistema

EventID 6005 indica inicialização do sistema, enquanto EventID 6006 marca o desligamento.

#### Exclusão de Log

O EventID de Segurança 1102 sinaliza a exclusão de logs, um evento crítico para análise forense.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos no** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
