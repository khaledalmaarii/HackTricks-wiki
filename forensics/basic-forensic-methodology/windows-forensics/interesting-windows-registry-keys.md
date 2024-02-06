# Chaves de Registro do Windows Interessantes

## Chaves de Registro do Windows Interessantes

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## **Informações do Sistema Windows**

### Versão

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Versão do Windows, Service Pack, Hora da instalação e proprietário registrado

### Nome do Host

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nome do host

### Fuso Horário

* **`System\ControlSet001\Control\TimeZoneInformation`**: Fuso horário

### Último Horário de Acesso

* **`System\ControlSet001\Control\Filesystem`**: Último horário de acesso (por padrão, está desativado com `NtfsDisableLastAccessUpdate=1`, se `0`, então está ativado).
* Para ativar: `fsutil behavior set disablelastaccess 0`

### Horário de Desligamento

* `System\ControlSet001\Control\Windows`: Horário de desligamento
* `System\ControlSet001\Control\Watchdog\Display`: Contagem de desligamentos (apenas XP)

### Informações de Rede

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces de rede
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: Primeira e última vez que uma conexão de rede foi realizada e conexões através de VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (para XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Tipo de rede (0x47-sem fio, 0x06-cabo, 0x17-3G) e categoria (0-Público, 1-Privado/Doméstico, 2-Domínio/Trabalho) e últimas conexões

### Pastas Compartilhadas

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Pastas compartilhadas e suas configurações. Se **Caching do Lado do Cliente** (CSCFLAGS) estiver ativado, uma cópia dos arquivos compartilhados será salva nos clientes e no servidor em `C:\Windows\CSC`
* CSCFlag=0 -> Por padrão, o usuário precisa indicar os arquivos que deseja armazenar em cache
* CSCFlag=16 -> Armazenamento automático de documentos. "Todos os arquivos e programas que os usuários abrem na pasta compartilhada estão automaticamente disponíveis offline" com a opção "otimizar para desempenho" desmarcada.
* CSCFlag=32 -> Como as opções anteriores, mas com a opção "otimizar para desempenho" marcada
* CSCFlag=48 -> Cache desativado.
* CSCFlag=2048: Essa configuração está presente apenas no Win 7 e 8 e é a configuração padrão até você desativar o "Compartilhamento Simples de Arquivos" ou usar a opção de compartilhamento "avançada". Também parece ser a configuração padrão para o "Grupo Doméstico"
* CSCFlag=768 -> Essa configuração foi vista apenas em dispositivos de impressão compartilhados.

### Programas de Inicialização Automática

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Pesquisas do Explorador

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: O que o usuário pesquisou usando o explorador/assistente. O item com `MRU=0` é o último.

### Caminhos Digitados

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Caminhos digitados no explorador (apenas W10)

### Documentos Recentes

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: Documentos recentes abertos pelo usuário
* `NTUSER.DAT\Software\Microsoft\Office{Versão}{Excel|Word}\FileMRU`: Documentos recentes do Office. Versões:
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Versão}{Excel|Word} UserMRU\LiveID_###\FileMRU`: Documentos recentes do Office. Versões:
* 15.0 Office 2013
* 16.0 Office 2016

### MRUs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

Indica o caminho de onde o executável foi executado

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

Indica arquivos abertos dentro de uma janela aberta

### Últimos Comandos Executados

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### User AssistKey

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

O GUID é o id do aplicativo. Dados salvos:

* Último Horário de Execução
* Contagem de Execuções
* Nome do aplicativo GUI (contém o caminho absoluto e mais informações)
* Tempo de foco e Nome do foco

## Shellbags

Quando você abre um diretório, o Windows salva dados sobre como visualizar o diretório no registro. Essas entradas são conhecidas como Shellbags.

Acesso ao Explorador:

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Acesso à Área de Trabalho:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Para analisar os Shellbags, você pode usar [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) e será capaz de encontrar o **tempo MAC da pasta** e também a **data de criação e modificação do shellbag** que estão relacionadas com a **primeira vez e a última vez** que a pasta foi acessada.

Observe 2 coisas na seguinte imagem:

1. Sabemos o **nome das pastas do USB** que foi inserido em **E:**
2. Sabemos quando o **shellbag foi criado e modificado** e quando a pasta foi criada e acessada

![](<../../../.gitbook/assets/image (475).png>)

## Informações sobre USB

### Informações do Dispositivo

O registro `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` monitora cada dispositivo USB que foi conectado ao PC.\
Dentro deste registro é possível encontrar:

* Nome do fabricante
* Nome e versão do produto
* ID da Classe do Dispositivo
* Nome do volume (nas imagens a seguir, o nome do volume é a subchave destacada)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

Além disso, verificando o registro `HKLM\SYSTEM\ControlSet001\Enum\USB` e comparando os valores das subchaves, é possível encontrar o valor VID.

![](<../../../.gitbook/assets/image (478).png>)

Com as informações anteriores, o registro `SOFTWARE\Microsoft\Windows Portable Devices\Devices` pode ser usado para obter o **`{GUID}`**:

![](<../../../.gitbook/assets/image (480).png>)

### Usuário que utilizou o dispositivo

Tendo o **{GUID}** do dispositivo, agora é possível **verificar todos os hives NTUDER.DAT de todos os usuários**, procurando pelo GUID até encontrá-lo em um deles (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Último montado

Verificando o registro `System\MoutedDevices`, é possível descobrir **qual dispositivo foi o último montado**. Na imagem a seguir, verifique como o último dispositivo montado em `E:` é o Toshiba (usando a ferramenta Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Número de Série do Volume

Em `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, você pode encontrar o número de série do volume. **Sabendo o nome do volume e o número de série do volume, você pode correlacionar as informações** dos arquivos LNK que usam essas informações.

Observe que quando um dispositivo USB é formatado:

* Um novo nome de volume é criado
* Um novo número de série de volume é criado
* O número de série físico é mantido

### Timestamps

Em `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`, você pode encontrar a primeira e última vez que o dispositivo foi conectado:

* 0064 -- Primeira conexão
* 0066 -- Última conexão
* 0067 -- Desconexão

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
