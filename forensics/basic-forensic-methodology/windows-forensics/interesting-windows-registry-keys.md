# Chaves do Registro do Windows Interessantes

## Chaves do Registro do Windows Interessantes

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informações do sistema Windows**

### Versão

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Versão do Windows, Service Pack, Tempo de instalação e o proprietário registrado

### Nome do Host

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nome do Host

### Fuso Horário

* **`System\ControlSet001\Control\TimeZoneInformation`**: Fuso Horário

### Último Acesso

* **`System\ControlSet001\Control\Filesystem`**: Último acesso (por padrão está desativado com `NtfsDisableLastAccessUpdate=1`, se `0`, então, está ativado).
* Para ativar: `fsutil behavior set disablelastaccess 0`

### Tempo de Desligamento

* `System\ControlSet001\Control\Windows`: Tempo de desligamento
* `System\ControlSet001\Control\Watchdog\Display`: Contagem de desligamento (apenas XP)

### Informações de Rede

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces de rede
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: Primeira e última vez que uma conexão de rede foi realizada e conexões através de VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (para XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Tipo de rede (0x47-sem fio, 0x06-cabo, 0x17-3G) e categoria (0-Pública, 1-Privada/Casa, 2-Domínio/Trabalho) e últimas conexões

### Pastas Compartilhadas

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Pastas compartilhadas e suas configurações. Se **Client Side Caching** (CSCFLAGS) estiver ativado, então, uma cópia dos arquivos compartilhados será salva nos clientes e servidor em `C:\Windows\CSC`
* CSCFlag=0 -> Por padrão o usuário precisa indicar os arquivos que ele quer armazenar em cache
* CSCFlag=16 -> Caching automático de documentos. "Todos os arquivos e programas que os usuários abrem da pasta compartilhada estão automaticamente disponíveis offline" com a opção "otimizar para desempenho" desmarcada.
* CSCFlag=32 -> Como as opções anteriores, mas com "otimizar para desempenho" marcado
* CSCFlag=48 -> Cache está desativado.
* CSCFlag=2048: Esta configuração é apenas no Win 7 & 8 e é a configuração padrão até você desativar o "Compartilhamento de arquivos simples" ou usar a opção de compartilhamento "avançado". Também parece ser a configuração padrão para o "Grupo Doméstico"
* CSCFlag=768 -> Esta configuração foi vista apenas em dispositivos de impressão compartilhados.

### Programas de AutoStart

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Pesquisas no Explorer

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: O que o usuário pesquisou usando o explorer/helper. O item com `MRU=0` é o último.

### Caminhos Digitados

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Caminhos digitados no explorer (apenas W10)

### Documentos Recentes

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: Documentos recentes abertos pelo usuário
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU`: Documentos recentes do office. Versões:
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU`: Documentos recentes do office. Versões:
* 15.0 office 2013
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

### Chave User Assist

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

O GUID é o id do aplicativo. Dados salvos:

* Último Tempo de Execução
* Contagem de Execução
* Nome do aplicativo GUI (isso contém o caminho absoluto e mais informações)
* Tempo de foco e Nome do foco

## Shellbags

Quando você abre um diretório, o Windows salva dados sobre como visualizar o diretório no registro. Essas entradas são conhecidas como Shellbags.

Acesso ao Explorer:

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Acesso ao Desktop:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Para analisar os Shellbags, você pode usar o [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) e você será capaz de encontrar o **tempo MAC da pasta** e também a **data de criação e data de modificação do shellbag** que estão relacionados ao **primeiro e último tempo** que a pasta foi acessada.

Observe 2 coisas da seguinte imagem:

1. Sabemos o **nome das pastas do USB** que foi inserido em **E:**
2. Sabemos quando o **shellbag foi criado e modificado** e quando a pasta foi criada e acessada

![](<../../../.gitbook/assets/image (475).png>)

## Informações USB

### Informações do Dispositivo

O registro `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` monitora cada dispositivo USB que foi conectado ao PC.\
Dentro deste registro é possível encontrar:

* O nome do fabricante
* O nome do produto e versão
* O ID da Classe do Dispositivo
* O nome do volume (nas imagens a seguir o nome do volume é a subchave destacada)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

Além disso, verificando o registro `HKLM\SYSTEM\ControlSet001\Enum\USB` e comparando os valores das subchaves é possível encontrar o valor VID.

![](<../../../.gitbook/assets/image (478).png>)

Com as informações anteriores, o registro `SOFTWARE\Microsoft\Windows Portable Devices\Devices` pode ser usado para obter o **`{GUID}`**:

![](<../../../.gitbook/assets/image (480).png>)

### Usuário que usou o dispositivo

Tendo o **{GUID}** do dispositivo, agora é possível **verificar todas as colmeias NTUDER.DAT de todos os usuários**, procurando pelo GUID até encontrá-lo em uma delas (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Último montado

Verificando o registro `System\MoutedDevices` é possível descobrir **qual dispositivo foi o último montado**. Na imagem a seguir, veja como o último dispositivo montado em `E:` é o da Toshiba (usando a ferramenta Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Número de Série do Volume

Em `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` você pode encontrar o número de série do volume. **Sabendo o nome do volume e o número de série do volume, você pode correlacionar as informações** de arquivos LNK que usam essa informação.

Note que quando um dispositivo USB é formatado:

* Um novo nome de volume é criado
* Um novo número de série do volume é criado
* O número de série físico é mantido

### Timestamps

Em `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\` você pode encontrar a primeira e última vez que o dispositivo foi conectado:

* 0064 -- Primeira conexão
* 0066 -- Última conexão
* 0067 -- Desconexão

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
