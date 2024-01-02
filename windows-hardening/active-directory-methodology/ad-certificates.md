# Certificados AD

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

### Partes de um certificado

* **Subject** - O proprietário do certificado.
* **Public Key** - Associa o Subject com uma chave privada armazenada separadamente.
* **Datas NotBefore e NotAfter** - Definem a duração da validade do certificado.
* **Serial Number** - Um identificador para o certificado atribuído pela CA.
* **Issuer** - Identifica quem emitiu o certificado (comumente uma CA).
* **SubjectAlternativeName** - Define um ou mais nomes alternativos pelos quais o Subject pode ser conhecido. (_Veja abaixo_)
* **Basic Constraints** - Identifica se o certificado é uma CA ou uma entidade final, e se existem restrições ao usar o certificado.
* **Extended Key Usages (EKUs)** - Identificadores de objeto (OIDs) que descrevem **como o certificado será usado**. Também conhecido como Enhanced Key Usage na terminologia da Microsoft. OIDs EKU comuns incluem:
* Code Signing (OID 1.3.6.1.5.5.7.3.3) - O certificado é para assinatura de código executável.
* Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - O certificado é para criptografia de sistemas de arquivos.
* Secure Email (1.3.6.1.5.5.7.3.4) - O certificado é para criptografia de e-mail.
* Client Authentication (OID 1.3.6.1.5.5.7.3.2) - O certificado é para autenticação em outro servidor (por exemplo, para AD).
* Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - O certificado é para uso em autenticação de smart card.
* Server Authentication (OID 1.3.6.1.5.5.7.3.1) - O certificado é para identificação de servidores (por exemplo, certificados HTTPS).
* **Signature Algorithm** - Especifica o algoritmo usado para assinar o certificado.
* **Signature** - A assinatura do corpo do certificado feita usando a chave privada do emissor (por exemplo, de uma CA).

#### Subject Alternative Names

Um **Subject Alternative Name** (SAN) é uma extensão X.509v3. Ele permite **identidades adicionais** a serem vinculadas a um **certificado**. Por exemplo, se um servidor web hospeda **conteúdo para múltiplos domínios**, **cada** domínio aplicável poderia ser **incluído** no **SAN** para que o servidor web precise apenas de um único certificado HTTPS.

Por padrão, durante a autenticação baseada em certificado, uma maneira de o AD mapear certificados para contas de usuário é com base em um UPN especificado no SAN. Se um atacante puder **especificar um SAN arbitrário** ao solicitar um certificado que tenha um **EKU que permita autenticação de cliente**, e a CA criar e assinar um certificado usando o SAN fornecido pelo atacante, o **atacante pode se tornar qualquer usuário no domínio**.

### CAs

O AD CS define certificados de CA que a floresta AD confia em quatro locais sob o contêiner `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`, cada um diferindo pelo seu propósito:

* O contêiner **Certification Authorities** define **certificados de CA raiz confiáveis**. Essas CAs estão no **topo da hierarquia da árvore PKI** e são a base da confiança nos ambientes AD CS. Cada CA é representada como um objeto AD dentro do contêiner onde o **objectClass** é definido como **`certificationAuthority`** e a propriedade **`cACertificate`** contém os **bytes** do **certificado da CA**. O Windows propaga esses certificados de CA para o armazenamento de certificados Trusted Root Certification Authorities em **cada máquina Windows**. Para que o AD considere um certificado como **confiável**, a cadeia de confiança do certificado deve eventualmente **terminar** com **uma das CAs raiz** definidas neste contêiner.
* O contêiner **Enrolment Services** define cada **Enterprise CA** (ou seja, CAs criadas no AD CS com o papel de Enterprise CA habilitado). Cada Enterprise CA tem um objeto AD com os seguintes atributos:
* Um atributo **objectClass** definido para **`pKIEnrollmentService`**
* Um atributo **`cACertificate`** contendo os **bytes do certificado da CA**
* Uma propriedade **`dNSHostName`** que define o **host DNS da CA**
* Um campo **certificateTemplates** definindo os **modelos de certificado habilitados**. Modelos de certificado são um "blueprint" de configurações que a CA usa ao criar um certificado, e incluem coisas como os EKUs, permissões de inscrição, a expiração do certificado, requisitos de emissão e configurações de criptografia. Discutiremos modelos de certificado mais detalhadamente mais tarde.

{% hint style="info" %}
Em ambientes AD, **clientes interagem com Enterprise CAs para solicitar um certificado** com base nas configurações definidas em um modelo de certificado. Certificados de Enterprise CA são propagados para o armazenamento de certificados Intermediate Certification Authorities em cada máquina Windows
{% endhint %}

* O objeto AD **NTAuthCertificates** define certificados de CA que permitem autenticação no AD. Este objeto tem um **objectClass** de **`certificationAuthority`** e a propriedade **`cACertificate`** do objeto define um array de **certificados de CA confiáveis**. Máquinas Windows unidas ao AD propagam essas CAs para o armazenamento de certificados Intermediate Certification Authorities em cada máquina. Aplicações **cliente** podem **autenticar** no AD usando um certificado apenas se uma das **CAs definidas pelo objeto NTAuthCertificates** tiver **assinado** o certificado do cliente autenticador.
* O contêiner **AIA** (Authority Information Access) contém os objetos AD de CAs intermediárias e cruzadas. **CAs intermediárias são "filhas" de CAs raiz** na hierarquia da árvore PKI; como tal, este contêiner existe para ajudar na **validação de cadeias de certificados**. Como o contêiner Certification Authorities, cada **CA é representada como um objeto AD** no contêiner AIA onde o atributo objectClass é definido como certificationAuthority e a propriedade **`cACertificate`** contém os **bytes** do **certificado da CA**. Essas CAs são propagadas para o armazenamento de certificados Intermediate Certification Authorities em cada máquina Windows.

### Fluxo de Solicitação de Certificado do Cliente

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

É o processo para **obter um certificado** do AD CS. Em alto nível, durante a inscrição, os clientes primeiro **encontram uma Enterprise CA** com base nos **objetos no contêiner Enrolment Services** discutido acima.

1. Os clientes então geram um **par de chaves pública-privada** e
2. colocam a chave pública em uma **mensagem de solicitação de assinatura de certificado (CSR)** junto com outros detalhes, como o subject do certificado e o **nome do modelo de certificado**. Os clientes então **assinam o CSR com sua chave privada** e enviam o CSR para um servidor Enterprise CA.
3. O servidor **CA** verifica se o cliente **pode solicitar certificados**. Se sim, ele determina se emitirá um certificado consultando o objeto AD do **modelo de certificado** especificado no CSR. A CA verificará se o objeto AD do modelo de certificado **permite** que a conta autenticadora **obtenha um certificado**.
4. Se sim, a **CA gera um certificado** usando as configurações de "blueprint" definidas pelo **modelo de certificado** (por exemplo, EKUs, configurações de criptografia e requisitos de emissão) e usando as outras informações fornecidas no CSR, se permitido pelas configurações do modelo do certificado. A **CA assina o certificado** usando sua chave privada e, em seguida, o retorna ao cliente.

### Modelos de Certificado

O AD CS armazena modelos de certificado disponíveis como objetos AD com um **objectClass** de **`pKICertificateTemplate`** localizado no seguinte contêiner:

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

Os atributos do objeto de modelo de certificado AD **definem suas configurações, e seu descritor de segurança controla** quais **princípios podem se inscrever** no certificado ou **editar** o modelo de certificado.

O atributo **`pKIExtendedKeyUsage`** em um objeto de modelo de certificado AD contém um **array de OIDs** habilitados no modelo. Esses OIDs EKU afetam **para que o certificado pode ser usado.** Você pode encontrar uma [lista de OIDs possíveis aqui](https://www.pkisolutions.com/object-identifiers-oid-in-pki/).

#### OIDs de Autenticação

* `1.3.6.1.5.5.7.3.2`: Client Authentication
* `1.3.6.1.5.2.3.4`: PKINIT Client Authentication (precisa ser adicionado manualmente)
* `1.3.6.1.4.1.311.20.2.2`: Smart Card Logon
* `2.5.29.37.0`: Qualquer propósito
* `(sem EKUs)`: SubCA
* Um OID EKU adicional que descobrimos que poderíamos abusar é o OID Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`). Certificados com este OID podem ser usados para **solicitar certificados em nome de outro usuário** a menos que restrições específicas sejam impostas.

## Inscrição de Certificado

Um administrador precisa **criar o modelo de certificado** e então uma **Enterprise CA "publica"** o modelo, tornando-o disponível para os clientes se inscreverem. O AD CS especifica que um modelo de certificado está habilitado em uma Enterprise CA **adicionando o nome do modelo ao campo `certificatetemplates`** do objeto AD.

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
O AD CS define direitos de inscrição - quais **princípios podem solicitar** um certificado – usando dois descritores de segurança: um no objeto AD do **modelo de certificado** e outro na **própria Enterprise CA**.\
Um cliente precisa ser concedido em ambos os descritores de segurança para poder solicitar um certificado.
{% endhint %}

### Direitos de Inscrição de Modelos de Certificado

* **O ACE concede a um princípio o direito estendido de Certificate-Enrollment**. O ACE bruto concede ao princípio o direito de acesso `RIGHT_DS_CONTROL_ACCESS45` onde o **ObjectType** é definido como `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. Este GUID corresponde ao direito estendido **Certificate-Enrolment**.
* **O ACE concede a um princípio o direito estendido de Certificate-AutoEnrollment**. O ACE bruto concede ao princípio o direito de acesso `RIGHT_DS_CONTROL_ACCESS48` onde o **ObjectType** é definido como `a05b8cc2-17bc-4802-a710-e7c15ab866a249`. Este GUID corresponde ao direito estendido **Certificate-AutoEnrollment**.
* **Um ACE concede a um princípio todos os ExtendedRights**. O ACE bruto habilita o direito de acesso `RIGHT_DS_CONTROL_ACCESS` onde o **ObjectType** é definido como `00000000-0000-0000-0000-000000000000`. Este GUID corresponde a **todos os direitos estendidos**.
* **Um ACE concede a um princípio FullControl/GenericAll**. O ACE bruto habilita o direito de acesso FullControl/GenericAll.

### Direitos de Inscrição da Enterprise CA

O **descritor de segurança** configurado na **Enterprise CA** define esses direitos e é **visível** no snap-in MMC da Autoridade de Certificação `certsrv.msc` clicando com o botão direito na CA → Propriedades → Segurança.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

Isso acaba configurando o valor de Segurança no registro **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`** no servidor CA. Encontramos vários servidores AD CS que concedem a usuários com poucos privilégios acesso remoto a essa chave via registro remoto:

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

Usuários com poucos privilégios também podem **enumerar isso via DCOM** usando a interface COM `ICertAdminD2` e o método `GetCASecurity`. No entanto, clientes Windows normais precisam instalar as Ferramentas de Administração de Servidor Remoto (RSAT) para usá-lo, pois a interface COM e quaisquer objetos COM que a implementam não estão presentes no Windows por padrão.

### Requisitos de Emissão

Outros requisitos podem estar em vigor para controlar quem pode obter um certificado.

#### Aprovação do Gerente

**A aprovação do gerente do certificado da CA** resulta na configuração do modelo de certificado definindo o bit `CT_FLAG_PEND_ALL_REQUESTS` (0x2) no atributo `msPKI-EnrollmentFlag` do objeto AD. Isso coloca todas as **solicitações de certificado** baseadas no modelo no **estado pendente** (visível na seção "Solicitações Pendentes" em `certsrv.msc`), o que requer que um gerente de certificado **aprove ou negue** a solicitação antes que o certificado seja emitido:

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### Agentes de Inscrição, Assinaturas Autorizadas e Políticas de Aplicação

**O número de assinaturas autorizadas** e a **Política de aplicação**. O primeiro controla o **número de assinaturas necessárias** no CSR para que a CA o aceite. O último define os **OIDs EKU que o certificado de assinatura do CSR deve ter**.

Um uso comum para essas configurações é para **agentes de inscrição**. Um agente de inscrição é um termo do AD CS dado a uma entidade que pode **solicitar certificados em nome de outro usuário**. Para fazer isso, a CA deve emitir ao agente de inscrição uma conta de certificado contendo pelo menos o **EKU de Agente de Solicitação de Certificado** (OID 1.3.6.1.4.1.311.20.2.1). Uma vez emitido, o agente de inscrição pode então **assinar CSRs e solicitar certificados em nome de outros usuários**. A CA **emitirá** o certificado do agente de inscrição como **outro usuário** apenas sob o seguinte conjunto não exaustivo de **condições** (
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## Referências

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
