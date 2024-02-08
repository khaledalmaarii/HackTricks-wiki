# Certificados AD

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Introdução

### Componentes de um Certificado

- O **Assunto** do certificado denota seu proprietário.
- Uma **Chave Pública** é emparelhada com uma chave privada para vincular o certificado ao seu legítimo proprietário.
- O **Período de Validade**, definido pelas datas **NotBefore** e **NotAfter**, marca a duração efetiva do certificado.
- Um **Número de Série** único, fornecido pela Autoridade de Certificação (CA), identifica cada certificado.
- O **Emissor** refere-se à CA que emitiu o certificado.
- **SubjectAlternativeName** permite nomes adicionais para o assunto, aumentando a flexibilidade de identificação.
- **Restrições Básicas** identificam se o certificado é para uma CA ou uma entidade final e definem restrições de uso.
- **Usos Estendidos de Chave (EKUs)** delineiam os propósitos específicos do certificado, como assinatura de código ou criptografia de e-mail, por meio de Identificadores de Objetos (OIDs).
- O **Algoritmo de Assinatura** especifica o método de assinatura do certificado.
- A **Assinatura**, criada com a chave privada do emissor, garante a autenticidade do certificado.

### Considerações Especiais

- **Nomes Alternativos do Assunto (SANs)** expandem a aplicabilidade de um certificado para múltiplas identidades, crucial para servidores com vários domínios. Processos seguros de emissão são vitais para evitar riscos de impersonação por parte de atacantes que manipulam a especificação SAN.

### Autoridades de Certificação (CAs) no Active Directory (AD)

O AD CS reconhece certificados de CA em um floresta AD por meio de contêineres designados, cada um desempenhando funções únicas:

- O contêiner **Certification Authorities** mantém certificados de CA raiz confiáveis.
- O contêiner **Enrolment Services** detalha CAs empresariais e seus modelos de certificado.
- O objeto **NTAuthCertificates** inclui certificados de CA autorizados para autenticação AD.
- O contêiner **AIA (Authority Information Access)** facilita a validação da cadeia de certificados com certificados intermediários e cruzados.

### Aquisição de Certificados: Fluxo de Solicitação de Certificado do Cliente

1. O processo de solicitação começa com os clientes encontrando uma CA empresarial.
2. Um CSR é criado, contendo uma chave pública e outros detalhes, após a geração de um par de chaves pública-privada.
3. A CA avalia o CSR em relação aos modelos de certificado disponíveis, emitindo o certificado com base nas permissões do modelo.
4. Após a aprovação, a CA assina o certificado com sua chave privada e o retorna ao cliente.

### Modelos de Certificado

Definidos dentro do AD, esses modelos delineiam as configurações e permissões para emissão de certificados, incluindo EKUs permitidos e direitos de inscrição ou modificação, essenciais para gerenciar o acesso aos serviços de certificado.

## Inscrição de Certificado

O processo de inscrição para certificados é iniciado por um administrador que **cria um modelo de certificado**, que é então **publicado** por uma Autoridade de Certificação Empresarial (CA). Isso torna o modelo disponível para inscrição de clientes, um passo alcançado adicionando o nome do modelo ao campo `certificatetemplates` de um objeto do Active Directory.

Para que um cliente solicite um certificado, os **direitos de inscrição** devem ser concedidos. Esses direitos são definidos por descritores de segurança no modelo de certificado e na própria CA empresarial. Permissões devem ser concedidas em ambos os locais para que uma solicitação seja bem-sucedida.

### Direitos de Inscrição de Modelo

Esses direitos são especificados por Entradas de Controle de Acesso (ACEs), detalhando permissões como:
- Direitos de **Certificate-Enrollment** e **Certificate-AutoEnrollment**, cada um associado a GUIDs específicos.
- **ExtendedRights**, permitindo todas as permissões estendidas.
- **FullControl/GenericAll**, fornecendo controle total sobre o modelo.

### Direitos de Inscrição da CA Empresarial

Os direitos da CA são delineados em seu descritor de segurança, acessível por meio do console de gerenciamento da Autoridade de Certificação. Algumas configurações até permitem que usuários com baixos privilégios acessem remotamente, o que poderia ser uma preocupação de segurança.

### Controles de Emissão Adicionais

Certos controles podem ser aplicados, como:
- **Aprovação do Gerente**: Coloca solicitações em um estado pendente até serem aprovadas por um gerente de certificados.
- **Agentes de Inscrição e Assinaturas Autorizadas**: Especificam o número de assinaturas necessárias em um CSR e as Políticas de Aplicação OIDs necessárias.

### Métodos para Solicitar Certificados

Certificados podem ser solicitados por meio de:
1. **Protocolo de Inscrição de Certificado do Cliente Windows** (MS-WCCE), usando interfaces DCOM.
2. **Protocolo Remoto ICertPassage** (MS-ICPR), por meio de pipes nomeados ou TCP/IP.
3. A **interface web de inscrição de certificado**, com a função de Inscrição Web da Autoridade de Certificação instalada.
4. O **Serviço de Inscrição de Certificado** (CES), em conjunto com o serviço de Política de Inscrição de Certificado (CEP).
5. O **Serviço de Inscrição de Dispositivos de Rede** (NDES) para dispositivos de rede, usando o Protocolo Simples de Inscrição de Certificado (SCEP).

Usuários do Windows também podem solicitar certificados por meio da GUI (`certmgr.msc` ou `certlm.msc`) ou ferramentas de linha de comando (`certreq.exe` ou comando `Get-Certificate` do PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticação de Certificado

O Active Directory (AD) suporta autenticação de certificado, utilizando principalmente os protocolos **Kerberos** e **Secure Channel (Schannel)**.

### Processo de Autenticação Kerberos

No processo de autenticação Kerberos, a solicitação de um Ticket Granting Ticket (TGT) de um usuário é assinada usando a **chave privada** do certificado do usuário. Esta solicitação passa por várias validações pelo controlador de domínio, incluindo a **validade**, **caminho** e **status de revogação** do certificado. As validações também incluem verificar se o certificado vem de uma fonte confiável e confirmar a presença do emissor na loja de certificados **NTAUTH**. Validações bem-sucedidas resultam na emissão de um TGT. O objeto **`NTAuthCertificates`** no AD, encontrado em:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
é fundamental para estabelecer confiança para autenticação de certificados.

### Autenticação do Canal Seguro (Schannel)

O Schannel facilita conexões seguras TLS/SSL, onde durante um handshake, o cliente apresenta um certificado que, se validado com sucesso, autoriza o acesso. O mapeamento de um certificado para uma conta AD pode envolver a função **S4U2Self** do Kerberos ou o **Nome Alternativo do Assunto (SAN)** do certificado, entre outros métodos.

### Enumeração de Serviços de Certificado AD

Os serviços de certificado do AD podem ser enumerados por meio de consultas LDAP, revelando informações sobre **Autoridades de Certificação Empresariais (CAs)** e suas configurações. Isso é acessível por qualquer usuário autenticado no domínio sem privilégios especiais. Ferramentas como **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** são usadas para enumeração e avaliação de vulnerabilidades em ambientes AD CS.

Comandos para usar essas ferramentas incluem:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referências

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
