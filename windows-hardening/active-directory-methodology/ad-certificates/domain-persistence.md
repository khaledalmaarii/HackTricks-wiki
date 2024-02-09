# Persistência de Domínio AD CS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Este é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Consulte para mais detalhes.

## Forjando Certificados com Certificados CA Roubados - DPERSIST1

Como você pode dizer que um certificado é um certificado CA?

Pode ser determinado que um certificado é um certificado CA se várias condições forem atendidas:

- O certificado é armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como um TPM/HSM se o sistema operacional o suportar.
- Os campos Emissor e Assunto do certificado correspondem ao nome distinto do CA.
- Uma extensão "Versão do CA" está presente exclusivamente nos certificados CA.
- O certificado não possui campos de Uso Estendido de Chave (EKU).

Para extrair a chave privada deste certificado, a ferramenta `certsrv.msc` no servidor CA é o método suportado via GUI integrada. No entanto, este certificado não difere dos outros armazenados no sistema; portanto, métodos como a técnica [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando o Certipy com o seguinte comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Após adquirir o certificado da CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
O usuário alvo da falsificação de certificado deve estar ativo e ser capaz de autenticar no Active Directory para o processo ter sucesso. Falsificar um certificado para contas especiais como krbtgt é ineficaz.
{% endhint %}

Este certificado falsificado será **válido** até a data de término especificada e enquanto o certificado da CA raiz for válido (geralmente de 5 a **10+ anos**). Também é válido para **máquinas**, então combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina de domínio** enquanto o certificado da CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados** pois a CA não tem conhecimento deles.

## Confiando em Certificados de CA Falsos - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **certificados de CA** em seu atributo `cacertificate`, que o Active Directory (AD) utiliza. O processo de verificação pelo **controlador de domínio** envolve verificar o objeto `NTAuthCertificates` em busca de uma entrada que corresponda à **CA especificada** no campo Emissor do **certificado** de autenticação. A autenticação prossegue se uma correspondência for encontrada.

Um certificado de CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que tenham controle sobre este objeto AD. Normalmente, apenas membros do grupo **Administrador da Empresa**, juntamente com **Administradores de Domínio** ou **Administradores** no **domínio raiz da floresta**, têm permissão para modificar este objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou utilizando a [**Ferramenta de Saúde de PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Essa capacidade é especialmente relevante quando usada em conjunto com um método previamente descrito envolvendo ForgeCert para gerar certificados dinamicamente.

## Configuração Maliciosa - DPERSIST3

As oportunidades de **persistência** por meio de **modificações de descritores de segurança dos componentes AD CS** são abundantes. Modificações descritas na seção "[Escalada de Domínio](domain-escalation.md)" podem ser implementadas de forma maliciosa por um atacante com acesso elevado. Isso inclui a adição de "direitos de controle" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis como:

- O objeto de computador AD do **servidor CA**
- O servidor RPC/DCOM do **servidor CA**
- Qualquer objeto ou contêiner AD descendente em **`CN=Serviços de Chave Pública,CN=Serviços,CN=Configuração,DC=<DOMÍNIO>,DC=<COM>`** (por exemplo, o contêiner de Modelos de Certificado, contêiner de Autoridades de Certificação, o objeto NTAuthCertificates, etc.)
- **Grupos AD com direitos delegados para controlar AD CS** por padrão ou pela organização (como o grupo Cert Publishers integrado e qualquer um de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que possui **permissões elevadas** no domínio, adicionando a permissão **`WriteOwner`** ao modelo de certificado padrão **`Usuário`**, sendo o principal para o direito o próprio atacante. Para explorar isso, o atacante primeiro mudaria a propriedade do modelo **`Usuário`** para si mesmo. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no modelo para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Nome Alternativo do Assunto na solicitação. Posteriormente, o atacante poderia **inscrever-se** usando o **modelo**, escolhendo um nome de **administrador de domínio** como nome alternativo, e utilizar o certificado adquirido para autenticação como o AD.
