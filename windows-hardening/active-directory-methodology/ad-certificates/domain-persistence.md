# AD CS Domain Persistence

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

**Este é um resumo das técnicas de persistência de domínio compartilhadas em [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Confira para mais detalhes.

## Forjando Certificados com Certificados CA Roubados - DPERSIST1

Como você pode saber se um certificado é um certificado CA?

Pode-se determinar que um certificado é um certificado CA se várias condições forem atendidas:

- O certificado está armazenado no servidor CA, com sua chave privada protegida pelo DPAPI da máquina, ou por hardware como um TPM/HSM, se o sistema operacional suportar.
- Os campos Issuer e Subject do certificado correspondem ao nome distinto da CA.
- Uma extensão "CA Version" está presente exclusivamente nos certificados CA.
- O certificado não possui campos de Uso de Chave Estendida (EKU).

Para extrair a chave privada deste certificado, a ferramenta `certsrv.msc` no servidor CA é o método suportado via a GUI integrada. No entanto, este certificado não difere de outros armazenados dentro do sistema; assim, métodos como a [técnica THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) podem ser aplicados para extração.

O certificado e a chave privada também podem ser obtidos usando Certipy com o seguinte comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Ao adquirir o certificado CA e sua chave privada no formato `.pfx`, ferramentas como [ForgeCert](https://github.com/GhostPack/ForgeCert) podem ser utilizadas para gerar certificados válidos:
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
O usuário alvo para a falsificação de certificados deve estar ativo e ser capaz de autenticar no Active Directory para que o processo tenha sucesso. Falsificar um certificado para contas especiais como krbtgt é ineficaz.
{% endhint %}

Este certificado falsificado será **válido** até a data de término especificada e **enquanto o certificado CA raiz for válido** (geralmente de 5 a **10+ anos**). Ele também é válido para **máquinas**, então, combinado com **S4U2Self**, um atacante pode **manter persistência em qualquer máquina do domínio** enquanto o certificado CA for válido.\
Além disso, os **certificados gerados** com este método **não podem ser revogados**, pois a CA não está ciente deles.

## Confiando em Certificados CA Maliciosos - DPERSIST2

O objeto `NTAuthCertificates` é definido para conter um ou mais **certificados CA** dentro de seu atributo `cacertificate`, que o Active Directory (AD) utiliza. O processo de verificação pelo **controlador de domínio** envolve verificar o objeto `NTAuthCertificates` em busca de uma entrada correspondente à **CA especificada** no campo Emissor do **certificado** autenticador. A autenticação prossegue se uma correspondência for encontrada.

Um certificado CA autoassinado pode ser adicionado ao objeto `NTAuthCertificates` por um atacante, desde que ele tenha controle sobre este objeto AD. Normalmente, apenas membros do grupo **Enterprise Admin**, juntamente com **Domain Admins** ou **Administrators** no **domínio raiz da floresta**, têm permissão para modificar este objeto. Eles podem editar o objeto `NTAuthCertificates` usando `certutil.exe` com o comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou empregando a [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Essa capacidade é especialmente relevante quando usada em conjunto com um método previamente descrito envolvendo ForgeCert para gerar certificados dinamicamente.

## Configuração Maliciosa - DPERSIST3

As oportunidades para **persistência** através de **modificações de descritores de segurança dos componentes AD CS** são abundantes. As modificações descritas na seção "[Domain Escalation](domain-escalation.md)" podem ser implementadas maliciosamente por um atacante com acesso elevado. Isso inclui a adição de "direitos de controle" (por exemplo, WriteOwner/WriteDACL/etc.) a componentes sensíveis, como:

- O objeto de computador AD do **servidor CA**
- O **servidor RPC/DCOM do servidor CA**
- Qualquer **objeto ou contêiner AD descendente** em **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (por exemplo, o contêiner de Modelos de Certificado, contêiner de Autoridades de Certificação, o objeto NTAuthCertificates, etc.)
- **Grupos AD com direitos delegados para controlar AD CS** por padrão ou pela organização (como o grupo Cert Publishers embutido e qualquer um de seus membros)

Um exemplo de implementação maliciosa envolveria um atacante, que possui **permissões elevadas** no domínio, adicionando a permissão **`WriteOwner`** ao modelo de certificado **`User`** padrão, com o atacante sendo o principal para o direito. Para explorar isso, o atacante primeiro mudaria a propriedade do modelo **`User`** para si mesmo. Em seguida, o **`mspki-certificate-name-flag`** seria definido como **1** no modelo para habilitar **`ENROLLEE_SUPPLIES_SUBJECT`**, permitindo que um usuário forneça um Nome Alternativo de Assunto na solicitação. Subsequentemente, o atacante poderia **se inscrever** usando o **modelo**, escolhendo um nome de **administrador de domínio** como um nome alternativo, e utilizar o certificado adquirido para autenticação como o DA.

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
