# AD CS Account Persistence

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

**Este é um pequeno resumo dos capítulos de persistência de máquina da pesquisa incrível de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## **Entendendo o Roubo de Credenciais de Usuário Ativo com Certificados – PERSIST1**

Em um cenário onde um certificado que permite a autenticação de domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de **solicitar** e **roubar** esse certificado para **manter a persistência** em uma rede. Por padrão, o modelo `User` no Active Directory permite tais solicitações, embora às vezes possa estar desativado.

Usando uma ferramenta chamada [**Certify**](https://github.com/GhostPack/Certify), pode-se procurar por certificados válidos que habilitam acesso persistente:
```bash
Certify.exe find /clientauth
```
É destacado que o poder de um certificado reside em sua capacidade de **autenticar como o usuário** ao qual pertence, independentemente de quaisquer alterações de senha, desde que o certificado permaneça **válido**.

Os certificados podem ser solicitados através de uma interface gráfica usando `certmgr.msc` ou através da linha de comando com `certreq.exe`. Com **Certify**, o processo para solicitar um certificado é simplificado da seguinte forma:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Após a solicitação bem-sucedida, um certificado junto com sua chave privada é gerado no formato `.pem`. Para converter isso em um arquivo `.pfx`, que é utilizável em sistemas Windows, o seguinte comando é utilizado:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
O arquivo `.pfx` pode então ser enviado para um sistema alvo e usado com uma ferramenta chamada [**Rubeus**](https://github.com/GhostPack/Rubeus) para solicitar um Ticket Granting Ticket (TGT) para o usuário, estendendo o acesso do atacante enquanto o certificado for **válido** (tipicamente um ano):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Um aviso importante é compartilhado sobre como essa técnica, combinada com outro método descrito na seção **THEFT5**, permite que um atacante obtenha persistentemente o **NTLM hash** de uma conta sem interagir com o Local Security Authority Subsystem Service (LSASS) e a partir de um contexto não elevado, proporcionando um método mais furtivo para o roubo de credenciais a longo prazo.

## **Ganhando Persistência de Máquina com Certificados - PERSIST2**

Outro método envolve inscrever a conta de máquina de um sistema comprometido para um certificado, utilizando o modelo padrão `Machine`, que permite tais ações. Se um atacante obtiver privilégios elevados em um sistema, ele pode usar a conta **SYSTEM** para solicitar certificados, proporcionando uma forma de **persistência**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Este acesso permite que o atacante se autentique no **Kerberos** como a conta da máquina e utilize **S4U2Self** para obter tickets de serviço do Kerberos para qualquer serviço no host, concedendo efetivamente ao atacante acesso persistente à máquina.

## **Estendendo a Persistência Através da Renovação de Certificados - PERSIST3**

O método final discutido envolve aproveitar os **períodos de validade** e **renovação** dos modelos de certificado. Ao **renovar** um certificado antes de sua expiração, um atacante pode manter a autenticação no Active Directory sem a necessidade de novas inscrições de tickets, o que poderia deixar rastros no servidor da Autoridade Certificadora (CA).

Essa abordagem permite um método de **persistência estendida**, minimizando o risco de detecção através de interações reduzidas com o servidor CA e evitando a geração de artefatos que poderiam alertar os administradores sobre a intrusão.
