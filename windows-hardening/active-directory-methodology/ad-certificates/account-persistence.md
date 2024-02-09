# Persistência de Conta AD CS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Este é um pequeno resumo dos capítulos de persistência de máquina da incrível pesquisa de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Compreendendo o Roubo de Credenciais de Usuário Ativo com Certificados – PERSIST1**

Em um cenário onde um certificado que permite autenticação de domínio pode ser solicitado por um usuário, um atacante tem a oportunidade de **solicitar** e **roubar** este certificado para **manter a persistência** em uma rede. Por padrão, o modelo `Usuário` no Active Directory permite tais solicitações, embora às vezes possa estar desativado.

Usando uma ferramenta chamada [**Certify**](https://github.com/GhostPack/Certify), é possível procurar certificados válidos que permitem acesso persistente:
```bash
Certify.exe find /clientauth
```
É destacado que o poder de um certificado reside em sua capacidade de **autenticar como o usuário** a quem pertence, independentemente de quaisquer alterações de senha, desde que o certificado permaneça **válido**.

Os certificados podem ser solicitados por meio de uma interface gráfica usando `certmgr.msc` ou através da linha de comando com `certreq.exe`. Com o **Certify**, o processo para solicitar um certificado é simplificado da seguinte forma:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Após uma solicitação bem-sucedida, um certificado juntamente com sua chave privada é gerado no formato `.pem`. Para converter isso em um arquivo `.pfx`, que é utilizável em sistemas Windows, o seguinte comando é utilizado:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
O arquivo `.pfx` pode então ser carregado em um sistema alvo e usado com uma ferramenta chamada [**Rubeus**](https://github.com/GhostPack/Rubeus) para solicitar um Ticket Granting Ticket (TGT) para o usuário, estendendo o acesso do atacante pelo tempo em que o certificado estiver **válido** (geralmente um ano):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
## **Obtenção de Persistência na Máquina com Certificados - PERSIST2**

Outro método envolve inscrever a conta da máquina de um sistema comprometido para um certificado, utilizando o modelo padrão `Machine` que permite tais ações. Se um atacante obtém privilégios elevados em um sistema, eles podem usar a conta **SYSTEM** para solicitar certificados, fornecendo uma forma de **persistência**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Este acesso permite que o atacante se autentique no **Kerberos** como a conta da máquina e utilize o **S4U2Self** para obter tickets de serviço do Kerberos para qualquer serviço no host, concedendo efetivamente ao atacante acesso persistente à máquina.

## **Estendendo a Persistência Através da Renovação de Certificados - PERSIST3**

O método final discutido envolve alavancar os **períodos de validade** e **renovação** dos modelos de certificados. Ao **renovar** um certificado antes de sua expiração, um atacante pode manter a autenticação no Active Directory sem a necessidade de inscrições adicionais de tickets, o que poderia deixar rastros no servidor de Autoridade de Certificação (CA).

Esta abordagem permite um método de **persistência estendida**, minimizando o risco de detecção através de menos interações com o servidor CA e evitando a geração de artefatos que poderiam alertar os administradores sobre a intrusão.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
