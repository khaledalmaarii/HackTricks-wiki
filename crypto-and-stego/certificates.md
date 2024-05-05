# Certificados

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir facilmente e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## O que é um Certificado

Um **certificado de chave pública** é um ID digital usado em criptografia para provar que alguém possui uma chave pública. Ele inclui os detalhes da chave, a identidade do proprietário (o sujeito) e uma assinatura digital de uma autoridade confiável (o emissor). Se o software confiar no emissor e a assinatura for válida, é possível uma comunicação segura com o proprietário da chave.

Os certificados são principalmente emitidos por [autoridades de certificação](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) em uma configuração de [infraestrutura de chave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Outro método é a [rede de confiança](https://en.wikipedia.org/wiki/Web\_of\_trust), onde os usuários verificam diretamente as chaves uns dos outros. O formato comum para certificados é o [X.509](https://en.wikipedia.org/wiki/X.509), que pode ser adaptado para necessidades específicas, conforme descrito no RFC 5280.

## Campos Comuns do x509

### **Campos Comuns em Certificados x509**

Nos certificados x509, vários **campos** desempenham papéis críticos para garantir a validade e a segurança do certificado. Aqui está uma explicação desses campos:

* O **Número da Versão** indica a versão do formato x509.
* O **Número de Série** identifica unicamente o certificado dentro do sistema de uma Autoridade de Certificação (CA), principalmente para rastreamento de revogação.
* O campo **Sujeito** representa o proprietário do certificado, que pode ser uma máquina, um indivíduo ou uma organização. Ele inclui identificação detalhada, como:
* **Nome Comum (CN)**: Domínios cobertos pelo certificado.
* **País (C)**, **Localidade (L)**, **Estado ou Província (ST, S ou P)**, **Organização (O)** e **Unidade Organizacional (OU)** fornecem detalhes geográficos e organizacionais.
* O **Nome Distinto (DN)** encapsula a identificação completa do sujeito.
* O **Emissor** detalha quem verificou e assinou o certificado, incluindo subcampos semelhantes ao Sujeito para a CA.
* O **Período de Validade** é marcado pelos horários **Não Antes** e **Não Depois**, garantindo que o certificado não seja usado antes ou depois de uma determinada data.
* A seção **Chave Pública**, crucial para a segurança do certificado, especifica o algoritmo, tamanho e outros detalhes técnicos da chave pública.
* As **extensões x509v3** aprimoram a funcionalidade do certificado, especificando **Uso da Chave**, **Uso Estendido da Chave**, **Nome Alternativo do Sujeito** e outras propriedades para ajustar a aplicação do certificado.

#### **Uso da Chave e Extensões**

* **Uso da Chave** identifica aplicações criptográficas da chave pública, como assinatura digital ou cifragem de chave.
* **Uso Estendido da Chave** restringe ainda mais os casos de uso do certificado, por exemplo, para autenticação de servidor TLS.
* **Nome Alternativo do Sujeito** e **Restrição Básica** definem nomes de host adicionais cobertos pelo certificado e se é um certificado de CA ou de entidade final, respectivamente.
* Identificadores como **Identificador de Chave do Sujeito** e **Identificador de Chave da Autoridade** garantem a singularidade e rastreabilidade das chaves.
* **Acesso à Informação da Autoridade** e **Pontos de Distribuição de Lista de Revogação (CRL)** fornecem caminhos para verificar a CA emissora e verificar o status de revogação do certificado.
* **CT Precertificate SCTs** oferecem registros de transparência, cruciais para a confiança pública no certificado.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Diferença entre Pontos de Distribuição OCSP e CRL**

**OCSP** (**RFC 2560**) envolve um cliente e um respondedor trabalhando juntos para verificar se um certificado de chave pública digital foi revogado, sem precisar baixar o **CRL** completo. Este método é mais eficiente do que o tradicional **CRL**, que fornece uma lista de números de série de certificados revogados, mas requer o download de um arquivo potencialmente grande. Os CRLs podem incluir até 512 entradas. Mais detalhes estão disponíveis [aqui](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **O que é Transparência de Certificado**

A Transparência de Certificado ajuda a combater ameaças relacionadas a certificados, garantindo que a emissão e a existência de certificados SSL sejam visíveis para os proprietários de domínios, CAs e usuários. Seus objetivos são:

* Impedir que CAs emitam certificados SSL para um domínio sem o conhecimento do proprietário do domínio.
* Estabelecer um sistema de auditoria aberto para rastrear certificados emitidos erroneamente ou maliciosamente.
* Proteger os usuários contra certificados fraudulentos.

#### **Logs de Certificado**

Os logs de certificado são registros publicamente auditáveis e somente de adição de certificados, mantidos por serviços de rede. Esses logs fornecem provas criptográficas para fins de auditoria. Tanto as autoridades de emissão quanto o público podem enviar certificados para esses logs ou consultá-los para verificação. Embora o número exato de servidores de log não seja fixo, espera-se que seja inferior a mil globalmente. Esses servidores podem ser gerenciados de forma independente por CAs, ISPs ou qualquer entidade interessada.

#### **Consulta**

Para explorar os logs de Transparência de Certificado para qualquer domínio, visite [https://crt.sh/](https://crt.sh).

Diferentes formatos existem para armazenar certificados, cada um com seus próprios casos de uso e compatibilidade. Este resumo abrange os principais formatos e fornece orientações sobre a conversão entre eles.

## **Formatos**

### **Formato PEM**

* Formato mais amplamente utilizado para certificados.
* Requer arquivos separados para certificados e chaves privadas, codificados em Base64 ASCII.
* Extensões comuns: .cer, .crt, .pem, .key.
* Principalmente usado por servidores Apache e similares.

### **Formato DER**

* Um formato binário de certificados.
* Não possui as declarações "BEGIN/END CERTIFICATE" encontradas em arquivos PEM.
* Extensões comuns: .cer, .der.
* Frequentemente usado com plataformas Java.

### **Formato P7B/PKCS#7**

* Armazenado em Base64 ASCII, com extensões .p7b ou .p7c.
* Contém apenas certificados e certificados de cadeia, excluindo a chave privada.
* Suportado pelo Microsoft Windows e Java Tomcat.

### **Formato PFX/P12/PKCS#12**

* Um formato binário que encapsula certificados de servidor, certificados intermediários e chaves privadas em um único arquivo.
* Extensões: .pfx, .p12.
* Principalmente usado no Windows para importação e exportação de certificados.

### **Conversão de Formatos**

As **conversões PEM** são essenciais para compatibilidade:

* **x509 para PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM para DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER para PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM para P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 para PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Conversões PFX** são cruciais para gerenciar certificados no Windows:

* **PFX para PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX para PKCS#8** envolve dois passos:
1. Converter PFX para PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Converter PEM para PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B para PFX** também requer dois comandos:
1. Converter P7B para CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Converter CER e Chave Privada para PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir facilmente e **automatizar fluxos de trabalho** com as ferramentas comunitárias **mais avançadas do mundo**.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
