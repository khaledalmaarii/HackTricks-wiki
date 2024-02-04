# Certificados

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## O que é um Certificado

Na criptografia, um **certificado de chave pública**, também conhecido como **certificado digital** ou **certificado de identidade**, é um documento eletrônico usado para provar a propriedade de uma chave pública. O certificado inclui informações sobre a chave, informações sobre a identidade de seu proprietário (chamado de sujeito) e a assinatura digital de uma entidade que verificou o conteúdo do certificado (chamado de emissor). Se a assinatura for válida e o software que examina o certificado confiar no emissor, ele pode usar essa chave para se comunicar de forma segura com o sujeito do certificado.

Em um esquema típico de [infraestrutura de chave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI), o emissor do certificado é uma [autoridade de certificação](https://en.wikipedia.org/wiki/Certificate\_authority) (CA), geralmente uma empresa que cobra dos clientes para emitir certificados para eles. Em contraste, em um esquema de [rede de confiança](https://en.wikipedia.org/wiki/Web\_of\_trust), os indivíduos assinam diretamente as chaves uns dos outros, em um formato que desempenha uma função semelhante a um certificado de chave pública.

O formato mais comum para certificados de chave pública é definido por [X.509](https://en.wikipedia.org/wiki/X.509). Como o X.509 é muito geral, o formato é ainda mais restrito por perfis definidos para determinados casos de uso, como [Infraestrutura de Chave Pública (X.509)](https://en.wikipedia.org/wiki/PKIX) conforme definido no RFC 5280.

## Campos Comuns x509

- **Número da Versão:** Versão do formato x509.
- **Número de Série**: Usado para identificar unicamente o certificado nos sistemas de uma CA. Em particular, isso é usado para rastrear informações de revogação.
- **Sujeito**: A entidade a qual o certificado pertence: uma máquina, um indivíduo ou uma organização.
- **Nome Comum**: Domínios afetados pelo certificado. Pode ser 1 ou mais e pode conter curingas.
- **País (C)**: País
- **Nome Distinto (DN)**: O sujeito completo: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
- **Localidade (L)**: Local
- **Organização (O)**: Nome da organização
- **Unidade Organizacional (OU)**: Divisão de uma organização (como "Recursos Humanos").
- **Estado ou Província (ST, S ou P)**: Lista de nomes de estado ou província
- **Emissor**: A entidade que verificou as informações e assinou o certificado.
- **Nome Comum (CN)**: Nome da autoridade de certificação
- **País (C)**: País da autoridade de certificação
- **Nome Distinto (DN)**: Nome distinto da autoridade de certificação
- **Localidade (L)**: Local onde a organização pode ser encontrada.
- **Organização (O)**: Nome da organização
- **Unidade Organizacional (OU)**: Divisão de uma organização (como "Recursos Humanos").
- **Não Antes**: A data e hora mais cedo em que o certificado é válido. Geralmente definido algumas horas ou dias antes do momento em que o certificado foi emitido, para evitar problemas de [diferença de horário](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network).
- **Não Depois**: A data e hora após as quais o certificado não é mais válido.
- **Chave Pública**: Uma chave pública pertencente ao sujeito do certificado. (Esta é uma das partes principais, pois é isso que é assinado pela CA)
- **Algoritmo de Chave Pública**: Algoritmo usado para gerar a chave pública. Como RSA.
- **Curva da Chave Pública**: A curva usada pelo algoritmo de chave pública de curva elíptica (se aplicável). Como nistp521.
- **Expoente da Chave Pública**: Expoente usado para derivar a chave pública (se aplicável). Como 65537.
- **Tamanho da Chave Pública**: O tamanho do espaço da chave pública em bits. Como 2048.
- **Algoritmo de Assinatura**: O algoritmo usado para assinar o certificado de chave pública.
- **Assinatura**: Uma assinatura do corpo do certificado pela chave privada do emissor.
- **Extensões x509v3**
- **Uso da Chave**: Os usos criptográficos válidos da chave pública do certificado. Os valores comuns incluem validação de assinatura digital, cifragem de chave e assinatura de certificado.
- Em um certificado Web, isso aparecerá como uma _extensão X509v3_ e terá o valor `Assinatura Digital`
- **Uso Estendido da Chave**: As aplicações nas quais o certificado pode ser usado. Os valores comuns incluem autenticação de servidor TLS, proteção de e-mail e assinatura de código.
- Em um certificado Web, isso aparecerá como uma _extensão X509v3_ e terá o valor `Autenticação de Servidor Web TLS`
- **Nome Alternativo do Sujeito:** Permite aos usuários especificar **nomes de host adicionais** para um único **certificado SSL**. O uso da extensão SAN é uma prática padrão para certificados SSL e está a caminho de substituir o uso do **nome** comum.
- **Restrição Básica:** Esta extensão descreve se o certificado é um certificado de CA ou um certificado de entidade final. Um certificado de CA é algo que assina certificados de outros e um certificado de entidade final é o certificado usado em uma página da web, por exemplo (a última parte da cadeia).
- **Identificador de Chave do Sujeito** (SKI): Esta extensão declara um **identificador único para a chave pública** no certificado. É necessário em todos os certificados de CA. As CAs propagam seu próprio SKI para a extensão de Identificador de Chave do Emissor (AKI) nos certificados emitidos. É o hash da chave pública do sujeito.
- **Identificador de Chave da Autoridade**: Contém um identificador de chave que é derivado da chave pública no certificado do emissor. É o hash da chave pública do emissor.
- **Acesso à Informação da Autoridade** (AIA): Esta extensão contém no máximo dois tipos de informações:
- Informações sobre **como obter o emissor deste certificado** (método de acesso do emissor da CA)
- Endereço do **respondedor OCSP de onde a revogação deste certificado** pode ser verificada (método de acesso OCSP).
- **Pontos de Distribuição de CRL**: Esta extensão identifica a localização da CRL da qual a revogação deste certificado pode ser verificada. A aplicação que processa o certificado pode obter a localização da CRL desta extensão, baixar a CRL e então verificar a revogação deste certificado.
- **CT Precertificate SCTs**: Logs de Transparência de Certificado referentes ao certificado

### Diferença entre OCSP e Pontos de Distribuição de CRL

**OCSP** (RFC 2560) é um protocolo padrão que consiste em um **cliente OCSP e um respondente OCSP**. Este protocolo **determina o status de revogação de um determinado certificado de chave pública digital** **sem** ter que **baixar** a **CRL inteira**.\
**CRL** é o **método tradicional** de verificação da validade do certificado. Uma **CRL fornece uma lista de números de série de certificados** que foram revogados ou não são mais válidos. As CRLs permitem que o verificador verifique o status de revogação do certificado apresentado enquanto o verifica. As CRLs são limitadas a 512 entradas.\
De [aqui](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### O que é Transparência de Certificado

A Transparência de Certificado visa remediar ameaças baseadas em certificados, **tornando a emissão e a existência de certificados SSL abertas à escrutínio pelos proprietários de domínios, CAs e usuários de domínios**. Especificamente, a Transparência de Certificado tem três objetivos principais:

* Tornar impossível (ou pelo menos muito difícil) para uma CA **emitir um certificado SSL para um domínio sem que o certificado seja visível para o proprietário** desse domínio.
* Fornecer um **sistema de auditoria e monitoramento aberto que permite a qualquer proprietário de domínio ou CA determinar se os certificados foram emitidos por engano ou maliciosamente**.
* **Proteger os usuários** (tanto quanto possível) de serem enganados por certificados que foram emitidos por engano ou maliciosamente.

#### **Logs de Certificado**

Os logs de certificado são serviços de rede simples que mantêm **registros de certificados criptograficamente assegurados, publicamente auditáveis e somente para adição**. **Qualquer pessoa pode enviar certificados para um log**, embora as autoridades de certificação provavelmente sejam os principais remetentes. Da mesma forma, qualquer pessoa pode consultar um log para obter uma prova criptográfica, que pode ser usada para verificar se o log está se comportando corretamente ou verificar se um determinado certificado foi registrado. O número de servidores de log não precisa ser grande (digamos, muito menos de mil em todo o mundo), e cada um pode ser operado independentemente por uma CA, um ISP ou qualquer outra parte interessada.

#### Consulta

Você pode consultar os logs de Transparência de Certificado de qualquer domínio em [https://crt.sh/](https://crt.sh).

## Formatos

Existem diferentes formatos que podem ser usados para armazenar um certificado.

#### **Formato PEM**

- É o formato mais comum usado para certificados
- A maioria dos servidores (Ex: Apache) espera que os certificados e a chave privada estejam em arquivos separados\
- Geralmente são arquivos ASCII codificados em Base64\
- As extensões usadas para certificados PEM são .cer, .crt, .pem, .key\
- O Apache e servidores similares usam certificados no formato PEM

#### **Formato DER**

- O formato DER é a forma binária do certificado
- Todos os tipos de certificados e chaves privadas podem ser codificados no formato DER
- Certificados formatados em DER não contêm as declarações "INÍCIO CERTIFICADO/FIM CERTIFICADO"
- Certificados formatados em DER usam mais frequentemente as extensões ‘.cer’ e '.der'
- DER é tipicamente usado em Plataformas Java

#### **Formato P7B/PKCS#7**

- O formato PKCS#7 ou P7B é armazenado em formato ASCII Base64 e tem uma extensão de arquivo .p7b ou .p7c
- Um arquivo P7B contém apenas certificados e certificados de cadeia (CAs intermediárias), não a chave privada
- As plataformas mais comuns que suportam arquivos P7B são Microsoft Windows e Java Tomcat

#### **Formato PFX/P12/PKCS#12**

- O formato PKCS#12 ou PFX/P12 é um formato binário para armazenar o certificado do servidor, certificados intermediários e a chave privada em um arquivo criptografável
- Esses arquivos geralmente têm extensões como .pfx e .p12
- Eles são tipicamente usados em máquinas Windows para importar e exportar certificados e chaves privadas

### Conversões de Formatos

**Converter x509 para PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Converter PEM para DER**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**Converter DER para PEM**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Converter PEM para P7B**

**Nota:** O formato PKCS#7 ou P7B é armazenado em formato Base64 ASCII e tem uma extensão de arquivo .p7b ou .p7c. Um arquivo P7B contém apenas certificados e certificados de cadeia (CAs intermediários), não a chave privada. As plataformas mais comuns que suportam arquivos P7B são o Microsoft Windows e o Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Converter PKCS7 para PEM**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Converter pfx para PEM**

**Nota:** O formato PKCS#12 ou PFX é um formato binário para armazenar o certificado do servidor, certificados intermediários e a chave privada em um arquivo criptografável. Arquivos PFX geralmente têm extensões como .pfx e .p12. Arquivos PFX são tipicamente usados em máquinas Windows para importar e exportar certificados e chaves privadas.
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**Converter PFX para PKCS#8**\
**Nota:** Isso requer 2 comandos

**1- Converter PFX para PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- Converter PEM para PKCS8**
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**Converter P7B para PFX**\
**Nota:** Isso requer 2 comandos

1- **Converter P7B para CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- Converter CER e Chave Privada para PFX**
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias **mais avançadas do mundo**.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud). 

</details>
