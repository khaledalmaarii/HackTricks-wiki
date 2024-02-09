# Roubo de Certificado AD CS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Este é um pequeno resumo dos capítulos de Roubo da incrível pesquisa de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## O que posso fazer com um certificado

Antes de verificar como roubar os certificados, aqui estão algumas informações sobre como descobrir para que o certificado é útil:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportando Certificados Usando as APIs de Criptografia – ROUBO1

Em uma **sessão de desktop interativa**, extrair um certificado de usuário ou de máquina, juntamente com a chave privada, pode ser facilmente feito, especialmente se a **chave privada for exportável**. Isso pode ser alcançado navegando até o certificado no `certmgr.msc`, clicando com o botão direito sobre ele e selecionando `Todas as Tarefas → Exportar` para gerar um arquivo .pfx protegido por senha.

Para uma abordagem **programática**, ferramentas como o cmdlet PowerShell `ExportPfxCertificate` ou projetos como [O projeto CertStealer C# de TheWover](https://github.com/TheWover/CertStealer) estão disponíveis. Estes utilizam o **Microsoft CryptoAPI** (CAPI) ou a API de Criptografia: Próxima Geração (CNG) para interagir com o repositório de certificados. Essas APIs fornecem uma variedade de serviços criptográficos, incluindo aqueles necessários para armazenamento e autenticação de certificados.

No entanto, se uma chave privada for definida como não exportável, tanto CAPI quanto CNG normalmente bloquearão a extração desses certificados. Para contornar essa restrição, ferramentas como o **Mimikatz** podem ser empregadas. Mimikatz oferece os comandos `crypto::capi` e `crypto::cng` para modificar as respectivas APIs, permitindo a exportação de chaves privadas. Especificamente, `crypto::capi` modifica o CAPI dentro do processo atual, enquanto `crypto::cng` direciona a memória do **lsass.exe** para modificação.

## Roubo de Certificado de Usuário via DPAPI – ROUBO2

Mais informações sobre DPAPI em:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

No Windows, as **chaves privadas de certificados são protegidas pelo DPAPI**. É crucial reconhecer que os **locais de armazenamento para chaves privadas de usuário e de máquina** são distintos, e as estruturas de arquivos variam dependendo da API criptográfica utilizada pelo sistema operacional. **SharpDPAPI** é uma ferramenta que pode navegar automaticamente por essas diferenças ao descriptografar os blobs do DPAPI.

Os **certificados de usuário** são predominantemente armazenados no registro em `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, mas alguns também podem ser encontrados no diretório `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. As **chaves privadas correspondentes** para esses certificados são tipicamente armazenadas em `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para chaves **CAPI** e `%APPDATA%\Microsoft\Crypto\Keys\` para chaves **CNG**.

Para **extrair um certificado e sua chave privada associada**, o processo envolve:

1. **Selecionar o certificado alvo** da loja do usuário e recuperar o nome da loja de chaves.
2. **Localizar a masterkey DPAPI necessária** para descriptografar a chave privada correspondente.
3. **Descriptografar a chave privada** utilizando a masterkey DPAPI em texto simples.

Para **adquirir a masterkey DPAPI em texto simples**, podem ser utilizadas as seguintes abordagens:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar a descriptografia de arquivos de chave mestra e arquivos de chave privada, o comando `certificates` do [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) é benéfico. Ele aceita `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` como argumentos para descriptografar as chaves privadas e certificados vinculados, gerando posteriormente um arquivo `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Roubo de Certificado de Máquina via DPAPI - THEFT3

Os certificados de máquina armazenados pelo Windows no registro em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e as chaves privadas associadas localizadas em `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (para CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (para CNG) são criptografados usando as chaves mestras DPAPI da máquina. Essas chaves não podem ser descriptografadas com a chave de backup DPAPI do domínio; em vez disso, é necessário o **segredo LSA DPAPI_SYSTEM**, ao qual apenas o usuário SYSTEM pode acessar.

A descriptografia manual pode ser realizada executando o comando `lsadump::secrets` no **Mimikatz** para extrair o segredo LSA DPAPI_SYSTEM e, posteriormente, usando essa chave para descriptografar as chaves mestras da máquina. Alternativamente, o comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` do Mimikatz pode ser usado após a correção do CAPI/CNG conforme descrito anteriormente.

O **SharpDPAPI** oferece uma abordagem mais automatizada com seu comando de certificados. Quando a flag `/machine` é usada com permissões elevadas, ele escala para SYSTEM, despeja o segredo LSA DPAPI_SYSTEM, o utiliza para descriptografar as chaves mestras DPAPI da máquina e, em seguida, emprega essas chaves em texto simples como uma tabela de pesquisa para descriptografar quaisquer chaves privadas de certificados de máquina.


## Localizando Arquivos de Certificado - THEFT4

Os certificados às vezes são encontrados diretamente no sistema de arquivos, como em compartilhamentos de arquivos ou na pasta Downloads. Os tipos de arquivos de certificado mais comumente encontrados direcionados a ambientes Windows são arquivos `.pfx` e `.p12`. Embora com menos frequência, arquivos com extensões `.pkcs12` e `.pem` também aparecem. Extensões de arquivo adicionais relacionadas a certificados que merecem destaque incluem:
- `.key` para chaves privadas,
- `.crt`/`.cer` para apenas certificados,
- `.csr` para Solicitações de Assinatura de Certificado, que não contêm certificados ou chaves privadas,
- `.jks`/`.keystore`/`.keys` para Java Keystores, que podem conter certificados juntamente com chaves privadas utilizadas por aplicativos Java.

Esses arquivos podem ser pesquisados usando o PowerShell ou o prompt de comando procurando pelas extensões mencionadas.

Nos casos em que um arquivo de certificado PKCS#12 é encontrado e está protegido por uma senha, a extração de um hash é possível por meio do uso do `pfx2john.py`, disponível em [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Posteriormente, o JohnTheRipper pode ser utilizado para tentar quebrar a senha.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Roubo de Credenciais NTLM via PKINIT - THEFT5

O conteúdo fornecido explica um método para roubo de credenciais NTLM via PKINIT, especificamente através do método de roubo rotulado como THEFT5. Aqui está uma reexplicação em voz passiva, com o conteúdo anonimizado e resumido quando aplicável:

Para suportar a autenticação NTLM [MS-NLMP] para aplicativos que não facilitam a autenticação Kerberos, o KDC é projetado para retornar a função unidirecional NTLM do usuário (OWF) dentro do certificado de atributo de privilégio (PAC), especificamente no buffer `PAC_CREDENTIAL_INFO`, quando o PKCA é utilizado. Consequentemente, caso uma conta autentique e obtenha um Ticket-Granting Ticket (TGT) via PKINIT, um mecanismo é fornecido de forma inerente que permite ao host atual extrair o hash NTLM do TGT para manter os protocolos de autenticação legados. Esse processo envolve a descriptografia da estrutura `PAC_CREDENTIAL_DATA`, que é essencialmente uma representação serializada NDR do texto simples NTLM.

A ferramenta **Kekeo**, acessível em [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), é mencionada como capaz de solicitar um TGT contendo esses dados específicos, facilitando assim a recuperação do NTLM do usuário. O comando utilizado para esse fim é o seguinte:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Além disso, é observado que o Kekeo pode processar certificados protegidos por smartcard, desde que o PIN possa ser recuperado, com referência feita a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). A mesma capacidade é indicada como suportada pelo **Rubeus**, disponível em [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Essa explicação encapsula o processo e as ferramentas envolvidas no roubo de credenciais NTLM via PKINIT, focando na recuperação de hashes NTLM através do TGT obtido usando PKINIT, e nos utilitários que facilitam esse processo.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
