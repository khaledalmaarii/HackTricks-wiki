# AD CS Certificate Theft

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

**Este é um pequeno resumo dos capítulos de Roubo da incrível pesquisa de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## O que posso fazer com um certificado

Antes de verificar como roubar os certificados, aqui você tem algumas informações sobre como descobrir para que o certificado é útil:
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
## Exportando Certificados Usando as APIs Crypto – THEFT1

Em uma **sessão de desktop interativa**, extrair um certificado de usuário ou máquina, junto com a chave privada, pode ser feito facilmente, particularmente se a **chave privada for exportável**. Isso pode ser alcançado navegando até o certificado em `certmgr.msc`, clicando com o botão direito sobre ele e selecionando `All Tasks → Export` para gerar um arquivo .pfx protegido por senha.

Para uma **abordagem programática**, ferramentas como o cmdlet PowerShell `ExportPfxCertificate` ou projetos como o [projeto CertStealer C# de TheWover](https://github.com/TheWover/CertStealer) estão disponíveis. Estas utilizam a **Microsoft CryptoAPI** (CAPI) ou a Cryptography API: Next Generation (CNG) para interagir com o armazenamento de certificados. Essas APIs fornecem uma gama de serviços criptográficos, incluindo aqueles necessários para armazenamento e autenticação de certificados.

No entanto, se uma chave privada for definida como não exportável, tanto CAPI quanto CNG normalmente bloquearão a extração de tais certificados. Para contornar essa restrição, ferramentas como **Mimikatz** podem ser empregadas. Mimikatz oferece comandos `crypto::capi` e `crypto::cng` para corrigir as respectivas APIs, permitindo a exportação de chaves privadas. Especificamente, `crypto::capi` corrige o CAPI dentro do processo atual, enquanto `crypto::cng` mira a memória de **lsass.exe** para correção.

## Roubo de Certificado de Usuário via DPAPI – THEFT2

Mais informações sobre DPAPI em:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

No Windows, **as chaves privadas de certificados são protegidas pelo DPAPI**. É crucial reconhecer que os **locais de armazenamento para chaves privadas de usuário e máquina** são distintos, e as estruturas de arquivos variam dependendo da API criptográfica utilizada pelo sistema operacional. **SharpDPAPI** é uma ferramenta que pode navegar automaticamente por essas diferenças ao descriptografar os blobs do DPAPI.

**Certificados de usuário** estão predominantemente armazenados no registro sob `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, mas alguns também podem ser encontrados no diretório `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. As correspondentes **chaves privadas** para esses certificados são tipicamente armazenadas em `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para chaves **CAPI** e `%APPDATA%\Microsoft\Crypto\Keys\` para chaves **CNG**.

Para **extrair um certificado e sua chave privada associada**, o processo envolve:

1. **Selecionar o certificado alvo** do armazenamento do usuário e recuperar seu nome de armazenamento de chave.
2. **Localizar a masterkey DPAPI necessária** para descriptografar a chave privada correspondente.
3. **Descriptografar a chave privada** utilizando a masterkey DPAPI em texto simples.

Para **adquirir a masterkey DPAPI em texto simples**, as seguintes abordagens podem ser usadas:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar a descriptografia de arquivos masterkey e arquivos de chave privada, o comando `certificates` do [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) se mostra benéfico. Ele aceita `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` como argumentos para descriptografar as chaves privadas e os certificados vinculados, gerando posteriormente um arquivo `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Roubo de Certificados de Máquina via DPAPI – THEFT3

Os certificados de máquina armazenados pelo Windows no registro em `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e as chaves privadas associadas localizadas em `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (para CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (para CNG) são criptografados usando as chaves mestres DPAPI da máquina. Essas chaves não podem ser descriptografadas com a chave de backup DPAPI do domínio; em vez disso, o **segredo LSA DPAPI_SYSTEM**, que apenas o usuário SYSTEM pode acessar, é necessário.

A descriptografia manual pode ser realizada executando o comando `lsadump::secrets` no **Mimikatz** para extrair o segredo LSA DPAPI_SYSTEM e, em seguida, usando essa chave para descriptografar as chaves mestres da máquina. Alternativamente, o comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` do Mimikatz pode ser usado após a correção do CAPI/CNG, conforme descrito anteriormente.

**SharpDPAPI** oferece uma abordagem mais automatizada com seu comando de certificados. Quando a flag `/machine` é usada com permissões elevadas, ela se eleva para SYSTEM, despeja o segredo LSA DPAPI_SYSTEM, usa-o para descriptografar as chaves mestres DPAPI da máquina e, em seguida, emprega essas chaves em texto claro como uma tabela de consulta para descriptografar quaisquer chaves privadas de certificados de máquina.

## Encontrando Arquivos de Certificado – THEFT4

Os certificados às vezes são encontrados diretamente no sistema de arquivos, como em compartilhamentos de arquivos ou na pasta Downloads. Os tipos de arquivos de certificado mais comumente encontrados direcionados a ambientes Windows são arquivos `.pfx` e `.p12`. Embora menos frequentemente, arquivos com extensões `.pkcs12` e `.pem` também aparecem. Outras extensões de arquivo relacionadas a certificados que merecem destaque incluem:
- `.key` para chaves privadas,
- `.crt`/`.cer` para certificados apenas,
- `.csr` para Solicitações de Assinatura de Certificado, que não contêm certificados ou chaves privadas,
- `.jks`/`.keystore`/`.keys` para Java Keystores, que podem conter certificados junto com chaves privadas utilizadas por aplicações Java.

Esses arquivos podem ser pesquisados usando PowerShell ou o prompt de comando, procurando pelas extensões mencionadas.

Nos casos em que um arquivo de certificado PKCS#12 é encontrado e está protegido por uma senha, a extração de um hash é possível através do uso de `pfx2john.py`, disponível em [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Subsequentemente, o JohnTheRipper pode ser empregado para tentar quebrar a senha.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

O conteúdo dado explica um método para roubo de credenciais NTLM via PKINIT, especificamente através do método de roubo rotulado como THEFT5. Aqui está uma reexplicação na voz passiva, com o conteúdo anonimizado e resumido onde aplicável:

Para suportar a autenticação NTLM [MS-NLMP] para aplicações que não facilitam a autenticação Kerberos, o KDC é projetado para retornar a função unidirecional (OWF) NTLM do usuário dentro do certificado de atributo de privilégio (PAC), especificamente no buffer `PAC_CREDENTIAL_INFO`, quando o PKCA é utilizado. Consequentemente, se uma conta autenticar e garantir um Ticket-Granting Ticket (TGT) via PKINIT, um mecanismo é inerentemente fornecido que permite ao host atual extrair o hash NTLM do TGT para manter os protocolos de autenticação legados. Este processo envolve a descriptografia da estrutura `PAC_CREDENTIAL_DATA`, que é essencialmente uma representação serializada NDR do NTLM em texto simples.

A utilidade **Kekeo**, acessível em [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), é mencionada como capaz de solicitar um TGT contendo esses dados específicos, facilitando assim a recuperação do NTLM do usuário. O comando utilizado para esse propósito é o seguinte:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Além disso, observa-se que o Kekeo pode processar certificados protegidos por smartcard, desde que o pin possa ser recuperado, com referência a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). A mesma capacidade é indicada como suportada pelo **Rubeus**, disponível em [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Esta explicação encapsula o processo e as ferramentas envolvidas na roubo de credenciais NTLM via PKINIT, focando na recuperação de hashes NTLM através do TGT obtido usando PKINIT, e as utilidades que facilitam esse processo.

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
