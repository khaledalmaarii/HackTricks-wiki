# Roubo de Certificados do AD CS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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
## Exportando Certificados Usando as Crypto APIs – THEFT1

A maneira mais fácil de extrair um certificado de usuário ou máquina e chave privada é através de uma **sessão de desktop interativa**. Se a **chave privada** for **exportável**, basta clicar com o botão direito do mouse no certificado em `certmgr.msc`, e ir para `Tarefas → Exportar`... para exportar um arquivo .pfx protegido por senha. \
Também é possível realizar isso **programaticamente**. Exemplos incluem o cmdlet `ExportPfxCertificate` do PowerShell ou [o projeto CertStealer C# de TheWover](https://github.com/TheWover/CertStealer).

Por baixo, esses métodos usam a **Microsoft CryptoAPI** (CAPI) ou a mais moderna Cryptography API: Next Generation (CNG) para interagir com o armazenamento de certificados. Essas APIs realizam vários serviços criptográficos necessários para o armazenamento e autenticação de certificados (entre outros usos).

Se a chave privada for não exportável, CAPI e CNG não permitirão a extração de certificados não exportáveis. Os comandos `crypto::capi` e `crypto::cng` do **Mimikatz** podem modificar o CAPI e o CNG para **permitir a exportação** de chaves privadas. `crypto::capi` **modifica** o **CAPI** no processo atual, enquanto `crypto::cng` requer **modificação** na memória do **lsass.exe**.

## Roubo de Certificado de Usuário via DPAPI – THEFT2

Mais informações sobre DPAPI em:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

O Windows **armazena chaves privadas de certificados usando DPAPI**. A Microsoft separa os locais de armazenamento para chaves privadas de usuário e máquina. Ao descriptografar manualmente os blobs DPAPI criptografados, um desenvolvedor precisa entender qual API de criptografia o sistema operacional usou, pois a estrutura do arquivo de chave privada difere entre as duas APIs. Quando se usa SharpDPAPI, ele automaticamente leva em conta essas diferenças de formato de arquivo.&#x20;

O Windows armazena mais **comumente certificados de usuários** no registro na chave `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, embora alguns certificados pessoais para usuários também sejam armazenados em `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Os locais associados à **chave privada do usuário** estão principalmente em `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para chaves **CAPI** e `%APPDATA%\Microsoft\Crypto\Keys\` para chaves **CNG**.

Para obter um certificado e sua chave privada associada, é necessário:

1. Identificar **qual certificado se deseja roubar** da loja de certificados do usuário e extrair o nome do armazenamento de chaves.
2. Encontrar a **chave-mestra DPAPI** necessária para descriptografar a chave privada associada.
3. Obter a chave-mestra DPAPI em texto claro e usá-la para **descriptografar a chave privada**.

Para **obter a chave-mestra DPAPI em texto claro**:
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar a descriptografia do arquivo masterkey e do arquivo de chave privada, o comando `certificates` do [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) pode ser usado com os argumentos `/pvk`, `/mkfile`, `/password`, ou `{GUID}:KEY` para descriptografar as chaves privadas e os certificados associados, gerando um arquivo de texto `.pem`.
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Roubo de Certificado de Máquina via DPAPI – THEFT3

O Windows armazena certificados de máquina na chave de registro `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e armazena chaves privadas em vários locais diferentes, dependendo da conta.\
Embora o SharpDPAPI pesquise todos esses locais, os resultados mais interessantes tendem a vir de `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG). Essas **chaves privadas** estão associadas ao **repositório de certificados da máquina** e o Windows as criptografa com as **chaves mestras DPAPI da máquina**.\
Não é possível descriptografar essas chaves usando a chave de backup DPAPI do domínio, mas sim **deve-se** usar o **segredo DPAPI\_SYSTEM LSA** no sistema, que é **acessível apenas pelo usuário SYSTEM**.&#x20;

Você pode fazer isso manualmente com o comando **`lsadump::secrets`** do **Mimikatz** e depois usar a chave extraída para **descriptografar as masterkeys da máquina**. \
Você também pode aplicar patch no CAPI/CNG como antes e usar o comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` do **Mimikatz**. \
O comando certificates do **SharpDPAPI** com a flag **`/machine`** (quando elevado) irá automaticamente **elevar** para **SYSTEM**, **despejar** o segredo **DPAPI\_SYSTEM** LSA, usar isso para **descriptografar** e encontrar masterkeys DPAPI da máquina, e usar os textos em claro das chaves como uma tabela de consulta para descriptografar quaisquer chaves privadas de certificados da máquina.

## Encontrando Arquivos de Certificado – THEFT4

Às vezes, **os certificados estão apenas no sistema de arquivos**, como em compartilhamentos de arquivos ou na pasta Downloads.\
Os tipos mais comuns de arquivos de certificado focados no Windows que vimos são **`.pfx`** e **`.p12`**, com **`.pkcs12`** e **`.pem`** aparecendo às vezes, mas menos frequentemente.\
Outras extensões de arquivo relacionadas a certificados interessantes são: **`.key`** (_chave privada_), **`.crt/.cer`** (_apenas certificado_), **`.csr`** (_Pedido de Assinatura de Certificado, não contém certificados ou chaves privadas_), **`.jks/.keystore/.keys`** (_Java Keystore. Pode conter certificados + chaves privadas usadas por aplicações Java_).

Para encontrar esses arquivos, basta procurar essas extensões usando o PowerShell ou o cmd.

Se você encontrar um arquivo de certificado **PKCS#12** e ele estiver **protegido por senha**, você pode extrair um hash usando [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) e **quebrar** a senha usando o JohnTheRipper.

## Roubo de Credenciais NTLM via PKINIT – THEFT5

> Para **suportar a autenticação NTLM** \[MS-NLMP] para aplicações que se conectam a serviços de rede que **não suportam autenticação Kerberos**, quando o PKCA é usado, o KDC retorna a função unidirecional (OWF) do **NTLM do usuário** no certificado de atributo de privilégio (PAC) **`PAC_CREDENTIAL_INFO`** buffer

Assim, se a conta se autenticar e obter um **TGT através do PKINIT**, há um "failsafe" embutido que permite ao host atual **obter nosso hash NTLM do TGT** para suportar a autenticação legada. Isso envolve **descriptografar** uma **estrutura `PAC_CREDENTIAL_DATA`** que é uma representação serializada em Representação de Dados de Rede (NDR) do NTLM em texto claro.

[**Kekeo**](https://github.com/gentilkiwi/kekeo) pode ser usado para solicitar um TGT com essas informações e recuperar o NTML do usuário.
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
A implementação do Kekeo também funcionará com certificados protegidos por smartcard que estejam conectados no momento, se você conseguir [**recuperar o pin**](https://github.com/CCob/PinSwipe)**.** Também será suportado no [**Rubeus**](https://github.com/GhostPack/Rubeus).

## Referências

* Todas as informações foram retiradas de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
