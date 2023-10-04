# macOS Gatekeeper

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** é um recurso de segurança desenvolvido para sistemas operacionais Mac, projetado para garantir que os usuários **executem apenas software confiável** em seus sistemas. Ele funciona **validando o software** que um usuário baixa e tenta abrir de **fontes fora da App Store**, como um aplicativo, um plug-in ou um pacote de instalação.

O mecanismo chave do Gatekeeper reside em seu processo de **verificação**. Ele verifica se o software baixado está **assinado por um desenvolvedor reconhecido**, garantindo a autenticidade do software. Além disso, ele verifica se o software foi **notarizado pela Apple**, confirmando que está livre de conteúdo malicioso conhecido e não foi adulterado após a notarização.

Além disso, o Gatekeeper reforça o controle e a segurança do usuário ao **solicitar a aprovação do usuário para abrir** o software baixado pela primeira vez. Essa salvaguarda ajuda a evitar que os usuários executem inadvertidamente código executável potencialmente prejudicial que possam ter confundido com um arquivo de dados inofensivo.

### Assinaturas de Aplicativos

As assinaturas de aplicativos, também conhecidas como assinaturas de código, são um componente crítico da infraestrutura de segurança da Apple. Elas são usadas para **verificar a identidade do autor do software** (o desenvolvedor) e garantir que o código não tenha sido adulterado desde a última assinatura.

Veja como funciona:

1. **Assinando o Aplicativo:** Quando um desenvolvedor está pronto para distribuir seu aplicativo, ele **o assina usando uma chave privada**. Essa chave privada está associada a um **certificado que a Apple emite para o desenvolvedor** quando ele se inscreve no Programa de Desenvolvedor da Apple. O processo de assinatura envolve a criação de um hash criptográfico de todas as partes do aplicativo e a criptografia desse hash com a chave privada do desenvolvedor.
2. **Distribuindo o Aplicativo:** O aplicativo assinado é então distribuído para os usuários juntamente com o certificado do desenvolvedor, que contém a chave pública correspondente.
3. **Verificando o Aplicativo:** Quando um usuário faz o download e tenta executar o aplicativo, o sistema operacional Mac usa a chave pública do certificado do desenvolvedor para descriptografar o hash. Em seguida, ele recalcula o hash com base no estado atual do aplicativo e compara isso com o hash descriptografado. Se eles coincidirem, significa que **o aplicativo não foi modificado** desde que o desenvolvedor o assinou, e o sistema permite a execução do aplicativo.

As assinaturas de aplicativos são uma parte essencial da tecnologia Gatekeeper da Apple. Quando um usuário tenta **abrir um aplicativo baixado da internet**, o Gatekeeper verifica a assinatura do aplicativo. Se estiver assinado com um certificado emitido pela Apple para um desenvolvedor conhecido e o código não tiver sido adulterado, o Gatekeeper permite a execução do aplicativo. Caso contrário, ele bloqueia o aplicativo e alerta o usuário.

A partir do macOS Catalina, o Gatekeeper também verifica se o aplicativo foi **notarizado** pela Apple, adicionando uma camada extra de segurança. O processo de notarização verifica o aplicativo em busca de problemas de segurança conhecidos e código malicioso, e se essas verificações forem aprovadas, a Apple adiciona um ticket ao aplicativo que o Gatekeeper pode verificar.

#### Verificar Assinaturas

Ao verificar alguma **amostra de malware**, você sempre deve **verificar a assinatura** do binário, pois o **desenvolvedor** que o assinou pode estar **relacionado** a **malware**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarização

O processo de notarização da Apple serve como uma salvaguarda adicional para proteger os usuários de software potencialmente prejudicial. Ele envolve o **desenvolvedor submetendo sua aplicação para exame** pelo **Serviço de Notarização da Apple**, que não deve ser confundido com a Revisão de Aplicativos. Esse serviço é um **sistema automatizado** que examina o software enviado em busca de **conteúdo malicioso** e possíveis problemas com a assinatura de código.

Se o software **passar** por essa inspeção sem levantar preocupações, o Serviço de Notarização gera um ticket de notarização. O desenvolvedor é então obrigado a **anexar esse ticket ao seu software**, um processo conhecido como 'grampeamento'. Além disso, o ticket de notarização também é publicado online, onde o Gatekeeper, a tecnologia de segurança da Apple, pode acessá-lo.

Na primeira instalação ou execução do software pelo usuário, a existência do ticket de notarização - seja anexado ao executável ou encontrado online - **informa ao Gatekeeper que o software foi notarizado pela Apple**. Como resultado, o Gatekeeper exibe uma mensagem descritiva no diálogo de lançamento inicial, indicando que o software passou por verificações de conteúdo malicioso pela Apple. Esse processo, portanto, aumenta a confiança do usuário na segurança do software que eles instalam ou executam em seus sistemas.

### Enumerando o GateKeeper

O GateKeeper é tanto **vários componentes de segurança** que impedem a execução de aplicativos não confiáveis quanto **um dos componentes**.

É possível verificar o **status** do GateKeeper com:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Observe que as verificações de assinatura do GateKeeper são realizadas apenas em **arquivos com o atributo de Quarentena**, não em todos os arquivos.
{% endhint %}

O GateKeeper verificará se, de acordo com as **preferências e a assinatura**, um binário pode ser executado:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

O banco de dados que mantém essa configuração está localizado em **`/var/db/SystemPolicy`**. Você pode verificar esse banco de dados como root usando:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Observe como a primeira regra terminou em "**App Store**" e a segunda em "**Developer ID**" e que na imagem anterior estava **habilitada para executar aplicativos da App Store e desenvolvedores identificados**.\
Se você **modificar** essa configuração para App Store, as regras de "**Notarized Developer ID" desaparecerão**.

Existem também milhares de regras do **tipo GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Estes são os hashes que vêm de **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** e **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

As opções **`--master-disable`** e **`--global-disable`** do **`spctl`** irão **desativar completamente** essas verificações de assinatura:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando totalmente habilitado, uma nova opção aparecerá:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

É possível **verificar se um aplicativo será permitido pelo GateKeeper** com:
```bash
spctl --assess -v /Applications/App.app
```
É possível adicionar novas regras no GateKeeper para permitir a execução de determinados aplicativos com:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### Arquivos em Quarentena

Ao **baixar** um aplicativo ou arquivo, aplicativos específicos do macOS, como navegadores da web ou clientes de e-mail, **anexam um atributo de arquivo estendido**, comumente conhecido como "**sinalizador de quarentena**", ao arquivo baixado. Esse atributo atua como uma medida de segurança para **marcar o arquivo** como proveniente de uma fonte não confiável (a internet) e potencialmente portador de riscos. No entanto, nem todos os aplicativos anexam esse atributo, por exemplo, software comum de cliente BitTorrent geralmente ignora esse processo.

**A presença de um sinalizador de quarentena sinaliza o recurso de segurança Gatekeeper do macOS quando um usuário tenta executar o arquivo**.

No caso em que o **sinalizador de quarentena não está presente** (como nos arquivos baixados por alguns clientes BitTorrent), as **verificações do Gatekeeper podem não ser realizadas**. Portanto, os usuários devem ter cuidado ao abrir arquivos baixados de fontes menos seguras ou desconhecidas.

{% hint style="info" %}
**Verificar** a **validade** das assinaturas de código é um processo **intensivo em recursos** que inclui a geração de **hashes** criptográficos do código e de todos os recursos agrupados. Além disso, verificar a validade do certificado envolve fazer uma **verificação online** nos servidores da Apple para ver se ele foi revogado após ter sido emitido. Por esses motivos, uma verificação completa de assinatura de código e notarização é **impraticável de ser executada toda vez que um aplicativo é iniciado**.

Portanto, essas verificações são **executadas apenas ao executar aplicativos com o atributo de quarentena**.
{% endhint %}

{% hint style="warning" %}
Esse atributo deve ser **definido pelo aplicativo que cria/baixa** o arquivo.

No entanto, arquivos que estão em sandbox terão esse atributo definido para todos os arquivos que eles criam. E aplicativos não em sandbox podem defini-lo por si próprios ou especificar a chave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) no arquivo **Info.plist**, o que fará com que o sistema defina o atributo estendido `com.apple.quarantine` nos arquivos criados.
{% endhint %}

É possível **verificar seu status e habilitar/desabilitar** (é necessário ter privilégios de root) com:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Você também pode **verificar se um arquivo possui o atributo de quarentena estendida** com:
```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```
Verifique o **valor** dos **atributos** **estendidos** e descubra o aplicativo que escreveu o atributo de quarentena com:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
E **remova** esse atributo com:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
E encontre todos os arquivos em quarentena com:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

As informações de quarentena também são armazenadas em um banco de dados central gerenciado pelo LaunchServices em **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

### XProtect

XProtect é um recurso embutido de **anti-malware** no macOS. O XProtect **verifica qualquer aplicativo quando ele é executado pela primeira vez ou modificado em relação ao seu banco de dados** de malwares conhecidos e tipos de arquivo inseguros. Quando você baixa um arquivo por meio de determinados aplicativos, como Safari, Mail ou Messages, o XProtect verifica automaticamente o arquivo. Se ele corresponder a algum malware conhecido em seu banco de dados, o XProtect **impedirá a execução do arquivo** e o alertará sobre a ameaça.

O banco de dados do XProtect é **atualizado regularmente** pela Apple com novas definições de malware, e essas atualizações são baixadas e instaladas automaticamente em seu Mac. Isso garante que o XProtect esteja sempre atualizado com as últimas ameaças conhecidas.

No entanto, vale ressaltar que o **XProtect não é uma solução antivírus completa**. Ele verifica apenas uma lista específica de ameaças conhecidas e não realiza varreduras de acesso como a maioria dos softwares antivírus.

Você pode obter informações sobre a última atualização do XProtect executando:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect está localizado em uma localização protegida pelo SIP em **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e dentro do pacote você pode encontrar as informações que o XProtect usa:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que o código com esses cdhashes use privilégios legados.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins e extensões que são proibidos de carregar via BundleID e TeamID ou indicando uma versão mínima.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regras Yara para detectar malware.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Banco de dados SQLite3 com hashes de aplicativos bloqueados e TeamIDs.

Observe que há outro aplicativo em **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionado ao XProtect que não está envolvido quando um aplicativo é executado.

## Bypasses do Gatekeeper

Qualquer forma de contornar o Gatekeeper (conseguir fazer o usuário baixar algo e executá-lo quando o Gatekeeper deveria proibir) é considerada uma vulnerabilidade no macOS. Estes são alguns CVEs atribuídos a técnicas que permitiram contornar o Gatekeeper no passado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Quando extraído pelo **Archive Utility**, arquivos com **caminhos mais longos que 886** caracteres falhariam em herdar o atributo estendido com.apple.quarantine, tornando possível **contornar o Gatekeeper para esses arquivos**.

Verifique o [**relatório original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para mais informações.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando um aplicativo é criado com o **Automator**, as informações sobre o que ele precisa executar estão dentro de `application.app/Contents/document.wflow`, não no executável. O executável é apenas um binário genérico do Automator chamado **Automator Application Stub**.

Portanto, você poderia fazer com que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apontasse com um link simbólico para outro Automator Application Stub dentro do sistema** e ele executaria o que está dentro de `document.wflow` (seu script) **sem acionar o Gatekeeper** porque o executável real não possui o atributo de quarentena.

Exemplo de localização esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Verifique o [**relatório original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para mais informações.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Neste contorno, um arquivo zip foi criado com um aplicativo começando a compactar a partir de `application.app/Contents` em vez de `application.app`. Portanto, o **atributo de quarentena** foi aplicado a todos os **arquivos de `application.app/Contents`**, mas **não a `application.app`**, que era o que o Gatekeeper estava verificando, então o Gatekeeper foi contornado porque quando `application.app` foi acionado, **ele não tinha o atributo de quarentena**.
```bash
zip -r test.app/Contents test.zip
```
Verifique o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para obter mais informações.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Mesmo que os componentes sejam diferentes, a exploração dessa vulnerabilidade é muito semelhante à anterior. Neste caso, iremos gerar um Apple Archive a partir de **`application.app/Contents`**, para que **`application.app` não receba o atributo de quarentena** ao ser descompactado pelo **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Verifique o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para obter mais informações.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

O ACL **`writeextattr`** pode ser usado para impedir que alguém escreva um atributo em um arquivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Além disso, o formato de arquivo **AppleDouble** copia um arquivo incluindo suas ACEs.

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), é possível ver que a representação de texto do ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descompactado. Portanto, se você comprimir um aplicativo em um arquivo zip com o formato de arquivo **AppleDouble** com um ACL que impede que outros xattrs sejam gravados nele... o xattr de quarentena não será definido no aplicativo:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file shuold be without a wuarantine xattr
```
Verifique o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obter mais informações.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
