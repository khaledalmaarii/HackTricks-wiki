# macOS Gatekeeper / Quarentena / XProtect

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** é um recurso de segurança desenvolvido para sistemas operacionais Mac, projetado para garantir que os usuários **executem apenas software confiável** em seus sistemas. Funciona **validando software** que um usuário baixa e tenta abrir de **fontes externas à App Store**, como um aplicativo, um plug-in ou um pacote de instalação.

O mecanismo chave do Gatekeeper está em seu processo de **verificação**. Ele verifica se o software baixado é **assinado por um desenvolvedor reconhecido**, garantindo a autenticidade do software. Além disso, assegura se o software foi **notarizado pela Apple**, confirmando que está livre de conteúdo malicioso conhecido e que não foi adulterado após a notarização.

Adicionalmente, o Gatekeeper reforça o controle e a segurança do usuário ao **solicitar que os usuários aprovem a abertura** do software baixado pela primeira vez. Essa proteção ajuda a prevenir que os usuários executem inadvertidamente código executável potencialmente prejudicial que possam ter confundido com um arquivo de dados inofensivo.

### Assinaturas de Aplicativos

Assinaturas de aplicativos, também conhecidas como assinaturas de código, são um componente crítico da infraestrutura de segurança da Apple. São usadas para **verificar a identidade do autor do software** (o desenvolvedor) e para garantir que o código não foi adulterado desde a última assinatura.

Veja como funciona:

1. **Assinando o Aplicativo:** Quando um desenvolvedor está pronto para distribuir seu aplicativo, ele **assina o aplicativo usando uma chave privada**. Essa chave privada está associada a um **certificado que a Apple emite para o desenvolvedor** quando eles se inscrevem no Programa de Desenvolvedores da Apple. O processo de assinatura envolve a criação de um hash criptográfico de todas as partes do aplicativo e a criptografia desse hash com a chave privada do desenvolvedor.
2. **Distribuindo o Aplicativo:** O aplicativo assinado é então distribuído aos usuários junto com o certificado do desenvolvedor, que contém a chave pública correspondente.
3. **Verificando o Aplicativo:** Quando um usuário baixa e tenta executar o aplicativo, o sistema operacional Mac usa a chave pública do certificado do desenvolvedor para descriptografar o hash. Em seguida, recalcula o hash com base no estado atual do aplicativo e compara isso com o hash descriptografado. Se eles coincidirem, significa que **o aplicativo não foi modificado** desde que o desenvolvedor o assinou, e o sistema permite que o aplicativo seja executado.

Assinaturas de aplicativos são uma parte essencial da tecnologia Gatekeeper da Apple. Quando um usuário tenta **abrir um aplicativo baixado da internet**, o Gatekeeper verifica a assinatura do aplicativo. Se estiver assinado com um certificado emitido pela Apple para um desenvolvedor conhecido e o código não tiver sido adulterado, o Gatekeeper permite que o aplicativo seja executado. Caso contrário, ele bloqueia o aplicativo e alerta o usuário.

A partir do macOS Catalina, **o Gatekeeper também verifica se o aplicativo foi notarizado** pela Apple, adicionando uma camada extra de segurança. O processo de notarização verifica o aplicativo em busca de problemas de segurança conhecidos e código malicioso, e se essas verificações forem aprovadas, a Apple adiciona um ticket ao aplicativo que o Gatekeeper pode verificar.

#### Verificar Assinaturas

Ao verificar uma **amostra de malware**, você deve sempre **verificar a assinatura** do binário, pois o **desenvolvedor** que o assinou pode já estar **relacionado** com **malware.**
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

O processo de notarização da Apple serve como uma salvaguarda adicional para proteger os usuários de softwares potencialmente prejudiciais. Envolve o **desenvolvedor submeter sua aplicação para exame** pelo **Serviço de Notarização da Apple**, que não deve ser confundido com a Revisão de Aplicativos. Este serviço é um **sistema automatizado** que examina o software submetido em busca de **conteúdo malicioso** e quaisquer problemas potenciais com a assinatura de código.

Se o software **passar** nesta inspeção sem levantar preocupações, o Serviço de Notarização gera um ticket de notarização. O desenvolvedor deve então **anexar este ticket ao seu software**, um processo conhecido como 'stapling' (grampeamento). Além disso, o ticket de notarização também é publicado online, onde o Gatekeeper, a tecnologia de segurança da Apple, pode acessá-lo.

Na primeira instalação ou execução do software pelo usuário, a existência do ticket de notarização - seja ele grampeado ao executável ou encontrado online - **informa ao Gatekeeper que o software foi notarizado pela Apple**. Como resultado, o Gatekeeper exibe uma mensagem descritiva no diálogo de lançamento inicial, indicando que o software passou por verificações de conteúdo malicioso pela Apple. Esse processo, portanto, aumenta a confiança do usuário na segurança do software que instalam ou executam em seus sistemas.

### Enumerando o GateKeeper

O GateKeeper é tanto **vários componentes de segurança** que impedem a execução de aplicativos não confiáveis quanto **um dos componentes**.

É possível ver o **status** do GateKeeper com:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Observe que as verificações de assinatura do GateKeeper são realizadas apenas em **arquivos com o atributo de Quarentena**, não em todos os arquivos.
{% endhint %}

O GateKeeper verificará se, de acordo com as **preferências e a assinatura**, um binário pode ser executado:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

O banco de dados que mantém essa configuração está localizado em **`/var/db/SystemPolicy`**. Você pode verificar este banco de dados como root com:
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
Observe como a primeira regra terminou em "**App Store**" e a segunda em "**Developer ID**" e que na imagem anterior estava **habilitado para executar apps da App Store e desenvolvedores identificados**.\
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
Estes são hashes que vêm de **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** e **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Ou você poderia listar as informações anteriores com:
```bash
sudo spctl --list
```
As opções **`--master-disable`** e **`--global-disable`** do **`spctl`** irão **desativar** completamente essas verificações de assinatura:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando completamente habilitado, uma nova opção aparecerá:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

É possível **verificar se um App será permitido pelo GateKeeper** com:
```bash
spctl --assess -v /Applications/App.app
```
É possível adicionar novas regras no GateKeeper para permitir a execução de certos aplicativos com:
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

Ao **baixar** um aplicativo ou arquivo, **aplicativos** específicos do macOS, como navegadores da web ou clientes de e-mail, **anexam um atributo estendido de arquivo**, comumente conhecido como "**bandeira de quarentena**", ao arquivo baixado. Esse atributo atua como uma medida de segurança para **marcar o arquivo** como vindo de uma fonte não confiável (a internet) e potencialmente carregando riscos. No entanto, nem todos os aplicativos anexam esse atributo, por exemplo, softwares clientes de BitTorrent comuns geralmente contornam esse processo.

**A presença da bandeira de quarentena sinaliza o recurso de segurança Gatekeeper do macOS quando um usuário tenta executar o arquivo**.

No caso em que a **bandeira de quarentena não está presente** (como em arquivos baixados via alguns clientes BitTorrent), as **verificações do Gatekeeper podem não ser realizadas**. Assim, os usuários devem ter cautela ao abrir arquivos baixados de fontes menos seguras ou desconhecidas.

{% hint style="info" %}
**Verificar** a **validade** das assinaturas de código é um processo **intensivo de recursos** que inclui a geração de **hashes** criptográficos do código e todos os seus recursos empacotados. Além disso, verificar a validade do certificado envolve fazer uma **verificação online** nos servidores da Apple para ver se ele foi revogado após a emissão. Por essas razões, uma verificação completa de assinatura de código e notarização é **imprática de ser executada toda vez que um aplicativo é lançado**.

Portanto, essas verificações são **realizadas apenas ao executar aplicativos com o atributo em quarentena.**
{% endhint %}

{% hint style="warning" %}
Este atributo deve ser **definido pelo aplicativo que cria/baixa** o arquivo.

No entanto, arquivos que estão em sandbox terão esse atributo definido para cada arquivo que criarem. E aplicativos que não estão em sandbox podem definir eles mesmos, ou especificar a chave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) no **Info.plist**, o que fará com que o sistema defina o atributo estendido `com.apple.quarantine` nos arquivos criados,
{% endhint %}

É possível **verificar seu status e habilitar/desabilitar** (root necessário) com:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Você também pode **verificar se um arquivo tem o atributo estendido de quarentena** com:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Verifique o **valor** dos **atributos estendidos** e descubra o app que escreveu o atributo de quarentena com:
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
```markdown
De fato, um processo "pode definir flags de quarentena nos arquivos que cria" (eu tentei aplicar a flag USER_APPROVED em um arquivo criado, mas ela não foi aplicada):

<details>

<summary>Código Fonte para aplicar flags de quarentena</summary>
```
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

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

Informações de quarentena também são armazenadas em um banco de dados central gerenciado pelo LaunchServices em **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

A extensão do kernel está disponível apenas através do **cache do kernel no sistema**; no entanto, você _pode_ baixar o **Kit de Depuração do Kernel em https://developer.apple.com/**, que conterá uma versão simbolizada da extensão.

### XProtect

XProtect é um recurso **anti-malware** integrado no macOS. O XProtect **verifica qualquer aplicativo quando é lançado pela primeira vez ou modificado contra seu banco de dados** de malware conhecido e tipos de arquivos inseguros. Quando você baixa um arquivo por meio de certos aplicativos, como Safari, Mail ou Messages, o XProtect automaticamente escaneia o arquivo. Se ele corresponder a qualquer malware conhecido em seu banco de dados, o XProtect irá **impedir que o arquivo seja executado** e alertará você sobre a ameaça.

O banco de dados do XProtect é **atualizado regularmente** pela Apple com novas definições de malware, e essas atualizações são baixadas e instaladas automaticamente no seu Mac. Isso garante que o XProtect esteja sempre atualizado com as ameaças conhecidas mais recentes.

No entanto, vale ressaltar que o **XProtect não é uma solução antivírus completa**. Ele verifica apenas uma lista específica de ameaças conhecidas e não realiza varredura em acesso como a maioria dos softwares antivírus.

Você pode obter informações sobre a última atualização do XProtect executando:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

O XProtect está localizado em uma localização protegida pelo SIP em **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e dentro do pacote você pode encontrar informações que o XProtect utiliza:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que o código com esses cdhashes use privilégios legados.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins e extensões que não são permitidos carregar através do BundleID e TeamID ou indicando uma versão mínima.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regras Yara para detectar malware.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Banco de dados SQLite3 com hashes de aplicações bloqueadas e TeamIDs.

Note que existe outro App em **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionado ao XProtect que não está envolvido com o processo do Gatekeeper.

### Não é o Gatekeeper

{% hint style="danger" %}
Note que o Gatekeeper **não é executado todas as vezes** que você executa uma aplicação, apenas o _**AppleMobileFileIntegrity**_ (AMFI) irá **verificar assinaturas de código executável** quando você executar um app que já foi executado e verificado pelo Gatekeeper.
{% endhint %}

Portanto, anteriormente era possível executar um app para armazená-lo em cache com o Gatekeeper, depois **modificar arquivos não executáveis da aplicação** (como arquivos Electron asar ou NIB) e, se não houvesse outras proteções em vigor, a aplicação era **executada** com as adições **maliciosas**.

No entanto, agora isso não é possível porque o macOS **impede a modificação de arquivos** dentro dos pacotes de aplicações. Então, se você tentar o ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), você descobrirá que não é mais possível abusar dele porque depois de executar o app para armazená-lo em cache com o Gatekeeper, você não poderá modificar o pacote. E se você mudar, por exemplo, o nome do diretório Contents para NotCon (como indicado no exploit), e depois executar o binário principal do app para armazená-lo em cache com o Gatekeeper, isso acionará um erro e não será executado.

## Bypasses do Gatekeeper

Qualquer maneira de contornar o Gatekeeper (conseguir fazer o usuário baixar algo e executá-lo quando o Gatekeeper deveria proibir) é considerada uma vulnerabilidade no macOS. Estes são alguns CVEs atribuídos a técnicas que permitiram contornar o Gatekeeper no passado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Quando extraído pelo **Archive Utility**, caminhos de arquivo **maiores que 886** caracteres falhavam em herdar o atributo estendido com.apple.quarantine, tornando possível **burlar o Gatekeeper para esses arquivos**.

Confira o [**relatório original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para mais informações.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando uma aplicação é criada com o **Automator**, as informações sobre o que ela precisa executar estão dentro de `application.app/Contents/document.wflow` e não no executável. O executável é apenas um binário genérico do Automator chamado **Automator Application Stub**.

Portanto, você poderia fazer `application.app/Contents/MacOS/Automator\ Application\ Stub` **apontar com um link simbólico para outro Automator Application Stub dentro do sistema** e ele executará o que está dentro de `document.wflow` (seu script) **sem acionar o Gatekeeper** porque o executável real não tem o xattr de quarentena.&#x20;

Exemplo de localização esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Confira o [**relatório original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para mais informações.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Neste bypass, um arquivo zip foi criado com uma aplicação começando a comprimir a partir de `application.app/Contents` em vez de `application.app`. Portanto, o **atributo de quarentena** foi aplicado a todos os **arquivos de `application.app/Contents`** mas **não a `application.app`**, que é o que o Gatekeeper estava verificando, então o Gatekeeper foi contornado porque quando `application.app` foi acionado, **não tinha o atributo de quarentena**.
```bash
zip -r test.app/Contents test.zip
```
Confira o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para mais informações.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Mesmo que os componentes sejam diferentes, a exploração desta vulnerabilidade é muito semelhante à anterior. Neste caso, iremos gerar um Apple Archive a partir de **`application.app/Contents`** para que **`application.app` não receba o atributo de quarentena** quando descomprimido pelo **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Confira o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para mais informações.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

O ACL **`writeextattr`** pode ser usado para impedir que alguém escreva um atributo em um arquivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Além disso, o formato de arquivo **AppleDouble** copia um arquivo incluindo seus ACEs.

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) é possível ver que a representação textual do ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descomprimido. Então, se você comprimiu um aplicativo em um arquivo zip com o formato de arquivo **AppleDouble** com um ACL que impede que outros xattrs sejam escritos nele... o xattr de quarentena não foi definido na aplicação:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Confira o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para mais informações.

Note que isso também poderia ser explorado com AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Descobriu-se que o **Google Chrome não estava definindo o atributo de quarentena** em arquivos baixados devido a alguns problemas internos do macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Formatos de arquivo AppleDouble armazenam os atributos de um arquivo em um arquivo separado iniciado por `._`, isso ajuda a copiar atributos de arquivo **entre máquinas macOS**. No entanto, notou-se que após descomprimir um arquivo AppleDouble, o arquivo iniciado com `._` **não recebia o atributo de quarentena**.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Ser capaz de criar um arquivo que não tenha o atributo de quarentena definido, era **possível burlar o Gatekeeper.** O truque era **criar um arquivo de aplicação DMG** usando a convenção de nome AppleDouble (iniciá-lo com `._`) e criar um **arquivo visível como um link simbólico para este arquivo oculto** sem o atributo de quarentena.\
Quando o **arquivo dmg é executado**, como ele não possui um atributo de quarentena, ele **burlará o Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### Prevenir Quarantine xattr

Em um pacote ".app", se o xattr de quarentena não for adicionado a ele, ao executá-lo **o Gatekeeper não será acionado**.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
