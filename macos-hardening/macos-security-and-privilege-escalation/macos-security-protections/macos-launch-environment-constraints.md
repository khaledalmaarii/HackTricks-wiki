# Restrições de Inicialização/Ambiente do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Informações Básicas

As restrições de inicialização no macOS foram introduzidas para aprimorar a segurança, **regulando como, por quem e de onde um processo pode ser iniciado**. Iniciadas no macOS Ventura, elas fornecem um framework que categoriza **cada binário do sistema em categorias de restrição distintas**, definidas dentro do **cache de confiança**, uma lista que contém binários do sistema e seus respectivos hashes. Essas restrições se estendem a todos os binários executáveis ​​do sistema, envolvendo um conjunto de **regras** que delineiam os requisitos para **iniciar um determinado binário**. As regras abrangem restrições próprias que um binário deve satisfazer, restrições dos processos pai que devem ser atendidas pelo processo pai e restrições responsáveis que devem ser seguidas por outras entidades relevantes.

O mecanismo se estende a aplicativos de terceiros por meio de **Restrições de Ambiente**, a partir do macOS Sonoma, permitindo que os desenvolvedores protejam seus aplicativos especificando um **conjunto de chaves e valores para restrições de ambiente**.

Você define **restrições de ambiente de inicialização e biblioteca** em dicionários de restrição que você salva em **arquivos de lista de propriedades `launchd`**, ou em **arquivos de lista de propriedades separados** que você usa na assinatura de código.

Existem 4 tipos de restrições:

* **Restrições Próprias**: Restrições aplicadas ao binário **em execução**.
* **Processo Pai**: Restrições aplicadas ao **processo pai** (por exemplo, **`launchd`** executando um serviço XP).
* **Restrições Responsáveis**: Restrições aplicadas ao **processo que chama o serviço** em uma comunicação XPC.
* **Restrições de Carregamento de Biblioteca**: Use restrições de carregamento de biblioteca para descrever seletivamente o código que pode ser carregado.

Portanto, quando um processo tenta iniciar outro processo - chamando `execve(_:_:_:)` ou `posix_spawn(_:_:_:_:_:_:)` - o sistema operacional verifica se o **arquivo executável** satisfaz sua **própria restrição**. Ele também verifica se o **executável do processo pai** satisfaz a **restrição do pai do executável**, e se o **executável do processo responsável** satisfaz a **restrição do processo responsável** do executável. Se alguma dessas restrições de inicialização não for satisfeita, o sistema operacional não executa o programa.

Se ao carregar uma biblioteca qualquer parte da **restrição da biblioteca não for verdadeira**, seu processo **não carrega** a biblioteca.

## Categorias LC

Um LC é composto por **fatos** e **operações lógicas** (e, ou...) que combinam fatos.

Os [**fatos que um LC pode usar são documentados**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Por exemplo:

* is-init-proc: Um valor booleano que indica se o executável deve ser o processo de inicialização do sistema operacional (`launchd`).
* is-sip-protected: Um valor booleano que indica se o executável deve ser um arquivo protegido pelo Sistema de Proteção de Integridade (SIP).
* `on-authorized-authapfs-volume:` Um valor booleano que indica se o sistema operacional carregou o executável de um volume APFS autorizado e autenticado.
* `on-authorized-authapfs-volume`: Um valor booleano que indica se o sistema operacional carregou o executável de um volume APFS autorizado e autenticado.
* Volume Cryptexes
* `on-system-volume:` Um valor booleano que indica se o sistema operacional carregou o executável do volume do sistema atualmente inicializado.
* Dentro de /System...
* ...

Quando um binário da Apple é assinado, ele é **atribuído a uma categoria LC** dentro do **cache de confiança**.

* As **categorias LC do iOS 16** foram [**revertidas e documentadas aqui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* As **categorias LC atuais (macOS 14** - Somona) foram revertidas e suas [**descrições podem ser encontradas aqui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Por exemplo, a Categoria 1 é:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Deve estar em um volume System ou Cryptexes.
* `launch-type == 1`: Deve ser um serviço do sistema (plist em LaunchDaemons).
* &#x20; `validation-category == 1`: Um executável do sistema operacional.
* `is-init-proc`: Launchd

### Reversing LC Categories

Você tem mais informações [**sobre isso aqui**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), mas basicamente, eles são definidos em **AMFI (AppleMobileFileIntegrity)**, então você precisa baixar o Kernel Development Kit para obter o **KEXT**. Os símbolos que começam com **`kConstraintCategory`** são os mais **interessantes**. Extraindo-os, você obterá um fluxo codificado DER (ASN.1) que precisará ser decodificado com o [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ou a biblioteca python-asn1 e seu script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), que fornecerá uma string mais compreensível.

## Restrições de Ambiente

Essas são as Restrições de Lançamento configuradas em **aplicativos de terceiros**. O desenvolvedor pode selecionar os **fatos** e **operandos lógicos a serem usados** em seu aplicativo para restringir o acesso a si mesmo.

É possível enumerar as Restrições de Ambiente de um aplicativo com:
```bash
codesign -d -vvvv app.app
```
## Caches de Confiança

No **macOS**, existem alguns caches de confiança:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

E no iOS parece estar em **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

### Enumerando Caches de Confiança

Os arquivos de cache de confiança mencionados anteriormente estão no formato **IMG4** e **IM4P**, sendo o IM4P a seção de carga útil de um formato IMG4.

Você pode usar o [**pyimg4**](https://github.com/m1stadev/PyIMG4) para extrair a carga útil dos bancos de dados:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Outra opção poderia ser usar a ferramenta [**img4tool**](https://github.com/tihmstar/img4tool), que funcionará mesmo no M1 mesmo se a versão for antiga e para x86\_64 se você instalá-la nos locais adequados).

Agora você pode usar a ferramenta [**trustcache**](https://github.com/CRKatri/trustcache) para obter as informações em um formato legível:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
O cache de confiança segue a seguinte estrutura, então a **categoria LC é a 4ª coluna**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Em seguida, você pode usar um script como [**este**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) para extrair dados.

A partir desses dados, você pode verificar os aplicativos com um **valor de restrição de lançamento de `0`**, que são aqueles que não possuem restrições ([**verifique aqui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) para saber o significado de cada valor).

## Mitigações de Ataque

As Restrições de Lançamento teriam mitigado vários ataques antigos, **garantindo que o processo não seja executado em condições inesperadas:** por exemplo, de locais inesperados ou sendo invocado por um processo pai inesperado (se apenas o launchd deveria iniciá-lo).

Além disso, as Restrições de Lançamento também **mitigam ataques de degradação**.

No entanto, elas **não mitigam abusos comuns de XPC**, injeções de código **Electron** ou injeções de **dylib** sem validação de biblioteca (a menos que sejam conhecidos os IDs da equipe que pode carregar bibliotecas).

### Proteção do Daemon XPC

No momento em que este texto foi escrito (lançamento Sonoma), o **processo responsável** pelo serviço XPC do daemon **é o próprio serviço XPC** em vez do cliente conectado. (Enviado FB: FB13206884). Supondo por um segundo que seja um bug, ainda **não seremos capazes de iniciar o serviço XPC em nosso código de ataque**, mas se ele já estiver **ativo** (talvez porque tenha sido invocado pelo aplicativo original), nada impede que nos **conectemos a ele**. Portanto, embora definir a restrição possa ser uma boa ideia e **limitaria o tempo de ataque**, isso não resolve o problema principal, e nosso serviço XPC ainda deve validar corretamente o cliente conectado. Essa ainda é a única maneira de protegê-lo. Além disso, como mencionado no início, nem funciona mais dessa maneira.

### Proteção do Electron

Mesmo que seja necessário que o aplicativo seja **aberto pelo LaunchService** (nas restrições dos pais). Isso pode ser alcançado usando o **`open`** (que pode definir variáveis de ambiente) ou usando a **API de Serviços de Lançamento** (onde as variáveis de ambiente podem ser indicadas).

## Referências

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>
