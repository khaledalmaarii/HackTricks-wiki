# Injeção de Biblioteca no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
O código do **dyld é open source** e pode ser encontrado em [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e pode ser baixado como um tar usando uma **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> Esta é uma **lista separada por dois pontos de bibliotecas dinâmicas** para **carregar antes das especificadas no programa**. Isso permite testar novos módulos de bibliotecas compartilhadas dinâmicas existentes que são usadas em imagens de namespace plano, carregando uma biblioteca compartilhada dinâmica temporária com apenas os novos módulos. Note que isso não tem efeito em imagens construídas com imagens de namespace de dois níveis usando uma biblioteca compartilhada dinâmica, a menos que DYLD\_FORCE\_FLAT\_NAMESPACE também seja usado.

Isso é como o [**LD\_PRELOAD no Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload).

Esta técnica também pode ser **usada como uma técnica de ASEP**, já que cada aplicativo instalado tem um plist chamado "Info.plist" que permite a **atribuição de variáveis de ambiente** usando uma chave chamada `LSEnvironmental`.

{% hint style="info" %}
Desde 2012, a **Apple reduziu drasticamente o poder** do **`DYLD_INSERT_LIBRARIES`**.

Vá até o código e **verifique `src/dyld.cpp`**. Na função **`pruneEnvironmentVariables`**, você pode ver que as variáveis **`DYLD_*`** são removidas.

Na função **`processRestricted`**, a razão da restrição é definida. Verificando esse código, você pode ver que as razões são:

* O binário é `setuid/setgid`
* Existência de uma seção `__RESTRICT/__restrict` no binário macho.
* O software tem entitlements (runtime reforçado) sem o entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Verifique **entitlements** de um binário com: `codesign -dv --entitlements :- </path/to/bin>`

Em versões mais atualizadas, você pode encontrar essa lógica na segunda parte da função **`configureProcessRestrictions`.** No entanto, o que é executado em versões mais recentes são as **verificações iniciais da função** (você pode remover os ifs relacionados ao iOS ou simulação, pois esses não serão usados no macOS.
{% endhint %}

### Validação de Biblioteca

Mesmo que o binário permita o uso da variável de ambiente **`DYLD_INSERT_LIBRARIES`**, se o binário verificar a assinatura da biblioteca a ser carregada, ele não carregará uma biblioteca personalizada.

Para carregar uma biblioteca personalizada, o binário precisa ter **um dos seguintes entitlements**:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou o binário **não deve** ter a **flag de runtime reforçado** ou a **flag de validação de biblioteca**.

Você pode verificar se um binário tem **runtime reforçado** com `codesign --display --verbose <bin>` verificando a flag runtime em **`CodeDirectory`** como: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Você também pode carregar uma biblioteca se ela estiver **assinada com o mesmo certificado que o binário**.

Encontre um exemplo de como (ab)usar isso e verificar as restrições em:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Sequestro de Dylib

{% hint style="danger" %}
Lembre-se de que as **restrições anteriores de Validação de Biblioteca também se aplicam** para realizar ataques de sequestro de Dylib.
{% endhint %}

Assim como no Windows, no MacOS você também pode **sequestrar dylibs** para fazer **aplicativos** **executarem** **código arbitrário**.\
No entanto, a maneira como os aplicativos **MacOS** **carregam** bibliotecas é **mais restrita** do que no Windows. Isso implica que os desenvolvedores de **malware** ainda podem usar essa técnica para **discrição**, mas a probabilidade de poder **abusar disso para escalar privilégios é muito menor**.

Primeiramente, é **mais comum** encontrar que os **binários do MacOS indicam o caminho completo** para as bibliotecas a serem carregadas. E segundo, o **MacOS nunca procura** nas pastas do **$PATH** por bibliotecas.

A **parte principal** do **código** relacionado a essa funcionalidade está em **`ImageLoader::recursiveLoadLibraries`** em `ImageLoader.cpp`.

Existem **4 diferentes Comandos de Cabeçalho** que um binário macho pode usar para carregar bibliotecas:

* O comando **`LC_LOAD_DYLIB`** é o comando comum para carregar uma dylib.
* O comando **`LC_LOAD_WEAK_DYLIB`** funciona como o anterior, mas se a dylib não for encontrada, a execução continua sem nenhum erro.
* O comando **`LC_REEXPORT_DYLIB`** ele faz proxy (ou reexporta) os símbolos de uma biblioteca diferente.
* O comando **`LC_LOAD_UPWARD_DYLIB`** é usado quando duas bibliotecas dependem uma da outra (isso é chamado de _dependência ascendente_).

No entanto, existem **2 tipos de sequestro de dylib**:

* **Bibliotecas vinculadas fracas ausentes**: Isso significa que o aplicativo tentará carregar uma biblioteca que não existe configurada com **LC\_LOAD\_WEAK\_DYLIB**. Então, **se um atacante colocar uma dylib onde é esperada, ela será carregada**.
* O fato de a ligação ser "fraca" significa que o aplicativo continuará funcionando mesmo que a biblioteca não seja encontrada.
* O **código relacionado** a isso está na função `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp` onde `lib->required` é apenas `false` quando `LC_LOAD_WEAK_DYLIB` é verdadeiro.
* **Encontre bibliotecas vinculadas fracas** em binários com (você tem mais tarde um exemplo de como criar bibliotecas de sequestro):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Configurado com @rpath**: Binários Mach-O podem ter os comandos **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. Baseado nos **valores** desses comandos, **bibliotecas** serão **carregadas** de **diferentes diretórios**.
* **`LC_RPATH`** contém os caminhos de algumas pastas usadas para carregar bibliotecas pelo binário.
* **`LC_LOAD_DYLIB`** contém o caminho para bibliotecas específicas a serem carregadas. Esses caminhos podem conter **`@rpath`**, que será **substituído** pelos valores em **`LC_RPATH`**. Se houver vários caminhos em **`LC_RPATH`**, todos serão usados para procurar a biblioteca a ser carregada. Exemplo:
* Se **`LC_LOAD_DYLIB`** contém `@rpath/library.dylib` e **`LC_RPATH`** contém `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Ambas as pastas serão usadas para carregar `library.dylib`**.** Se a biblioteca não existir em `[...]/v1/` e um atacante puder colocá-la lá para sequestrar o carregamento da biblioteca em `[...]/v2/`, pois a ordem dos caminhos em **`LC_LOAD_DYLIB`** é seguida.
* **Encontre caminhos rpath e bibliotecas** em binários com: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: É o **caminho** para o diretório que contém o **arquivo executável principal**.

**`@loader_path`**: É o **caminho** para o **diretório** que contém o **binário Mach-O** que contém o comando de carregamento.

* Quando usado em um executável, **`@loader_path`** é efetivamente o **mesmo** que **`@executable_path`**.
* Quando usado em uma **dylib**, **`@loader_path`** fornece o **caminho** para a **dylib**.
{% endhint %}

A maneira de **escalar privilégios** abusando dessa funcionalidade seria no raro caso de um **aplicativo** sendo executado **por** **root** estar **procurando** por alguma **biblioteca em algum diretório onde o atacante tem permissões de escrita.**

{% hint style="success" %}
Um bom **scanner** para encontrar **bibliotecas ausentes** em aplicativos é o [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou uma [**versão CLI**](https://github.com/pandazheng/DylibHijack).\
Um bom **relatório com detalhes técnicos** sobre essa técnica pode ser encontrado [**aqui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Exemplo**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Sequestro de Dlopen

{% hint style="danger" %}
Lembre-se de que as **restrições anteriores de Validação de Biblioteca também se aplicam** para realizar ataques de sequestro de Dlopen.
{% endhint %}

Do **`man dlopen`**:

* Quando o caminho **não contém um caractere de barra** (ou seja, é apenas um nome de folha), **dlopen() fará uma busca**. Se **`$DYLD_LIBRARY_PATH`** foi definido no lançamento, dyld primeiro **procurará nesse diretório**. Em seguida, se o arquivo mach-o chamador ou o executável principal especificar um **`LC_RPATH`**, então dyld **procurará nesses** diretórios. Em seguida, se o processo for **não restrito**, dyld procurará no **diretório de trabalho atual**. Por fim, para binários antigos, dyld tentará alguns fallbacks. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** foi definido no lançamento, dyld procurará nesses diretórios, caso contrário, dyld procurará em **`/usr/local/lib/`** (se o processo for não restrito) e então em **`/usr/lib/`** (esta informação foi tirada do **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(se não restrito)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (se não restrito)
6. `/usr/lib/`

{% hint style="danger" %}
Se não houver barras no nome, haveria 2 maneiras de fazer um sequestro:

* Se algum **`LC_RPATH`** for **gravável** (mas a assinatura é verificada, então para isso você também precisa que o binário seja não restrito)
* Se o binário for **não restrito** e então for possível carregar algo do CWD (ou abusando de uma das variáveis de ambiente mencionadas)
{% endhint %}

* Quando o caminho **parece um caminho de framework** (por exemplo, `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** foi definido no lançamento, dyld primeiro procurará nesse diretório pelo **caminho parcial do framework** (por exemplo, `foo.framework/foo`). Em seguida, dyld tentará o **caminho fornecido como está** (usando o diretório de trabalho atual para caminhos relativos). Por fim, para binários antigos, dyld tentará alguns fallbacks. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** foi definido no lançamento, dyld procurará nesses diretórios. Caso contrário, ele procurará em **`/Library/Frameworks`** (no macOS se o processo for não restrito), e então em **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. caminho fornecido (usando o diretório de trabalho atual para caminhos relativos se não restrito)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (se não restrito)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Se for um caminho de framework, a maneira de sequestrá-lo seria:

* Se o processo for **não restrito**, abusando do **caminho relativo do CWD** as variáveis de ambiente mencionadas (mesmo que não seja dito nos documentos se o processo for restrito, as variáveis de ambiente DYLD\_\* são removidas)
{% endhint %}

* Quando o caminho **contém uma barra mas não é um caminho de framework** (ou seja, um caminho completo ou um caminho parcial para uma dylib), dlopen() primeiro olha em (se definido) em **`$DYLD_LIBRARY_PATH`** (com a parte da folha do caminho). Em seguida, dyld **tenta o caminho fornecido** (usando o diretório de trabalho atual para caminhos relativos (mas apenas para processos não restritos)). Por fim, para binários mais antigos, dyld tentará fallbacks. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** foi definido no lançamento, dyld procurará nesses diretórios, caso contrário, dyld procurará em **`/usr/local/lib/`** (se o processo for não restrito) e então em **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. caminho fornecido (usando o diretório de trabalho atual para caminhos relativos se não restrito)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (se não restrito)
5. `/usr/lib/`

{% hint style="danger" %}
Se houver barras no nome e não for um framework, a mane
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Se você compilar e executar, poderá ver **onde cada biblioteca foi procurada sem sucesso**. Além disso, você poderia **filtrar os logs do FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Sequestro de Caminho Relativo

Se um **binário/aplicativo privilegiado** (como um SUID ou algum binário com permissões poderosas) estiver **carregando uma biblioteca de caminho relativo** (por exemplo, usando `@executable_path` ou `@loader_path`) e tiver **Validação de Biblioteca desativada**, poderia ser possível mover o binário para um local onde o atacante pudesse **modificar a biblioteca de caminho relativo carregada**, e abusar dela para injetar código no processo.

## Podar variáveis de ambiente `DYLD_*` e `LD_LIBRARY_PATH`

No arquivo `dyld-dyld-832.7.1/src/dyld2.cpp` é possível encontrar a função **`pruneEnvironmentVariables`**, que removerá qualquer variável de ambiente que **comece com `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Ela também definirá como **nulo** especificamente as variáveis de ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** para binários **suid** e **sgid**.

Esta função é chamada a partir da função **`_main`** do mesmo arquivo se estiver direcionada para OSX assim:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
e essas flags booleanas são definidas no mesmo arquivo no código:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
O que basicamente significa que se o binário for **suid** ou **sgid**, ou tiver um segmento **RESTRICT** nos cabeçalhos ou foi assinado com a flag **CS\_RESTRICT**, então **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** é verdadeiro e as variáveis de ambiente são eliminadas.

Note que se CS\_REQUIRE\_LV for verdadeiro, então as variáveis não serão eliminadas, mas a validação da biblioteca verificará se elas estão usando o mesmo certificado que o binário original.

## Verificar Restrições

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Seção `__RESTRICT` com segmento `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Runtime reforçado

Crie um novo certificado no Keychain e use-o para assinar o binário:

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Observe que mesmo que existam binários assinados com as flags **`0x0(nenhuma)`**, eles podem receber a flag **`CS_RESTRICT`** dinamicamente quando executados e, portanto, essa técnica não funcionará neles.

Você pode verificar se um processo tem essa flag com (obtenha [**csops aqui**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
e depois verifique se a flag 0x800 está habilitada.
{% endhint %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
