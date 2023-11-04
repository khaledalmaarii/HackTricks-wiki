# Injeção de Biblioteca no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="danger" %}
O código do **dyld é de código aberto** e pode ser encontrado em [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e pode ser baixado como um arquivo tar usando um **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> Esta é uma lista de bibliotecas dinâmicas separadas por dois pontos **para carregar antes das especificadas no programa**. Isso permite testar novos módulos de bibliotecas compartilhadas dinâmicas existentes que são usadas em imagens de espaço de nomes plano, carregando uma biblioteca compartilhada dinâmica temporária apenas com os novos módulos. Observe que isso não tem efeito em imagens construídas com um espaço de nomes de dois níveis usando uma biblioteca compartilhada dinâmica, a menos que DYLD\_FORCE\_FLAT\_NAMESPACE também seja usado.

Isso é semelhante ao [**LD\_PRELOAD no Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload).

Essa técnica também pode ser **usada como uma técnica ASEP** já que cada aplicativo instalado possui um arquivo plist chamado "Info.plist" que permite a **atribuição de variáveis ambientais** usando uma chave chamada `LSEnvironmental`.

{% hint style="info" %}
Desde 2012, a **Apple reduziu drasticamente o poder** do **`DYLD_INSERT_LIBRARIES`**.

Vá para o código e **verifique `src/dyld.cpp`**. Na função **`pruneEnvironmentVariables`**, você pode ver que as variáveis **`DYLD_*`** são removidas.

Na função **`processRestricted`**, é definido o motivo da restrição. Verificando esse código, você pode ver que os motivos são:

* O binário é `setuid/setgid`
* Existência da seção `__RESTRICT/__restrict` no binário macho.
* O software possui direitos (execução protegida) sem o direito [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Verifique os **direitos** de um binário com: `codesign -dv --entitlements :- </path/to/bin>`

Em versões mais atualizadas, você pode encontrar essa lógica na segunda parte da função **`configureProcessRestrictions`**. No entanto, o que é executado em versões mais recentes são as **verificações iniciais da função** (você pode remover os ifs relacionados ao iOS ou simulação, pois eles não serão usados no macOS.
{% endhint %}

### Validação de Biblioteca

Mesmo que o binário permita o uso da variável de ambiente **`DYLD_INSERT_LIBRARIES`**, se o binário verificar a assinatura da biblioteca para carregá-la, não carregará uma biblioteca personalizada.

Para carregar uma biblioteca personalizada, o binário precisa ter **uma das seguintes direitos**:

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou o binário **não deve** ter a **flag de execução protegida** ou a **flag de validação de biblioteca**.

Você pode verificar se um binário possui **execução protegida** com `codesign --display --verbose <bin>` verificando a flag runtime em **`CodeDirectory`** como: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Você também pode carregar uma biblioteca se ela estiver **assinada com o mesmo certificado do binário**.

Encontre um exemplo de como (ab)usar isso e verificar as restrições em:

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}
## Dylib Hijacking

{% hint style="danger" %}
Lembre-se de que as restrições de **Validação de Biblioteca anteriores também se aplicam** para realizar ataques de hijacking de dylib.
{% endhint %}

Assim como no Windows, no MacOS também é possível **hijackar dylibs** para fazer com que **aplicativos** executem **código arbitrário**.\
No entanto, a maneira como os aplicativos do **MacOS** carregam bibliotecas é **mais restrita** do que no Windows. Isso implica que os desenvolvedores de **malware** ainda podem usar essa técnica para **furtividade**, mas a probabilidade de conseguir **abuso disso para elevar privilégios é muito menor**.

Em primeiro lugar, é **mais comum** encontrar que os binários do **MacOS indicam o caminho completo** para as bibliotecas a serem carregadas. E em segundo lugar, o **MacOS nunca procura** nas pastas do **$PATH** por bibliotecas.

A **parte principal** do **código** relacionado a essa funcionalidade está em **`ImageLoader::recursiveLoadLibraries`** em `ImageLoader.cpp`.

Existem **4 comandos de cabeçalho diferentes** que um binário macho pode usar para carregar bibliotecas:

* O comando **`LC_LOAD_DYLIB`** é o comando comum para carregar uma dylib.
* O comando **`LC_LOAD_WEAK_DYLIB`** funciona como o anterior, mas se a dylib não for encontrada, a execução continua sem nenhum erro.
* O comando **`LC_REEXPORT_DYLIB`** faz a proxy (ou reexportação) dos símbolos de uma biblioteca diferente.
* O comando **`LC_LOAD_UPWARD_DYLIB`** é usado quando duas bibliotecas dependem uma da outra (isso é chamado de _dependência ascendente_).

No entanto, existem **2 tipos de hijacking de dylib**:

* **Bibliotecas fracamente vinculadas ausentes**: Isso significa que o aplicativo tentará carregar uma biblioteca que não existe configurada com **LC\_LOAD\_WEAK\_DYLIB**. Então, **se um invasor colocar uma dylib onde ela é esperada, ela será carregada**.
* O fato de o link ser "fraco" significa que o aplicativo continuará sendo executado mesmo se a biblioteca não for encontrada.
* O **código relacionado** a isso está na função `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, onde `lib->required` é apenas `false` quando `LC_LOAD_WEAK_DYLIB` é verdadeiro.
* **Encontre bibliotecas fracamente vinculadas** em binários com (você terá um exemplo posterior sobre como criar bibliotecas de hijacking):
* ```bash
otool -l </caminho/para/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **Configurado com @rpath**: Os binários Mach-O podem ter os comandos **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. Com base nos **valores** desses comandos, as **bibliotecas** serão **carregadas** de **diretórios diferentes**.
* **`LC_RPATH`** contém os caminhos de algumas pastas usadas para carregar bibliotecas pelo binário.
* **`LC_LOAD_DYLIB`** contém o caminho para bibliotecas específicas a serem carregadas. Esses caminhos podem conter **`@rpath`**, que será **substituído** pelos valores em **`LC_RPATH`**. Se houver vários caminhos em **`LC_RPATH`**, todos serão usados para pesquisar a biblioteca a ser carregada. Exemplo:
* Se **`LC_LOAD_DYLIB`** contém `@rpath/library.dylib` e **`LC_RPATH`** contém `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Ambas as pastas serão usadas para carregar `library.dylib`**.** Se a biblioteca não existir em `[...]/v1/` e o invasor puder colocá-la lá para hijackar o carregamento da biblioteca em `[...]/v2/` conforme a ordem dos caminhos em **`LC_LOAD_DYLIB`**.
* **Encontre caminhos rpath e bibliotecas** em binários com: `otool -l </caminho/para/binário> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: É o **caminho** para o diretório que contém o **arquivo executável principal**.

**`@loader_path`**: É o **caminho** para o **diretório** que contém o **binário Mach-O** que contém o comando de carregamento.

* Quando usado em um executável, **`@loader_path`** é efetivamente o **mesmo** que **`@executable_path`**.
* Quando usado em uma **dylib**, **`@loader_path`** fornece o **caminho** para a **dylib**.
{% endhint %}

A maneira de **elevar privilégios** abusando dessa funcionalidade seria no caso raro de um **aplicativo** sendo executado **por** **root** estar **procurando** por alguma **biblioteca em alguma pasta onde o invasor tenha permissões de gravação**.

{% hint style="success" %}
Um bom **scanner** para encontrar **bibliotecas ausentes** em aplicativos é o [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou uma [**versão CLI**](https://github.com/pandazheng/DylibHijack).\
Um bom **relatório com detalhes técnicos** sobre essa técnica pode ser encontrado [**aqui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Exemplo**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Lembre-se de que as restrições de **Validação de Biblioteca anteriores também se aplicam** para realizar ataques de hijacking de Dlopen.
{% endhint %}

Do **`man dlopen`**:

* Quando o caminho **não contém um caractere de barra** (ou seja, é apenas um nome de folha), o **dlopen() fará uma busca**. Se **`$DYLD_LIBRARY_PATH`** foi definido no lançamento, o dyld primeiro **procurará nesse diretório**. Em seguida, se o arquivo mach-o chamador ou o executável principal especificar um **`LC_RPATH`**, o dyld **procurará nesses** diretórios. Em seguida, se o processo estiver **sem restrições**, o dyld procurará no **diretório de trabalho atual**. Por último, para binários antigos, o dyld tentará algumas alternativas. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** foi definido no lançamento, o dyld procurará nesses diretórios, caso contrário, o dyld procurará em **`/usr/local/lib/`** (se o processo estiver sem restrições) e depois em **`/usr/lib/`** (essas informações foram retiradas do **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(se sem restrições)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (se sem restrições)
6. `/usr/lib/`

{% hint style="danger" %}
Se não houver barras no nome, haveria 2 maneiras de fazer um hijacking:

* Se algum **`LC_RPATH`** for **gravável** (mas a assinatura é verificada, então para isso você também precisa que o binário esteja sem restrições)
* Se o binário estiver **sem restrições** e, em seguida, for possível carregar algo do CWD (ou abusar de uma das variáveis de ambiente mencionadas)
{% endhint %}
* Quando o caminho **se parece com um caminho de framework** (por exemplo, `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** foi definido no lançamento, o dyld primeiro procurará nesse diretório pelo **caminho parcial do framework** (por exemplo, `foo.framework/foo`). Em seguida, o dyld tentará o **caminho fornecido como está** (usando o diretório de trabalho atual para caminhos relativos). Por último, para binários antigos, o dyld tentará algumas alternativas. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** foi definido no lançamento, o dyld pesquisará nesses diretórios. Caso contrário, ele pesquisará em **`/Library/Frameworks`** (no macOS se o processo não tiver restrições), e depois em **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. caminho fornecido (usando o diretório de trabalho atual para caminhos relativos se não houver restrições)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (se não houver restrições)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Se for um caminho de framework, a maneira de sequestrá-lo seria:

* Se o processo não tiver restrições, abusar do **caminho relativo do diretório de trabalho** e das variáveis de ambiente mencionadas (mesmo que não seja mencionado na documentação se o processo está restrito, as variáveis de ambiente DYLD\_\* são removidas)
{% endhint %}

* Quando o caminho **contém uma barra, mas não é um caminho de framework** (ou seja, um caminho completo ou um caminho parcial para um dylib), o dlopen() primeiro procura (se definido) em **`$DYLD_LIBRARY_PATH`** (com a parte final do caminho). Em seguida, o dyld **tenta o caminho fornecido** (usando o diretório de trabalho atual para caminhos relativos, mas apenas para processos não restritos). Por último, para binários mais antigos, o dyld tentará alternativas. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** foi definido no lançamento, o dyld pesquisará nesses diretórios, caso contrário, o dyld procurará em **`/usr/local/lib/`** (se o processo não tiver restrições) e depois em **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. caminho fornecido (usando o diretório de trabalho atual para caminhos relativos se não houver restrições)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (se não houver restrições)
5. `/usr/lib/`

{% hint style="danger" %}
Se houver barras no nome e não for um framework, a maneira de sequestrá-lo seria:

* Se o binário não tiver restrições, então é possível carregar algo do diretório de trabalho atual ou `/usr/local/lib` (ou abusar de uma das variáveis de ambiente mencionadas)
{% endhint %}

{% hint style="info" %}
Observação: Não existem arquivos de configuração para **controlar a busca do dlopen**.

Observação: Se o executável principal for um binário **set\[ug]id ou tiver assinatura com entitlements**, então **todas as variáveis de ambiente são ignoradas**, e apenas um caminho completo pode ser usado ([verifique as restrições do DYLD\_INSERT\_LIBRARIES](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) para obter informações mais detalhadas)

Observação: As plataformas da Apple usam arquivos "universais" para combinar bibliotecas de 32 bits e 64 bits. Isso significa que **não existem caminhos de busca separados para 32 bits e 64 bits**.

Observação: Nas plataformas da Apple, a maioria das bibliotecas do sistema operacional é **combinada no cache do dyld** e não existe no disco. Portanto, chamar **`stat()`** para verificar antecipadamente se uma biblioteca do sistema operacional existe **não funcionará**. No entanto, **`dlopen_preflight()`** usa as mesmas etapas que **`dlopen()`** para encontrar um arquivo mach-o compatível.
{% endhint %}

**Verificar caminhos**

Vamos verificar todas as opções com o seguinte código:
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
Se você compilar e executar, você pode ver **onde cada biblioteca foi procurada sem sucesso**. Além disso, você pode **filtrar os logs do sistema de arquivos**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Remover variáveis de ambiente `DYLD_*` e `LD_LIBRARY_PATH`

No arquivo `dyld-dyld-832.7.1/src/dyld2.cpp`, é possível encontrar a função **`pruneEnvironmentVariables`**, que irá remover qualquer variável de ambiente que **comece com `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Também irá definir como **nulo** especificamente as variáveis de ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** para binários **suid** e **sgid**.

Essa função é chamada a partir da função **`_main`** do mesmo arquivo, se o alvo for o OSX, da seguinte forma:
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
O que basicamente significa que se o binário for **suid** ou **sgid**, ou tiver um segmento **RESTRICT** nos cabeçalhos ou se foi assinado com a flag **CS\_RESTRICT**, então **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** é verdadeiro e as variáveis de ambiente são removidas.

Observe que se CS\_REQUIRE\_LV for verdadeiro, as variáveis não serão removidas, mas a validação da biblioteca verificará se elas estão usando o mesmo certificado que o binário original.

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

The `__RESTRICT` section is a segment in macOS that is used to restrict the execution of certain processes. This section is designed to prevent unauthorized access and privilege escalation by limiting the capabilities of processes.

The `__restrict` segment is specifically used to enforce restrictions on library injection. Library injection is a technique where a malicious library is injected into a legitimate process, allowing the attacker to execute arbitrary code within the context of that process.

By utilizing the `__restrict` segment, macOS can prevent library injection by restricting the loading of libraries from certain locations or by enforcing code signing requirements. This helps to ensure the integrity and security of the system by preventing unauthorized modifications to processes.

It is important for developers and system administrators to understand the functionality of the `__RESTRICT` section and the `__restrict` segment in order to effectively secure macOS systems against privilege escalation and unauthorized access.
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
Observe que mesmo que existam binários assinados com as flags **`0x0(none)`**, eles podem obter a flag **`CS_RESTRICT`** dinamicamente quando executados e, portanto, essa técnica não funcionará neles.

Você pode verificar se um processo possui essa flag com (obtenha [**csops aqui**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
e então verifique se a flag 0x800 está habilitada.
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
