# Depuração do Sandbox Padrão do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

Nesta página, você pode encontrar como criar um aplicativo para lançar comandos arbitrários de dentro do sandbox padrão do macOS:

1. Compile o aplicativo:

{% code title="main.m" %}
```objectivec
#include <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
while (true) {
char input[512];

printf("Enter command to run (or 'exit' to quit): ");
if (fgets(input, sizeof(input), stdin) == NULL) {
break;
}

// Remove newline character
size_t len = strlen(input);
if (len > 0 && input[len - 1] == '\n') {
input[len - 1] = '\0';
}

if (strcmp(input, "exit") == 0) {
break;
}

system(input);
}
}
return 0;
}
```
{% endcode %}

Compile-o executando: `clang -framework Foundation -o SandboxedShellApp main.m`

2. Construa o pacote `.app`
```bash
mkdir -p SandboxedShellApp.app/Contents/MacOS
mv SandboxedShellApp SandboxedShellApp.app/Contents/MacOS/

cat << EOF > SandboxedShellApp.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>com.example.SandboxedShellApp</string>
<key>CFBundleName</key>
<string>SandboxedShellApp</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleExecutable</key>
<string>SandboxedShellApp</string>
</dict>
</plist>
EOF
```
3. Definir as permissões

{% tabs %}
{% tab title="sandbox" %}
```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
EOF
```
{% endtab %}

{% tab title="sandbox + downloads" %} 

## macOS Default Sandbox Debug

### macOS Default Sandbox Debug

The macOS default sandbox profile is located at `/System/Library/Sandbox/Profiles/system.sb`. This profile is used by system processes that run in the sandbox but do not have a specific sandbox profile defined for them.

To debug the macOS default sandbox profile, you can use the `sandbox-exec` tool with the `-n` flag to run a process in the default sandbox and print debugging information to the console. For example:

```bash
sandbox-exec -n system /bin/ls
```

This command runs the `/bin/ls` command in the default sandbox and prints debugging information to the console.

You can also use the `sandbox-exec` tool with the `-p` flag to specify a custom sandbox profile to use for debugging. For example:

```bash
sandbox-exec -p "/path/to/custom.sb" /bin/ls
```

This command runs the `/bin/ls` command in the custom sandbox profile specified by `/path/to/custom.sb` and prints debugging information to the console.

By debugging the macOS default sandbox profile, you can gain insights into the restrictions and permissions applied to system processes running in the sandbox, helping you understand and potentially exploit any misconfigurations or vulnerabilities in the sandbox environment. 

### macOS Default Sandbox Debug

O perfil de sandbox padrão do macOS está localizado em `/System/Library/Sandbox/Profiles/system.sb`. Este perfil é usado por processos do sistema que são executados no sandbox, mas não possuem um perfil de sandbox específico definido para eles.

Para depurar o perfil de sandbox padrão do macOS, você pode usar a ferramenta `sandbox-exec` com a flag `-n` para executar um processo no sandbox padrão e imprimir informações de depuração no console. Por exemplo:

```bash
sandbox-exec -n system /bin/ls
```

Este comando executa o comando `/bin/ls` no sandbox padrão e imprime informações de depuração no console.

Você também pode usar a ferramenta `sandbox-exec` com a flag `-p` para especificar um perfil de sandbox personalizado a ser usado para depuração. Por exemplo:

```bash
sandbox-exec -p "/caminho/para/custom.sb" /bin/ls
```

Este comando executa o comando `/bin/ls` no perfil de sandbox personalizado especificado por `/caminho/para/custom.sb` e imprime informações de depuração no console.

Ao depurar o perfil de sandbox padrão do macOS, você pode obter insights sobre as restrições e permissões aplicadas aos processos do sistema em execução no sandbox, ajudando a entender e potencialmente explorar quaisquer configurações incorretas ou vulnerabilidades no ambiente de sandbox. 

{% endtab %}
```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
<key>com.apple.security.files.downloads.read-write</key>
<true/>
</dict>
</plist>
EOF
```
{% endtab %}
{% endtabs %}

4. Assine o aplicativo (você precisa criar um certificado no chaveiro)
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# An d in case you need this in the future
codesign --remove-signature SandboxedShellApp.app
```
<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
