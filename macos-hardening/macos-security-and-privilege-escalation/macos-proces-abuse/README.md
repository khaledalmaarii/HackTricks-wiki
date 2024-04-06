# macOS Proces Abuse

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abuso de Processos no macOS

O macOS, como qualquer outro sistema operacional, fornece uma variedade de métodos e mecanismos para que os **processos interajam, comuniquem e compartilhem dados**. Embora essas técnicas sejam essenciais para o funcionamento eficiente do sistema, também podem ser abusadas por atores maliciosos para **realizar atividades maliciosas**.

### Injeção de Biblioteca

A Injeção de Biblioteca é uma técnica na qual um atacante **força um processo a carregar uma biblioteca maliciosa**. Uma vez injetada, a biblioteca é executada no contexto do processo-alvo, fornecendo ao atacante as mesmas permissões e acesso do processo.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hooking de Funções

O Hooking de Funções envolve **interceptar chamadas de função** ou mensagens dentro de um código de software. Ao enganchar funções, um atacante pode **modificar o comportamento** de um processo, observar dados sensíveis ou até mesmo obter controle sobre o fluxo de execução.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Comunicação entre Processos

A Comunicação entre Processos (IPC) refere-se a diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora o IPC seja fundamental para muitas aplicações legítimas, ele também pode ser mal utilizado para subverter o isolamento de processos, vazar informações sensíveis ou realizar ações não autorizadas.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injeção em Aplicações Electron

Aplicações Electron executadas com variáveis de ambiente específicas podem ser vulneráveis à injeção de processos:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Injeção em Chromium

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **ataque man in the browser** permitindo roubar pressionamentos de teclas, tráfego, cookies, injetar scripts em páginas...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### NIB Sujo

Arquivos NIB **definem elementos de interface do usuário (UI)** e suas interações dentro de um aplicativo. No entanto, eles podem **executar comandos arbitrários** e o **Gatekeeper não impede** que um aplicativo já executado seja executado se um **arquivo NIB for modificado**. Portanto, eles poderiam ser usados para fazer programas arbitrários executarem comandos arbitrários:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Injeção em Aplicações Java

É possível abusar de certas capacidades do Java (como a variável de ambiente **`_JAVA_OPTS`**) para fazer um aplicativo Java executar **código/comandos arbitrários**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Injeção em Aplicações .Net

É possível injetar código em aplicativos .Net **abusando da funcionalidade de depuração do .Net** (não protegida por proteções do macOS, como o fortalecimento em tempo de execução).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Injeção em Perl

Verifique diferentes opções para fazer um script Perl executar código arbitrário em:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Injeção em Ruby

Também é possível abusar das variáveis de ambiente do Ruby para fazer scripts arbitrários executarem código arbitrário:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Injeção em Python

Se a variável de ambiente **`PYTHONINSPECT`** estiver definida, o processo Python entrará em um cli Python assim que terminar. Também é possível usar **`PYTHONSTARTUP`** para indicar um script Python a ser executado no início de uma sessão interativa.\
No entanto, observe que o script **`PYTHONSTARTUP`** não será executado quando o **`PYTHONINSPECT`** cria a sessão interativa.

Outras variáveis de ambiente, como **`PYTHONPATH`** e **`PYTHONHOME`**, também podem ser úteis para fazer um comando Python executar código arbitrário.

Observe que executáveis compilados com **`pyinstaller`** não usarão essas variáveis ambientais, mesmo que estejam sendo executados usando um Python incorporado.

No geral, não consegui encontrar uma maneira de fazer o Python executar código arbitrário abusando de variáveis de ambiente.\ No entanto, a maioria das pessoas instala o Python usando o \*\*Hombrew\*\*, que instalará o Python em um \*\*local gravável\*\* para o usuário administrador padrão. Você pode se apropriar disso com algo como: \`\`\`bash mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old cat > /opt/homebrew/bin/python3 <

## Detecção

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) é um aplicativo de código aberto que pode **detectar e bloquear ações de injeção de processo**:

* Usando **Variáveis Ambientais**: Ele monitorará a presença de qualquer uma das seguintes variáveis ambientais: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
* Usando chamadas de **`task_for_pid`**: Para encontrar quando um processo deseja obter a **porta de tarefa de outro**, o que permite injetar código no processo.
* Parâmetros de aplicativos **Electron**: Alguém pode usar os argumentos de linha de comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** para iniciar um aplicativo Electron no modo de depuração e, assim, injetar código nele.
* Usando **links simbólicos** ou **hardlinks**: Tipicamente, o abuso mais comum é **colocar um link com nossos privilégios de usuário** e **apontá-lo para uma localização de privilégio superior**. A detecção é muito simples para ambos, hardlinks e links simbólicos. Se o processo que cria o link tiver um **nível de privilégio diferente** do arquivo de destino, criamos um **alerta**. Infelizmente, no caso de links simbólicos, o bloqueio não é possível, pois não temos informações sobre o destino do link antes da criação. Esta é uma limitação do framework EndpointSecuriy da Apple.

### Chamadas feitas por outros processos

Neste [**post do blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode encontrar como é possível usar a função **`task_name_for_pid`** para obter informações sobre outros **processos injetando código em um processo** e, em seguida, obter informações sobre esse outro processo.

Observe que para chamar essa função, você precisa ter **o mesmo uid** que o processo em execução ou ser **root** (e ela retorna informações sobre o processo, não uma maneira de injetar código).

## Referências

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
