# Abuso de Processos no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abuso de Processos no MacOS

O MacOS, como qualquer outro sistema operacional, oferece uma variedade de métodos e mecanismos para que **processos interajam, comuniquem-se e compartilhem dados**. Embora essas técnicas sejam essenciais para o funcionamento eficiente do sistema, elas também podem ser abusadas por atores de ameaças para **realizar atividades maliciosas**.

### Injeção de Biblioteca

Injeção de Biblioteca é uma técnica na qual um atacante **força um processo a carregar uma biblioteca maliciosa**. Uma vez injetada, a biblioteca executa no contexto do processo alvo, fornecendo ao atacante as mesmas permissões e acesso que o processo.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hooking de Função

Hooking de Função envolve **interceptar chamadas de função** ou mensagens dentro de um código de software. Ao fazer hooking de funções, um atacante pode **modificar o comportamento** de um processo, observar dados sensíveis ou até mesmo ganhar controle sobre o fluxo de execução.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Comunicação Entre Processos

Comunicação Entre Processos (IPC) refere-se a diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora o IPC seja fundamental para muitas aplicações legítimas, ele também pode ser mal utilizado para subverter o isolamento de processos, vazar informações sensíveis ou realizar ações não autorizadas.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injeção em Aplicações Electron

Aplicações Electron executadas com variáveis de ambiente específicas podem ser vulneráveis à injeção de processos:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### NIB Sujo

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de uma aplicação. No entanto, eles podem **executar comandos arbitrários** e o **Gatekeeper não impede** uma aplicação já executada de ser executada se um **arquivo NIB for modificado**. Portanto, eles podem ser usados para fazer programas arbitrários executarem comandos arbitrários:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Injeção em Aplicações Java

É possível abusar de certas capacidades do java (como a variável de ambiente **`_JAVA_OPTS`**) para fazer uma aplicação java executar **código/comandos arbitrários**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Injeção em Aplicações .Net

É possível injetar código em aplicações .Net **abusando da funcionalidade de depuração do .Net** (não protegida pelas proteções do macOS, como o endurecimento em tempo de execução).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Injeção em Perl

Confira diferentes opções para fazer um script Perl executar código arbitrário em:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Injeção em Ruby

Também é possível abusar de variáveis de ambiente ruby para fazer scripts arbitrários executarem código arbitrário:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Injeção em Python

Se a variável de ambiente **`PYTHONINSPECT`** estiver definida, o processo python entrará em um cli python assim que terminar. Também é possível usar **`PYTHONSTARTUP`** para indicar um script python a ser executado no início de uma sessão interativa.\
No entanto, observe que o script **`PYTHONSTARTUP`** não será executado quando **`PYTHONINSPECT`** criar a sessão interativa.

Outras variáveis de ambiente como **`PYTHONPATH`** e **`PYTHONHOME`** também podem ser úteis para fazer um comando python executar código arbitrário.

Note que executáveis compilados com **`pyinstaller`** não usarão essas variáveis ambientais mesmo que estejam rodando usando um python embutido.

{% hint style="danger" %}
No geral, não encontrei uma maneira de fazer o python executar código arbitrário abusando de variáveis de ambiente.\
No entanto, a maioria das pessoas instala o python usando o **Homebrew**, que instala o python em um **local gravável** para o usuário admin padrão. Você pode sequestrar isso com algo como:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
```markdown
Até mesmo o **root** executará este código ao rodar python.
{% endhint %}

## Detecção

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) é uma aplicação de código aberto que pode **detectar e bloquear ações de injeção de processos**:

* Usando **Variáveis Ambientais**: Ele monitorará a presença de quaisquer das seguintes variáveis ambientais: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
* Usando chamadas **`task_for_pid`**: Para encontrar quando um processo deseja obter o **porta de tarefa de outro** que permite injetar código no processo.
* **Parâmetros de apps Electron**: Alguém pode usar os argumentos de linha de comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** para iniciar um app Electron no modo de depuração e, assim, injetar código nele.
* Usando **symlinks** ou **hardlinks**: Tipicamente, o abuso mais comum é **colocar um link com nossos privilégios de usuário** e **apontá-lo para um local de privilégio mais alto**. A detecção é muito simples para ambos, hardlink e symlinks. Se o processo que cria o link tem um **nível de privilégio diferente** do arquivo alvo, criamos um **alerta**. Infelizmente, no caso de symlinks, o bloqueio não é possível, pois não temos informações sobre o destino do link antes da criação. Esta é uma limitação do framework EndpointSecuriy da Apple.

### Chamadas feitas por outros processos

Neste [**post do blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode encontrar como é possível usar a função **`task_name_for_pid`** para obter informações sobre outros **processos injetando código em um processo** e depois obter informações sobre esse outro processo.

Note que para chamar essa função você precisa ser **o mesmo uid** que o do processo em execução ou **root** (e ela retorna informações sobre o processo, não uma maneira de injetar código).

## Referências

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
