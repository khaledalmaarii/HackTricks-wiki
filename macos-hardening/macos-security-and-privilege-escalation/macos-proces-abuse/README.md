# Abuso de Processos no macOS

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Informações Básicas sobre Processos

Um processo é uma instância de um executável em execução, no entanto, os processos não executam código, esses são threads. Portanto, **os processos são apenas contêineres para threads em execução** fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`** que criaria uma cópia exata do processo atual e então o **processo filho** geralmente chamaria **`execve`** para carregar o novo executável e executá-lo. Em seguida, **`vfork`** foi introduzido para tornar esse processo mais rápido sem qualquer cópia de memória.\
Então **`posix_spawn`** foi introduzido combinando **`vfork`** e **`execve`** em uma chamada e aceitando flags:

* `POSIX_SPAWN_RESETIDS`: Redefinir ids efetivos para ids reais
* `POSIX_SPAWN_SETPGROUP`: Definir a filiação ao grupo de processos
* `POSUX_SPAWN_SETSIGDEF`: Definir o comportamento padrão do sinal
* `POSIX_SPAWN_SETSIGMASK`: Definir a máscara de sinal
* `POSIX_SPAWN_SETEXEC`: Executar no mesmo processo (como `execve` com mais opções)
* `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspenso
* `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sem ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar o Nano alocador do libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` em segmentos de dados
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fechar todas as descrições de arquivos em exec(2) por padrão
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatorizar os bits altos do slide ASLR

Além disso, `posix_spawn` permite especificar uma matriz de **`posix_spawnattr`** que controla alguns aspectos do processo gerado, e **`posix_spawn_file_actions`** para modificar o estado dos descritores.

Quando um processo morre, ele envia o **código de retorno para o processo pai** (se o pai morreu, o novo pai é o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()` e até que isso aconteça, o filho permanece em um estado zumbi onde ainda está listado, mas não consome recursos.

### PIDs

PIDs, identificadores de processo, identificam um processo único. No XNU, os **PIDs** são de **64 bits** aumentando monotonicamente e **nunca se repetem** (para evitar abusos).

### Grupos de Processos, Sessões e Coalizões

**Processos** podem ser inseridos em **grupos** para facilitar o manuseio deles. Por exemplo, comandos em um script de shell estarão no mesmo grupo de processos, então é possível **sinalizá-los juntos** usando kill, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são colocados dentro da sessão, a menos que iniciem sua própria sessão.

Coalition é outra forma de agrupar processos no Darwin. Um processo que ingressa em uma coalizão permite acessar recursos em pool, compartilhando um livro-razão ou enfrentando Jetsam. As coalizões têm diferentes papéis: Líder, serviço XPC, Extensão.

### Credenciais e Personas

Cada processo mantém **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível alterar o id do usuário e do grupo se o binário tiver o bit `setuid/setgid`.\
Existem várias funções para **definir novos uids/gids**.

A chamada de sistema **`persona`** fornece um **conjunto alternativo** de **credenciais**. Adotar uma persona assume seu uid, gid e associações de grupo **de uma vez**. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) é possível encontrar a struct:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Informações Básicas sobre Threads

1. **Threads POSIX (pthreads):** O macOS suporta threads POSIX (`pthreads`), que fazem parte de uma API de threads padrão para C/C++. A implementação de pthreads no macOS é encontrada em `/usr/lib/system/libsystem_pthread.dylib`, que vem do projeto `libpthread` publicamente disponível. Esta biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criando Threads:** A função `pthread_create()` é usada para criar novas threads. Internamente, esta função chama `bsdthread_create()`, que é uma chamada de sistema de nível mais baixo específica para o kernel XNU (o kernel no qual o macOS é baseado). Esta chamada de sistema recebe vários flags derivados de `pthread_attr` (atributos) que especificam o comportamento da thread, incluindo políticas de agendamento e tamanho da pilha.
* **Tamanho Padrão da Pilha:** O tamanho padrão da pilha para novas threads é de 512 KB, o que é suficiente para operações típicas, mas pode ser ajustado via atributos da thread se mais ou menos espaço for necessário.
3. **Inicialização da Thread:** A função `__pthread_init()` é crucial durante a configuração da thread, utilizando o argumento `env[]` para analisar variáveis de ambiente que podem incluir detalhes sobre a localização e tamanho da pilha.

#### Término de Threads no macOS

1. **Encerrando Threads:** As threads são tipicamente encerradas chamando `pthread_exit()`. Esta função permite que uma thread saia limparmente, realizando a limpeza necessária e permitindo que a thread envie um valor de retorno para qualquer thread que a esteja aguardando.
2. **Limpeza da Thread:** Ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada, que lida com a remoção de todas as estruturas de thread associadas. Ela desaloca as portas de thread Mach (Mach é o subsistema de comunicação no kernel XNU) e chama `bsdthread_terminate`, uma chamada de sistema que remove as estruturas de nível de kernel associadas à thread.

#### Mecanismos de Sincronização

Para gerenciar o acesso a recursos compartilhados e evitar condições de corrida, o macOS fornece vários primitivos de sincronização. Estes são críticos em ambientes de múltiplas threads para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
* **Mutex Regular (Assinatura: 0x4D555458):** Mutex padrão com uma pegada de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a assinatura).
* **Mutex Rápido (Assinatura: 0x4d55545A):** Semelhante a um mutex regular, mas otimizado para operações mais rápidas, também com 60 bytes de tamanho.
2. **Variáveis de Condição:**
* Usadas para aguardar que certas condições ocorram, com um tamanho de 44 bytes (40 bytes mais uma assinatura de 4 bytes).
* **Atributos de Variável de Condição (Assinatura: 0x434e4441):** Atributos de configuração para variáveis de condição, com 12 bytes de tamanho.
3. **Variável Once (Assinatura: 0x4f4e4345):**
* Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Travas de Leitura-Escrita:**
* Permitem múltiplos leitores ou um escritor por vez, facilitando o acesso eficiente a dados compartilhados.
* **Trava de Leitura-Escrita (Assinatura: 0x52574c4b):** Com tamanho de 196 bytes.
* **Atributos de Trava de Leitura-Escrita (Assinatura: 0x52574c41):** Atributos para travas de leitura-escrita, com 20 bytes de tamanho.

{% hint style="success" %}
Os últimos 4 bytes desses objetos são usados para detectar estouros.
{% endhint %}

### Variáveis Locais da Thread (TLV)

**Variáveis Locais da Thread (TLV)** no contexto de arquivos Mach-O (o formato para executáveis no macOS) são usadas para declarar variáveis específicas para **cada thread** em um aplicativo multithread. Isso garante que cada thread tenha sua própria instância separada de uma variável, fornecendo uma maneira de evitar conflitos e manter a integridade dos dados sem a necessidade de mecanismos explícitos de sincronização como mutexes.

Em C e linguagens relacionadas, você pode declarar uma variável local da thread usando a palavra-chave **`__thread`**. Veja como funciona no seu exemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este trecho define `tlv_var` como uma variável local de thread. Cada thread que executa este código terá sua própria `tlv_var`, e as alterações feitas por uma thread em `tlv_var` não afetarão `tlv_var` em outra thread.

No binário Mach-O, os dados relacionados às variáveis locais de thread são organizados em seções específicas:

- **`__DATA.__thread_vars`**: Esta seção contém metadados sobre as variáveis locais de thread, como seus tipos e status de inicialização.
- **`__DATA.__thread_bss`**: Esta seção é usada para variáveis locais de thread que não são inicializadas explicitamente. É uma parte da memória reservada para dados inicializados com zero.

O Mach-O também fornece uma API específica chamada **`tlv_atexit`** para gerenciar variáveis locais de thread quando uma thread termina. Esta API permite que você **registre destruidores** - funções especiais que limpam os dados locais da thread quando uma thread termina.

### Prioridades de Thread

Entender as prioridades de thread envolve observar como o sistema operacional decide quais threads executar e quando. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. Em sistemas macOS e Unix-like, isso é tratado usando conceitos como `nice`, `renice` e classes de Qualidade de Serviço (QoS).

#### Nice e Renice

1. **Nice:**
   - O valor `nice` de um processo é um número que afeta sua prioridade. Cada processo tem um valor `nice` variando de -20 (a maior prioridade) a 19 (a menor prioridade). O valor `nice` padrão quando um processo é criado é tipicamente 0.
   - Um valor `nice` mais baixo (mais próximo de -20) torna um processo mais "egoísta", dando-lhe mais tempo de CPU em comparação com outros processos com valores `nice` mais altos.
2. **Renice:**
   - `renice` é um comando usado para alterar o valor `nice` de um processo em execução. Isso pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo sua alocação de tempo de CPU com base em novos valores `nice`.
   - Por exemplo, se um processo precisa de mais recursos de CPU temporariamente, você pode diminuir seu valor `nice` usando `renice`.

#### Classes de Qualidade de Serviço (QoS)

As classes de QoS são uma abordagem mais moderna para lidar com as prioridades de thread, especialmente em sistemas como macOS que suportam o **Grand Central Dispatch (GCD)**. As classes de QoS permitem que os desenvolvedores **classifiquem** o trabalho em diferentes níveis com base em sua importância ou urgência. O macOS gerencia a priorização de threads automaticamente com base nessas classes de QoS:

1. **Interativo do Usuário:**
   - Esta classe é para tarefas que estão interagindo atualmente com o usuário ou exigem resultados imediatos para fornecer uma boa experiência ao usuário. Essas tarefas recebem a mais alta prioridade para manter a interface responsiva (por exemplo, animações ou manipulação de eventos).
2. **Iniciado pelo Usuário:**
   - Tarefas que o usuário inicia e espera resultados imediatos, como abrir um documento ou clicar em um botão que requer cálculos. Estas são de alta prioridade, mas abaixo do interativo do usuário.
3. **Utilitário:**
   - Essas tarefas são de longa duração e geralmente mostram um indicador de progresso (por exemplo, baixar arquivos, importar dados). Elas têm prioridade mais baixa do que tarefas iniciadas pelo usuário e não precisam ser concluídas imediatamente.
4. **Background:**
   - Esta classe é para tarefas que operam em segundo plano e não são visíveis para o usuário. Podem ser tarefas como indexação, sincronização ou backups. Elas têm a menor prioridade e impacto mínimo no desempenho do sistema.

Usando classes de QoS, os desenvolvedores não precisam gerenciar os números exatos de prioridade, mas sim se concentrar na natureza da tarefa, e o sistema otimiza os recursos da CPU de acordo.

Além disso, existem diferentes **políticas de agendamento de threads** que fluem para especificar um conjunto de parâmetros de agendamento que o agendador levará em consideração. Isso pode ser feito usando `thread_policy_[set/get]`. Isso pode ser útil em ataques de condição de corrida.
### Injeção de Python

Se a variável de ambiente **`PYTHONINSPECT`** estiver definida, o processo python entrará em um cli python assim que terminar. Também é possível usar **`PYTHONSTARTUP`** para indicar um script python a ser executado no início de uma sessão interativa.\
No entanto, observe que o script **`PYTHONSTARTUP`** não será executado quando **`PYTHONINSPECT`** criar a sessão interativa.

Outras variáveis de ambiente como **`PYTHONPATH`** e **`PYTHONHOME`** também podem ser úteis para fazer um comando python executar código arbitrário.

Observe que executáveis compilados com **`pyinstaller`** não usarão essas variáveis ambientais, mesmo que estejam sendo executados usando um python incorporado.

{% hint style="danger" %}
No geral, não consegui encontrar uma maneira de fazer o python executar código arbitrário abusando de variáveis de ambiente.\
No entanto, a maioria das pessoas instala o python usando o **Hombrew**, que instalará o python em uma **localização gravável** para o usuário administrador padrão. Você pode sequestrá-lo com algo como:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Mesmo o **root** executará este código ao executar python.

## Detecção

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) é um aplicativo de código aberto que pode **detectar e bloquear ações de injeção de processo**:

* Usando **Variáveis Ambientais**: Ele monitorará a presença de qualquer uma das seguintes variáveis ambientais: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
* Usando chamadas de **`task_for_pid`**: Para encontrar quando um processo deseja obter a **porta de tarefa de outro** que permite injetar código no processo.
* Parâmetros de aplicativos **Electron**: Alguém pode usar os argumentos de linha de comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** para iniciar um aplicativo Electron no modo de depuração e, assim, injetar código nele.
* Usando **links simbólicos** ou **hardlinks**: Tipicamente, o abuso mais comum é **colocar um link com nossos privilégios de usuário** e **apontá-lo para uma localização de privilégio mais alto**. A detecção é muito simples para ambos, hardlinks e links simbólicos. Se o processo que cria o link tiver um **nível de privilégio diferente** do arquivo de destino, criamos um **alerta**. Infelizmente, no caso de links simbólicos, o bloqueio não é possível, pois não temos informações sobre o destino do link antes da criação. Esta é uma limitação do framework EndpointSecuriy da Apple.

### Chamadas feitas por outros processos

Neste [**post do blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) você pode encontrar como é possível usar a função **`task_name_for_pid`** para obter informações sobre outros **processos injetando código em um processo** e então obter informações sobre esse outro processo.

Observe que para chamar essa função você precisa ter o **mesmo uid** que o processo em execução ou ser **root** (e ela retorna informações sobre o processo, não uma maneira de injetar código).

## Referências

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
