# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha numa **empresa de cibersegurança**? Quer ver a sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o repositório [hacktricks](https://github.com/carlospolop/hacktricks) e o repositório [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Variáveis de Identificação do Usuário

- **`ruid`**: O **ID do usuário real** denota o usuário que iniciou o processo.
- **`euid`**: Conhecido como **ID do usuário efetivo**, representa a identidade do usuário utilizada pelo sistema para determinar os privilégios do processo. Geralmente, `euid` reflete `ruid`, exceto em casos como a execução de um binário SetUID, onde `euid` assume a identidade do proprietário do arquivo, concedendo permissões operacionais específicas.
- **`suid`**: Este **ID do usuário salvo** é crucial quando um processo de alto privilégio (tipicamente executado como root) precisa temporariamente renunciar aos seus privilégios para realizar certas tarefas, para depois recuperar seu status elevado inicial.

#### Nota Importante
Um processo não operando sob root só pode modificar seu `euid` para corresponder ao `ruid`, `euid` ou `suid` atual.

### Entendendo as Funções set*uid

- **`setuid`**: Ao contrário do que se pode assumir inicialmente, `setuid` modifica principalmente `euid` em vez de `ruid`. Especificamente, para processos privilegiados, alinha `ruid`, `euid` e `suid` com o usuário especificado, frequentemente root, solidificando efetivamente esses IDs devido ao `suid` sobreposto. Detalhes podem ser encontrados na [página do manual setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** e **`setresuid`**: Estas funções permitem o ajuste matizado de `ruid`, `euid` e `suid`. No entanto, suas capacidades dependem do nível de privilégio do processo. Para processos não-root, as modificações são restritas aos valores atuais de `ruid`, `euid` e `suid`. Em contraste, processos root ou aqueles com a capacidade `CAP_SETUID` podem atribuir valores arbitrários a esses IDs. Mais informações podem ser obtidas na [página do manual setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) e na [página do manual setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Essas funcionalidades são projetadas não como um mecanismo de segurança, mas para facilitar o fluxo operacional pretendido, como quando um programa adota a identidade de outro usuário alterando seu ID de usuário efetivo.

Notavelmente, enquanto `setuid` pode ser uma escolha comum para elevação de privilégio para root (já que alinha todos os IDs para root), diferenciar entre essas funções é crucial para entender e manipular comportamentos de ID de usuário em diferentes cenários.

### Mecanismos de Execução de Programas no Linux

#### **Chamada de Sistema `execve`**
- **Funcionalidade**: `execve` inicia um programa, determinado pelo primeiro argumento. Aceita dois argumentos de array, `argv` para argumentos e `envp` para o ambiente.
- **Comportamento**: Mantém o espaço de memória do chamador, mas atualiza a pilha, o heap e os segmentos de dados. O código do programa é substituído pelo novo programa.
- **Preservação do ID do Usuário**:
- `ruid`, `euid` e IDs de grupo suplementares permanecem inalterados.
- `euid` pode ter mudanças sutis se o novo programa tiver o bit SetUID definido.
- `suid` é atualizado a partir do `euid` após a execução.
- **Documentação**: Informações detalhadas podem ser encontradas na [página do manual `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Função `system`**
- **Funcionalidade**: Diferente de `execve`, `system` cria um processo filho usando `fork` e executa um comando dentro desse processo filho usando `execl`.
- **Execução de Comando**: Executa o comando via `sh` com `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamento**: Como `execl` é uma forma de `execve`, opera de maneira semelhante, mas no contexto de um novo processo filho.
- **Documentação**: Mais insights podem ser obtidos na [página do manual `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamento do `bash` e `sh` com SUID**
- **`bash`**:
- Possui uma opção `-p` que influencia o tratamento de `euid` e `ruid`.
- Sem `-p`, `bash` define `euid` para `ruid` se inicialmente forem diferentes.
- Com `-p`, o `euid` inicial é preservado.
- Mais detalhes podem ser encontrados na [página do manual `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Não possui um mecanismo semelhante ao `-p` do `bash`.
- O comportamento em relação aos IDs de usuário não é explicitamente mencionado, exceto sob a opção `-i`, que enfatiza a preservação da igualdade de `euid` e `ruid`.
- Informações adicionais estão disponíveis na [página do manual `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Esses mecanismos, distintos em sua operação, oferecem uma gama versátil de opções para executar e transitar entre programas, com nuances específicas em como os IDs de usuário são gerenciados e preservados.

### Testando Comportamentos de ID de Usuário em Execuções

Exemplos retirados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, confira para mais informações

#### Caso 1: Usando `setuid` com `system`

**Objetivo**: Entender o efeito de `setuid` em combinação com `system` e `bash` como `sh`.

**Código C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilação e Permissões:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* `ruid` e `euid` começam como 99 (nobody) e 1000 (frank) respectivamente.
* `setuid` alinha ambos para 1000.
* `system` executa `/bin/bash -c id` devido ao symlink de sh para bash.
* `bash`, sem `-p`, ajusta `euid` para corresponder a `ruid`, resultando em ambos sendo 99 (nobody).

#### Caso 2: Usando setreuid com system

**Código C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilação e Permissões:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* `setreuid` define tanto ruid quanto euid para 1000.
* `system` invoca bash, que mantém os IDs de usuário devido à igualdade deles, operando efetivamente como frank.

#### Caso 3: Usando setuid com execve
Objetivo: Explorar a interação entre setuid e execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* `ruid` permanece 99, mas o `euid` é definido como 1000, de acordo com o efeito do setuid.

**Exemplo de Código C 2 (Chamando Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* Embora `euid` seja definido como 1000 por `setuid`, `bash` redefine euid para `ruid` (99) devido à ausência de `-p`.

**Exemplo de Código C 3 (Usando bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
# Referências
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
