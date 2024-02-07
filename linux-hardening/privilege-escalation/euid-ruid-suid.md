# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Variáveis de Identificação do Usuário

- **`ruid`**: O **ID de usuário real** denota o usuário que iniciou o processo.
- **`euid`**: Conhecido como **ID de usuário efetivo**, representa a identidade do usuário utilizada pelo sistema para determinar os privilégios do processo. Geralmente, `euid` espelha `ruid`, exceto em casos como a execução de um binário SetUID, onde `euid` assume a identidade do proprietário do arquivo, concedendo permissões operacionais específicas.
- **`suid`**: Este **ID de usuário salvo** é crucial quando um processo de alta privilégio (geralmente em execução como root) precisa temporariamente renunciar aos seus privilégios para realizar determinadas tarefas, apenas para posteriormente recuperar seu status elevado inicial.

#### Nota Importante
Um processo que não opera sob root só pode modificar seu `euid` para corresponder ao `ruid`, `euid` ou `suid` atual.

### Compreensão das Funções set*uid

- **`setuid`**: Contrariamente às suposições iniciais, `setuid` modifica principalmente `euid` em vez de `ruid`. Especificamente, para processos privilegiados, alinha `ruid`, `euid` e `suid` com o usuário especificado, frequentemente root, solidificando efetivamente esses IDs devido à substituição de `suid`. Informações detalhadas podem ser encontradas na [página do manual do setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** e **`setresuid`**: Essas funções permitem o ajuste sutil de `ruid`, `euid` e `suid`. No entanto, suas capacidades dependem do nível de privilégio do processo. Para processos não root, as modificações são restritas aos valores atuais de `ruid`, `euid` e `suid`. Em contraste, processos root ou aqueles com a capacidade `CAP_SETUID` podem atribuir valores arbitrários a esses IDs. Mais informações podem ser obtidas na [página do manual do setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) e na [página do manual do setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Essas funcionalidades não são projetadas como um mecanismo de segurança, mas sim para facilitar o fluxo operacional pretendido, como quando um programa adota a identidade de outro usuário alterando seu ID de usuário efetivo.

É importante notar que, embora `setuid` possa ser comum para a elevação de privilégios para root (pois alinha todos os IDs a root), diferenciar entre essas funções é crucial para entender e manipular os comportamentos de ID de usuário em cenários variados.

### Mecanismos de Execução de Programas no Linux

#### Chamada de Sistema **`execve`**
- **Funcionalidade**: `execve` inicia um programa, determinado pelo primeiro argumento. Ele recebe dois argumentos de array, `argv` para argumentos e `envp` para o ambiente.
- **Comportamento**: Mantém o espaço de memória do chamador, mas atualiza a pilha, heap e segmentos de dados. O código do programa é substituído pelo novo programa.
- **Preservação do ID de Usuário**:
- `ruid`, `euid` e IDs de grupo suplementares permanecem inalterados.
- `euid` pode ter mudanças sutis se o novo programa tiver o bit SetUID definido.
- `suid` é atualizado a partir de `euid` pós-execução.
- **Documentação**: Informações detalhadas podem ser encontradas na [página do manual do `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### Função **`system`**
- **Funcionalidade**: Ao contrário de `execve`, `system` cria um processo filho usando `fork` e executa um comando dentro desse processo filho usando `execl`.
- **Execução do Comando**: Executa o comando via `sh` com `execl("/bin/sh", "sh", "-c", comando, (char *) NULL);`.
- **Comportamento**: Como `execl` é uma forma de `execve`, opera de forma semelhante, mas no contexto de um novo processo filho.
- **Documentação**: Mais insights podem ser obtidos na [página do manual do `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### Comportamento de `bash` e `sh` com SUID
- **`bash`**:
- Possui uma opção `-p` que influencia como `euid` e `ruid` são tratados.
- Sem `-p`, `bash` define `euid` como `ruid` se inicialmente forem diferentes.
- Com `-p`, o `euid` inicial é preservado.
- Mais detalhes podem ser encontrados na [página do manual do `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Não possui um mecanismo semelhante ao `-p` no `bash`.
- O comportamento em relação aos IDs de usuário não é mencionado explicitamente, exceto sob a opção `-i`, enfatizando a preservação da igualdade de `euid` e `ruid`.
- Informações adicionais estão disponíveis na [página do manual do `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Esses mecanismos, distintos em sua operação, oferecem uma ampla gama de opções para executar e transitar entre programas, com nuances específicas na forma como os IDs de usuário são gerenciados e preservados.

### Testando Comportamentos de ID de Usuário em Execuções

Exemplos retirados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, verifique para mais informações

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

- `ruid` e `euid` começam como 99 (nobody) e 1000 (frank) respectivamente.
- `setuid` alinha ambos para 1000.
- `system` executa `/bin/bash -c id` devido ao symlink de sh para bash.
- `bash`, sem `-p`, ajusta `euid` para corresponder a `ruid`, resultando em ambos sendo 99 (nobody).

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

* `setreuid` define tanto o ruid quanto o euid como 1000.
* `system` invoca o bash, que mantém os IDs de usuário devido à sua igualdade, operando efetivamente como frank.

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

* `ruid` permanece 99, mas `euid` é definido como 1000, de acordo com o efeito do `setuid`.

**Exemplo de Código C 2 (Chamando o Bash):**
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

* Embora `euid` seja definido como 1000 por `setuid`, o `bash` redefine o euid para `ruid` (99) devido à ausência de `-p`.

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

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me no** **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
