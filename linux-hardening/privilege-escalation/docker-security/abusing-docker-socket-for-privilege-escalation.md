# Abusando do Socket Docker para Escalação de Privilégios

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Há ocasiões em que você tem apenas **acesso ao socket do docker** e deseja usá-lo para **escalar privilégios**. Algumas ações podem ser muito suspeitas e você pode querer evitá-las, então aqui você pode encontrar diferentes flags que podem ser úteis para escalar privilégios:

### Via montagem

Você pode **montar** diferentes partes do **sistema de arquivos** em um contêiner executado como root e **acessá-los**.\
Você também pode **abusar de uma montagem para escalar privilégios** dentro do contêiner.

* **`-v /:/host`** -> Monta o sistema de arquivos do host no contêiner para que você possa **ler o sistema de arquivos do host.**
* Se você quer **sentir como se estivesse no host** mas estando no contêiner, você poderia desativar outros mecanismos de defesa usando flags como:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Este é semelhante ao método anterior, mas aqui estamos **montando o disco do dispositivo**. Então, dentro do contêiner execute `mount /dev/sda1 /mnt` e você pode **acessar** o **sistema de arquivos do host** em `/mnt`
* Execute `fdisk -l` no host para encontrar o dispositivo `</dev/sda1>` para montar
* **`-v /tmp:/host`** -> Se por algum motivo você pode **apenas montar algum diretório** do host e você tem acesso dentro do host. Monte-o e crie um **`/bin/bash`** com **suid** no diretório montado para que você possa **executá-lo a partir do host e escalar para root**.

{% hint style="info" %}
Note que talvez você não possa montar a pasta `/tmp`, mas você pode montar um **diretório gravável diferente**. Você pode encontrar diretórios graváveis usando: `find / -writable -type d 2>/dev/null`

**Note que nem todos os diretórios em uma máquina linux suportarão o bit suid!** Para verificar quais diretórios suportam o bit suid, execute `mount | grep -v "nosuid"`. Por exemplo, geralmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` não suportam o bit suid.

Note também que se você pode **montar `/etc`** ou qualquer outro diretório **contendo arquivos de configuração**, você pode alterá-los a partir do contêiner docker como root para **abusar deles no host** e escalar privilégios (talvez modificando `/etc/shadow`)
{% endhint %}

### Escapando do contêiner

* **`--privileged`** -> Com esta flag você [remove toda a isolação do contêiner](docker-privileged.md#what-affects). Confira técnicas para [escapar de contêineres privilegiados como root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Para [escalar abusando de capacidades](../linux-capabilities.md), **conceda essa capacidade ao contêiner** e desative outros métodos de proteção que possam impedir que o exploit funcione.

### Curl

Nesta página discutimos maneiras de escalar privilégios usando flags do docker, você pode encontrar **maneiras de abusar desses métodos usando o comando curl** na página:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
