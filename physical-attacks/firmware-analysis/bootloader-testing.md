<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


Copiado de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Ao modificar a inicialização do dispositivo e bootloaders como U-boot, tente o seguinte:

* Tente acessar o shell interpretador do bootloader pressionando "0", espaço ou outros "códigos mágicos" identificados durante a inicialização.
* Modifique configurações para executar um comando shell, como adicionar '`init=/bin/sh`' ao final dos argumentos de inicialização
* `#printenv`
* `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh`
* `#saveenv`
* `#boot`
* Configure um servidor tftp para carregar imagens pela rede localmente a partir de sua estação de trabalho. Garanta que o dispositivo tenha acesso à rede.
* `#setenv ipaddr 192.168.2.2 #IP local do dispositivo`
* `#setenv serverip 192.168.2.1 #IP do servidor tftp`
* `#saveenv`
* `#reset`
* `#ping 192.168.2.1 #verifique se o acesso à rede está disponível`
* `#tftp ${loadaddr} uImage-3.6.35 #loadaddr recebe dois argumentos: o endereço para carregar o arquivo e o nome do arquivo da imagem no servidor TFTP`
* Use `ubootwrite.py` para escrever a imagem do uboot e enviar um firmware modificado para obter root
* Verifique se recursos de depuração estão habilitados, como:
* registro detalhado
* carregamento de kernels arbitrários
* inicialização a partir de fontes não confiáveis
* \*Use cautela: Conecte um pino ao terra, observe a sequência de inicialização do dispositivo, antes da descompressão do kernel, faça um curto/conecte o pino aterrado a um pino de dados (DO) em um chip de flash SPI
* \*Use cautela: Conecte um pino ao terra, observe a sequência de inicialização do dispositivo, antes da descompressão do kernel, faça um curto/conecte o pino aterrado aos pinos 8 e 9 do chip de flash NAND no momento em que o U-boot descomprime a imagem UBI
* \*Revise a ficha técnica do chip de flash NAND antes de fazer curto nos pinos
* Configure um servidor DHCP malicioso com parâmetros maliciosos como entrada para um dispositivo durante uma inicialização PXE
* Use o servidor auxiliar DHCP do Metasploit (MSF) e modifique o parâmetro '`FILENAME`' com comandos de injeção de comando como `‘a";/bin/sh;#’` para testar a validação de entrada para procedimentos de inicialização do dispositivo.

\*Teste de segurança de hardware


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
