<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Integridade do Firmware

Os **firmwares personalizados e/ou binários compilados podem ser carregados para explorar falhas de integridade ou verificação de assinatura**. Os seguintes passos podem ser seguidos para compilar um backdoor bind shell:

1. O firmware pode ser extraído usando o firmware-mod-kit (FMK).
2. A arquitetura do firmware de destino e a ordem dos bytes devem ser identificadas.
3. Um compilador cruzado pode ser construído usando o Buildroot ou outros métodos adequados para o ambiente.
4. O backdoor pode ser construído usando o compilador cruzado.
5. O backdoor pode ser copiado para o diretório /usr/bin do firmware extraído.
6. O binário QEMU apropriado pode ser copiado para o rootfs do firmware extraído.
7. O backdoor pode ser emulado usando chroot e QEMU.
8. O backdoor pode ser acessado via netcat.
9. O binário QEMU deve ser removido do rootfs do firmware extraído.
10. O firmware modificado pode ser empacotado novamente usando o FMK.
11. O firmware com backdoor pode ser testado emulando-o com o firmware analysis toolkit (FAT) e conectando-se ao IP e porta do backdoor alvo usando netcat.

Se um shell de root já foi obtido por meio de análise dinâmica, manipulação de bootloader ou testes de segurança de hardware, binários maliciosos pré-compilados, como implantes ou shells reversos, podem ser executados. Ferramentas automatizadas de payload/implante como o framework Metasploit e 'msfvenom' podem ser aproveitadas seguindo os seguintes passos:

1. A arquitetura do firmware de destino e a ordem dos bytes devem ser identificadas.
2. O Msfvenom pode ser usado para especificar o payload de destino, IP do host atacante, número da porta de escuta, tipo de arquivo, arquitetura, plataforma e o arquivo de saída.
3. O payload pode ser transferido para o dispositivo comprometido e garantido que tenha permissões de execução.
4. O Metasploit pode ser preparado para lidar com solicitações recebidas iniciando o msfconsole e configurando as configurações de acordo com o payload.
5. O shell reverso meterpreter pode ser executado no dispositivo comprometido.
6. As sessões do meterpreter podem ser monitoradas à medida que são abertas.
7. Atividades pós-exploração podem ser realizadas.

Se possível, vulnerabilidades dentro de scripts de inicialização podem ser exploradas para obter acesso persistente a um dispositivo através de reinicializações. Essas vulnerabilidades surgem quando os scripts de inicialização fazem referência, [link simbolicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dependem de código localizado em locais montados não confiáveis, como cartões SD e volumes flash usados para armazenar dados fora dos sistemas de arquivos raiz.

## Referências
* Para mais informações, consulte [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
