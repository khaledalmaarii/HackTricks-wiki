# Aplicações Defensivas para macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver a sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitora cada conexão feita por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexões silenciosamente e alerta), irá **mostrar um alerta** toda vez que uma nova conexão for estabelecida. Também possui uma interface gráfica muito boa para ver todas essas informações.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall da Objective-See. É um firewall básico que alertará sobre conexões suspeitas (tem uma interface gráfica, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de Persistência

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicativo da Objective-See que procura em vários locais onde **malwares poderiam estar persistindo** (é uma ferramenta de uso único, não um serviço de monitoramento).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Semelhante ao KnockKnock, monitora processos que geram persistência.

## Detecção de Keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicativo da Objective-See para encontrar **keyloggers** que instalam "event taps" de teclado.

## Detecção de Ransomware

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): Aplicativo da Objective-See para detectar ações de **criptografia de arquivos**.

## Detecção de Mic & Webcam

* [**OverSight**](https://objective-see.org/products/oversight.html): Aplicativo da Objective-See para detectar **aplicativos que começam a usar a webcam e o microfone.**

## Detecção de Injeção de Processos

* [**Shield**](https://theevilbit.github.io/shield/): Aplicativo que **detecta diferentes técnicas de injeção de processos**.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver a sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
