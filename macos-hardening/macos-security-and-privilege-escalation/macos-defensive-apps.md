# Aplicativos de Defesa para macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Especialista Red Team AWS do HackTricks)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Ele irá monitorar cada conexão feita por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexão silenciosamente e alerta), ele **mostrará um alerta** toda vez que uma nova conexão for estabelecida. Ele também possui uma GUI muito boa para ver todas essas informações.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall da Objective-See. Este é um firewall básico que irá alertá-lo para conexões suspeitas (ele possui uma GUI, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de Persistência

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicativo da Objective-See que irá procurar em vários locais onde **malwares podem estar persistindo** (é uma ferramenta de execução única, não um serviço de monitoramento).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Similar ao KnockKnock, monitorando processos que geram persistência.

## Detecção de Keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicativo da Objective-See para encontrar **keyloggers** que instalam "event taps" de teclado.

## Detecção de Ransomware

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): Aplicativo da Objective-See para detectar ações de **criptografia de arquivos**.

## Detecção de Microfone e Webcam

* [**OverSight**](https://objective-see.org/products/oversight.html): Aplicativo da Objective-See para detectar **aplicativos que começam a usar a webcam e o microfone**.

## Detecção de Injeção de Processos

* [**Shield**](https://theevilbit.github.io/shield/): Aplicativo que **detecta diferentes técnicas de injeção de processos**.
