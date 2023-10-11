# Aplicativos de Defesa para macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Ele monitorará todas as conexões feitas por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexões silenciosamente e alertar), ele **mostrará um alerta** toda vez que uma nova conexão for estabelecida. Ele também possui uma interface gráfica muito boa para visualizar todas essas informações.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall da Objective-See. Este é um firewall básico que irá alertá-lo sobre conexões suspeitas (ele possui uma interface gráfica, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de Persistência

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicativo da Objective-See que procurará em vários locais onde **malwares podem estar persistindo** (é uma ferramenta de execução única, não um serviço de monitoramento).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Similar ao KnockKnock, monitora processos que geram persistência.

## Detecção de Keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicativo da Objective-See para encontrar **keyloggers** que instalam "event taps" no teclado.

## Detecção de Ransomware

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): Aplicativo da Objective-See para detectar ações de **criptografia de arquivos**.

## Detecção de Microfone e Webcam

* [**OverSight**](https://objective-see.org/products/oversight.html): Aplicativo da Objective-See para detectar **aplicativos que começam a usar a webcam e o microfone**.

## Detecção de Injeção de Processos

* [**Shield**](https://theevilbit.github.io/shield/): Aplicativo que **detecta diferentes técnicas de injeção de processos**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
