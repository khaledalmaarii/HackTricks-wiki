# Armamento do Distroless

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## O que é Distroless

Um container distroless é um tipo de container que **contém apenas as dependências necessárias para executar uma aplicação específica**, sem nenhum software ou ferramenta adicional que não seja necessário. Esses containers são projetados para serem o mais **leves** e **seguros** possível, e visam **minimizar a superfície de ataque** removendo quaisquer componentes desnecessários.

Containers distroless são frequentemente usados em **ambientes de produção onde segurança e confiabilidade são primordiais**.

Alguns **exemplos** de **containers distroless** são:

* Fornecidos pelo **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Fornecidos pela **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armamento do Distroless

O objetivo de armar um container distroless é ser capaz de **executar binários e payloads arbitrários mesmo com as limitações** implicadas pelo **distroless** (falta de binários comuns no sistema) e também proteções comumente encontradas em containers, como **somente leitura** ou **não-execução** em `/dev/shm`.

### Através da memória

Chegando em algum momento de 2023...

### Via Binários Existentes

#### openssl

****[**Neste post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) é explicado que o binário **`openssl`** é frequentemente encontrado nesses containers, potencialmente porque é **necessário** pelo software que vai ser executado dentro do container.

Abusar do binário **`openssl`** é possível para **executar coisas arbitrariamente**.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
