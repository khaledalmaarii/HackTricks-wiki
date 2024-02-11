# Bewapening van Distroless

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks in PDF wilt downloaden**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit je aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Wat is Distroless

Een distroless-container is een type container dat **alleen de noodzakelijke afhankelijkheden bevat om een specifieke toepassing uit te voeren**, zonder extra software of tools die niet nodig zijn. Deze containers zijn ontworpen om zo **lichtgewicht** en **veilig** mogelijk te zijn en ze streven ernaar om **het aanvalsoppervlak te minimaliseren** door onnodige componenten te verwijderen.

Distroless-containers worden vaak gebruikt in **productieomgevingen waar beveiliging en betrouwbaarheid van groot belang zijn**.

Enkele **voorbeelden** van **distroless-containers** zijn:

* Aangeboden door **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Aangeboden door **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Bewapening van Distroless

Het doel van het bewapenen van een distroless-container is om in staat te zijn **willekeurige binaries en payloads uit te voeren, zelfs met de beperkingen** die worden opgelegd door **distroless** (gebrek aan gangbare binaries in het systeem) en ook beveiligingsmaatregelen die vaak worden aangetroffen in containers, zoals **alleen-lezen** of **niet-uitvoeren** in `/dev/shm`.

### Via het geheugen

Komt op een gegeven moment in 2023...

### Via bestaande binaries

#### openssl

****[**In deze post**](https://www.form3.tech/engineering/content/exploiting-distroless-images) wordt uitgelegd dat de binary **`openssl`** vaak wordt aangetroffen in deze containers, mogelijk omdat deze **nodig** is voor de software die binnen de container wordt uitgevoerd.

Door misbruik te maken van de **`openssl`** binary is het mogelijk om **willekeurige dingen uit te voeren**.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks in PDF wilt downloaden**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit je aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
