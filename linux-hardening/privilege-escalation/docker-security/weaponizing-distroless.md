# Weaponizing Distroless

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Šta je Distroless

Distroless kontejner je vrsta kontejnera koja **sadrži samo neophodne zavisnosti za pokretanje specifične aplikacije**, bez dodatnog softvera ili alata koji nisu potrebni. Ovi kontejneri su dizajnirani da budu što **lakši** i **bezbedniji**, i imaju za cilj da **minimizuju površinu napada** uklanjanjem nepotrebnih komponenti.

Distroless kontejneri se često koriste u **produkcijskim okruženjima gde su bezbednost i pouzdanost od suštinskog značaja**.

Neki **primeri** **distroless kontejnera** su:

* Pruženi od strane **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Pruženi od strane **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Cilj oružavanja distroless kontejnera je da se može **izvršiti proizvoljni binarni kod i payload-ovi čak i sa ograničenjima** koja podrazumeva **distroless** (nedostatak uobičajenih binarnih datoteka u sistemu) i takođe zaštitama koje se obično nalaze u kontejnerima kao što su **samo za čitanje** ili **bez izvršavanja** u `/dev/shm`.

### Kroz memoriju

Dolazi u nekom trenutku 2023...

### Putem postojećih binarnih datoteka

#### openssl

****[**U ovom postu,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) objašnjeno je da se binarna datoteka **`openssl`** često nalazi u ovim kontejnerima, potencijalno zato što je **potrebna** softveru koji će se pokretati unutar kontejnera.
