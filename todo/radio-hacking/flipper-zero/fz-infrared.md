# FZ - Infrared

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

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Za više informacija o tome kako funkcioniše infracrveno, proverite:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper koristi digitalni IR prijemnik TSOP, koji **omogućava presretanje signala sa IR daljinskih upravljača**. Postoje neki **smartfoni** poput Xiaomija, koji takođe imaju IR port, ali imajte na umu da **većina njih može samo da prenosi** signale i **nije u stanju da ih primi**.

Flipperov infracrveni **prijemnik je prilično osetljiv**. Možete čak i **uhvatiti signal** dok se nalazite **negde između** daljinskog upravljača i televizora. Usmeravanje daljinskog upravljača direktno na Flipperov IR port nije neophodno. Ovo je korisno kada neko menja kanale dok stoji blizu televizora, a i vi i Flipper ste na određenoj udaljenosti.

Kako se **dekodiranje infracrvenog** signala dešava na **softverskoj** strani, Flipper Zero potencijalno podržava **prijem i prenos bilo kojih IR daljinskih kodova**. U slučaju **nepoznatih** protokola koji nisu mogli biti prepoznati - on **snima i reprodukuje** sirovi signal tačno onako kako je primljen.

## Actions

### Universal Remotes

Flipper Zero može se koristiti kao **univerzalni daljinski upravljač za kontrolu bilo kog televizora, klima uređaja ili medijskog centra**. U ovom režimu, Flipper **bruteforcuje** sve **poznate kodove** svih podržanih proizvođača **prema rečniku sa SD kartice**. Nije potrebno odabrati određeni daljinski upravljač da biste isključili televizor u restoranu.

Dovoljno je pritisnuti dugme za napajanje u režimu Univerzalnog daljinskog upravljača, i Flipper će **uzastopno slati "Power Off"** komande svih televizora koje poznaje: Sony, Samsung, Panasonic... i tako dalje. Kada televizor primi svoj signal, reagovaće i isključiti se.

Takav brute-force zahteva vreme. Što je rečnik veći, to će duže trajati da se završi. Nemoguće je saznati koji signal je tačno televizor prepoznao jer nema povratne informacije od televizora.

### Learn New Remote

Moguće je **uhvatiti infracrveni signal** sa Flipper Zero. Ako **pronađe signal u bazi podataka**, Flipper će automatski **znati koji je to uređaj** i omogućiti vam da komunicirate s njim.\
Ako ne, Flipper može **sačuvati** **signal** i omogućiti vam da ga **ponovo reprodukujete**.

## References

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
