{% hint style="success" %}
Naučite i vežbajte AWS hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


Ako imate pcap fajl USB konekcije sa puno prekida, verovatno je u pitanju USB tastatura konekcija.

Wireshark filter poput ovog može biti koristan: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Važno je znati da se podaci koji počinju sa "02" pritiskaju koristeći shift.

Možete pročitati više informacija i pronaći neke skripte o tome kako analizirati ovo na:

* [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
* [https://github.com/tanc7/HacktheBox\_Deadly\_Arthropod\_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)



{% hint style="success" %}
Naučite i vežbajte AWS hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
