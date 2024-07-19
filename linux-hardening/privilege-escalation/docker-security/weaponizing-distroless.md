# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Proverite [**subsrippangithub.cm/sorsarlosp!**
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Delite trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Šta je Distroless

Distroless kontejner je tip kontejnera koji **sadrži samo neophodne zavisnosti za pokretanje specifične aplikacije**, bez dodatnog softvera ili alata koji nisu potrebni. Ovi kontejneri su dizajnirani da budu što **lakši** i **bezbedniji**, i imaju za cilj da **minimizuju površinu napada** uklanjanjem nepotrebnih komponenti.

Distroless kontejneri se često koriste u **produžnim okruženjima gde su bezbednost i pouzdanost od suštinskog značaja**.

Neki **primeri** **distroless kontejnera** su:

* Obebedili **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Obebedili **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Cilj oružavanja distroless kontejnera je da se može **izvršiti proizvoljni binarni kod i payload-ovi čak i sa ograničenjima** koja podrazumeva **distroless** (nedostatak uobičajenih binarnih datoteka u sistemu) i takođe zaštite koje se obično nalaze u kontejnerima kao što su **samo za čitanje** ili **bez izvršavanja** u `/dev/shm`.

### Kroz memoriju

Dolazi u nekom trenutku 2023...

### Putem postojećih binarnih datoteka

#### openssl

****[**U ovom postu,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) objašnjeno je da se binarna datoteka **`openssl`** često nalazi u ovim kontejnerima, potencijalno zato što je **potrebna** softveru koji će se pokretati unutar kontejnera.
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Proverite [**subsrippangithub.cm/sorsarlosp!**
* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Pridružite se 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
