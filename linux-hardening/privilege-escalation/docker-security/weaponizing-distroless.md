# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Leer & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Kontroleer die [**subskripsie**](https://github.com/sponsors/carlospolop)!  
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Deel hacks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Wat is Distroless

'n Distroless-container is 'n tipe container wat **slegs die nodige afhanklikhede bevat om 'n spesifieke toepassing te laat loop**, sonder enige bykomende sagteware of gereedskap wat nie benodig word nie. Hierdie containers is ontwerp om so **liggewig** en **veilig** as moontlik te wees, en hulle poog om die **aanvaloppervlak te minimaliseer** deur enige onnodige komponente te verwyder.

Distroless-containers word dikwels in **produksie-omgewings gebruik waar veiligheid en betroubaarheid van die grootste belang is**.

Sommige **voorbeelde** van **distroless-containers** is:

* Verskaf deur **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Verskaf deur **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Die doel van die wapen van 'n distroless-container is om in staat te wees om **arbitraire binêre en payloads uit te voer selfs met die beperkings** wat deur **distroless** impliseer (gebrek aan algemene binêre in die stelsel) en ook beskermings wat algemeen in containers voorkom soos **lees-slegs** of **geen-uitvoering** in `/dev/shm`.

### Deur geheue

Kom op 'n sekere punt in 2023...

### Via Bestaande binêre

#### openssl

****[**In hierdie pos,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) word verduidelik dat die binêre **`openssl`** gereeld in hierdie containers gevind word, moontlik omdat dit **benodig** word deur die sagteware wat binne die container gaan loop.
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Leer & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Kontroleer die [**subskripsie**](https://github.com/sponsors/carlospolop)!  
* Kontroleer die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
