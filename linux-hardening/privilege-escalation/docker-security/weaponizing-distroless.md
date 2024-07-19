# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Impara & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Controlla il [**sottoscrizione su github.cm/sorsarlosp!**
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Condividi trucchi inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## What is Distroless

Un container distroless è un tipo di container che **contiene solo le dipendenze necessarie per eseguire un'applicazione specifica**, senza software o strumenti aggiuntivi non richiesti. Questi container sono progettati per essere il più **leggeri** e **sicuri** possibile e mirano a **minimizzare la superficie di attacco** rimuovendo componenti non necessari.

I container distroless sono spesso utilizzati in **ambienti di produzione dove la sicurezza e l'affidabilità sono fondamentali**.

Alcuni **esempi** di **container distroless** sono:

* Forniti da **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Forniti da **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

L'obiettivo di armare un container distroless è essere in grado di **eseguire binari e payload arbitrari anche con le limitazioni** imposte da **distroless** (mancanza di binari comuni nel sistema) e anche protezioni comunemente trovate nei container come **sola lettura** o **nessuna esecuzione** in `/dev/shm`.

### Through memory

In arrivo a un certo punto del 2023...

### Via Existing binaries

#### openssl

****[**In questo post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) si spiega che il binario **`openssl`** è frequentemente trovato in questi container, potenzialmente perché è **necessario** dal software che verrà eseguito all'interno del container.
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Impara & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Controlla il [**sottoscrizione su github.cm/sorsarlosp!**
* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Unisciti 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
