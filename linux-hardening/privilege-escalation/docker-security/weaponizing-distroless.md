# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Aprende & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Verifica el [**subsrippangithub.cm/sorsarlosp!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Comparte trucos enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## What is Distroless

Un contenedor distroless es un tipo de contenedor que **contiene solo las dependencias necesarias para ejecutar una aplicación específica**, sin ningún software o herramienta adicional que no sea requerida. Estos contenedores están diseñados para ser lo más **ligeros** y **seguros** posible, y su objetivo es **minimizar la superficie de ataque** al eliminar cualquier componente innecesario.

Los contenedores distroless se utilizan a menudo en **entornos de producción donde la seguridad y la fiabilidad son primordiales**.

Algunos **ejemplos** de **contenedores distroless** son:

* Proporcionados por **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Proporcionados por **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

El objetivo de armar un contenedor distroless es poder **ejecutar binarios y cargas útiles arbitrarias incluso con las limitaciones** implicadas por **distroless** (falta de binarios comunes en el sistema) y también protecciones comúnmente encontradas en contenedores como **solo lectura** o **sin ejecución** en `/dev/shm`.

### Through memory

Llegando en algún momento de 2023...

### Via Existing binaries

#### openssl

****[**En esta publicación,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) se explica que el binario **`openssl`** se encuentra frecuentemente en estos contenedores, potencialmente porque es **necesario** para el software que se va a ejecutar dentro del contenedor.
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Aprende & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Verifica el [**subsrippangithub.cm/sorsarlosp!
* Verifica los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Únete  💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
