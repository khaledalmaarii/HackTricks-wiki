# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Aprenda & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Verifique o [**subsrippangithub.cm/sorsarlosp!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Compartilhe truques enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## O que é Distroless

Um contêiner distroless é um tipo de contêiner que **contém apenas as dependências necessárias para executar um aplicativo específico**, sem qualquer software ou ferramentas adicionais que não sejam necessárias. Esses contêineres são projetados para serem o mais **leves** e **seguros** possível, e têm como objetivo **minimizar a superfície de ataque** removendo quaisquer componentes desnecessários.

Contêineres distroless são frequentemente usados em **ambientes de produção onde segurança e confiabilidade são fundamentais**.

Alguns **exemplos** de **contêineres distroless** são:

* Fornecido por **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Fornecido por **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

O objetivo de armar um contêiner distroless é ser capaz de **executar binários e payloads arbitrários, mesmo com as limitações** impostas pelo **distroless** (falta de binários comuns no sistema) e também proteções comumente encontradas em contêineres, como **somente leitura** ou **sem execução** em `/dev/shm`.

### Através da memória

Chegando em algum momento de 2023...

### Via binários existentes

#### openssl

****[**Neste post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) é explicado que o binário **`openssl`** é frequentemente encontrado nesses contêineres, potencialmente porque é **necessário** pelo software que vai ser executado dentro do contêiner.
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Aprenda & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Verifique o [**subsrippangithub.cm/sorsarlosp!
* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
