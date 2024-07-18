# Injection de Chromium macOS

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Informations de base

Les navigateurs basés sur Chromium comme Google Chrome, Microsoft Edge, Brave, et d'autres. Ces navigateurs sont construits sur le projet open-source Chromium, ce qui signifie qu'ils partagent une base commune et, par conséquent, ont des fonctionnalités et des options de développement similaires.

#### Drapeau `--load-extension`

Le drapeau `--load-extension` est utilisé lors du démarrage d'un navigateur basé sur Chromium à partir de la ligne de commande ou d'un script. Ce drapeau permet de **charger automatiquement une ou plusieurs extensions** dans le navigateur au démarrage.

#### Drapeau `--use-fake-ui-for-media-stream`

Le drapeau `--use-fake-ui-for-media-stream` est une autre option en ligne de commande qui peut être utilisée pour démarrer les navigateurs basés sur Chromium. Ce drapeau est conçu pour **contourner les invites utilisateur normales qui demandent la permission d'accéder aux flux multimédias de la caméra et du microphone**. Lorsque ce drapeau est utilisé, le navigateur accorde automatiquement la permission à tout site web ou application qui demande l'accès à la caméra ou au microphone.

### Outils

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Exemple
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Trouvez plus d'exemples dans les liens des outils

## Références

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
