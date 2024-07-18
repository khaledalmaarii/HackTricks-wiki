{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons-Lizenz" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Copyright © Carlos Polop 2021. Sofern nicht anders angegeben (die externen Informationen, die in das Buch kopiert wurden, gehören den Originalautoren), steht der Text auf <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> von Carlos Polop unter der <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Namensnennung-Nicht kommerziell 4.0 International (CC BY-NC 4.0)</a>.

Lizenz: Namensnennung-Nicht kommerziell 4.0 International (CC BY-NC 4.0)<br>
Menschlich lesbare Lizenz: https://creativecommons.org/licenses/by-nc/4.0/<br>
Vollständige rechtliche Bestimmungen: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formatierung: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Namensnennung-Nicht kommerziell 4.0 International

Die Creative Commons Corporation ("Creative Commons") ist keine Anwaltskanzlei und bietet keine Rechtsberatung oder Rechtsdienstleistungen an. Die Verbreitung von Creative Commons-Lizenzen schafft keine Anwaltsmandanten- oder andere Beziehungen. Creative Commons stellt ihre Lizenzen und zugehörigen Informationen "wie sie sind" zur Verfügung. Creative Commons übernimmt keine Gewährleistung für ihre Lizenzen, Materialien, die gemäß ihren Bedingungen lizenziert sind, oder zugehörige Informationen. Creative Commons lehnt jegliche Haftung für Schäden ab, die sich aus ihrer Verwendung ergeben, soweit gesetzlich zulässig.

## Verwendung von Creative Commons Public Licenses

Die öffentlichen Lizenzen von Creative Commons bieten einen standardisierten Satz von Bedingungen, die Urheber und andere Rechteinhaber verwenden können, um originale Werke des geistigen Eigentums und anderes Material, das dem Urheberrecht und bestimmten anderen Rechten unterliegt, gemäß der unten stehenden öffentlichen Lizenz zu teilen. Die folgenden Überlegungen dienen nur zu Informationszwecken, sind nicht erschöpfend und sind kein Bestandteil unserer Lizenzen.

* __Überlegungen für Lizenzgeber:__ Unsere öffentlichen Lizenzen sind für die Verwendung durch diejenigen gedacht, die berechtigt sind, der Öffentlichkeit die Erlaubnis zu geben, Material auf Arten zu nutzen, die durch das Urheberrecht und bestimmte andere Rechte eingeschränkt sind. Unsere Lizenzen sind unwiderruflich. Lizenzgeber sollten die Bedingungen der von ihnen gewählten Lizenz lesen und verstehen, bevor sie sie anwenden. Lizenzgeber sollten auch alle erforderlichen Rechte sichern, bevor sie unsere Lizenzen anwenden, damit die Öffentlichkeit das Material wie erwartet wiederverwenden kann. Lizenzgeber sollten deutlich kennzeichnen, welches Material nicht der Lizenz unterliegt. Dazu gehören anderes CC-lizenziertes Material oder Material, das unter einer Ausnahme oder Beschränkung des Urheberrechts verwendet wird. [Weitere Überlegungen für Lizenzgeber](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Überlegungen für die Öffentlichkeit:__ Durch die Verwendung einer unserer öffentlichen Lizenzen gewährt ein Lizenzgeber der Öffentlichkeit die Erlaubnis, das lizenzierte Material unter bestimmten Bedingungen zu nutzen. Wenn die Erlaubnis des Lizenzgebers aus irgendeinem Grund nicht erforderlich ist - zum Beispiel aufgrund einer anwendbaren Ausnahme oder Beschränkung des Urheberrechts - wird diese Nutzung nicht durch die Lizenz reguliert. Unsere Lizenzen gewähren nur Berechtigungen gemäß dem Urheberrecht und bestimmten anderen Rechten, die ein Lizenzgeber gewähren darf. Die Verwendung des lizenzierten Materials kann aus anderen Gründen immer noch eingeschränkt sein, einschließlich der Tatsache, dass andere Urheberrechte oder andere Rechte am Material haben. Ein Lizenzgeber kann spezielle Anfragen stellen, z. B. die Markierung oder Beschreibung aller Änderungen. Obwohl dies von unseren Lizenzen nicht verlangt wird, wird empfohlen, diese Anfragen zu respektieren, soweit dies vernünftig ist. [Weitere Überlegungen für die Öffentlichkeit](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Namensnennung-Nicht kommerziell 4.0 International Public License

Durch die Ausübung der Lizenzierten Rechte (unten definiert) akzeptieren und stimmen Sie den Bedingungen dieser Creative Commons Namensnennung-Nicht kommerziell 4.0 International Public License ("Public License") zu. Soweit diese Public License als Vertrag interpretiert werden kann, werden Ihnen die Lizenzierten Rechte als Gegenleistung für Ihre Annahme dieser Bedingungen gewährt, und der Lizenzgeber gewährt Ihnen solche Rechte als Gegenleistung für die Vorteile, die der Lizenzgeber aus der Bereitstellung des Lizenzierten Materials unter diesen Bedingungen erhält.

## Abschnitt 1 - Definitionen.

a. __Angepasstes Material__ bezeichnet Material, das dem Urheberrecht und ähnlichen Rechten unterliegt und das aus dem lizenzierten Material abgeleitet ist oder auf diesem basiert und bei dem das lizenzierte Material in einer Weise übersetzt, verändert, angeordnet, transformiert oder anderweitig modifiziert wird, die eine Genehmigung gemäß den Urheberrechten und ähnlichen Rechten erfordert, die der Lizenzgeber besitzt. Im Sinne dieser Public License wird bei einem musikalischen Werk, einer Aufführung oder einer Tonaufnahme immer angepasstes Material produziert, wenn das lizenzierte Material in zeitlicher Beziehung zu einem bewegten Bild synchronisiert wird.

b. __Adapter-Lizenz__ bezeichnet die Lizenz, die Sie auf Ihre Urheberrechte und ähnlichen Rechte in Ihren Beiträgen zum angepassten Material gemäß den Bedingungen dieser Public License anwenden.

c. __Urheberrechte und ähnliche Rechte__ bezeichnen das Urheberrecht und/oder ähnliche Rechte, die eng mit dem Urheberrecht verbunden sind, einschließlich, aber nicht beschränkt auf Leistung, Rundfunk, Tonaufnahme und Datenbankrechte sui generis, unabhängig davon, wie die Rechte bezeichnet oder kategorisiert sind. Im Sinne dieser Public License sind die in Abschnitt 2(b)(1)-(2) genannten Rechte keine Urheberrechte und ähnlichen Rechte.

d. __Wirksame Technologische Maßnahmen__ bezeichnen Maßnahmen, die ohne ordnungsgemäße Autorisierung nicht umgangen werden dürfen, wie es die Gesetze erfordern, die die Verpflichtungen aus Artikel 11 des am 20. Dezember 1996 verabschiedeten WIPO-Urheberrechtsvertrags und/oder ähnlichen internationalen Abkommen erfüllen.

e. __Ausnahmen und Beschränkungen__ bezeichnen die Schranken des fairen Gebrauchs, des fairen Handels und/oder jeder anderen Ausnahme oder Beschränkung der Urheberrechte und ähnlichen Rechte, die für Ihre Nutzung des lizenzierten Materials gelten.

f. __Lizenziertes Material__ bezeichnet das künstlerische oder literarische Werk, die Datenbank oder ein anderes Material, auf das der Lizenzgeber diese Public License angewendet hat.

g. __Lizenzierte Rechte__ bezeichnen die Ihnen gemäß den Bedingungen dieser Public License gewährten Rechte, die auf alle Urheberrechte und ähnlichen Rechte beschränkt sind, die für Ihre Nutzung des lizenzierten Materials gelten und die der Lizenzgeber lizenzieren darf.

h. __Lizenzgeber__ bezeichnet die Einzelperson(en) oder Einrichtung(en), die Rechte gemäß dieser Public License gewähren.

i. __Nicht kommerziell__ bedeutet nicht hauptsächlich für oder auf kommerziellen Vorteil oder monetäre Entschädigung ausgerichtet. Im Sinne dieser Public License ist der Austausch des lizenzierten Materials gegen anderes Material, das dem Urheberrecht und ähnlichen Rechten unterliegt, durch digitales Filesharing oder ähnliche Mittel nicht kommerziell, sofern keine Zahlung einer monetären Entschädigung im Zusammenhang mit dem Austausch erfolgt.

j. __Teilen__ bedeutet, Material der Öffentlichkeit auf jede Weise oder durch jeden Prozess bereitzustellen, der die Erlaubnis gemäß den Lizenzierten Rechten erfordert, wie Vervielfältigung, öffentliche Darstellung, öffentliche Aufführung, Verbreitung, Verbreitung, Kommunikation oder Einfuhr, und Material der Öffentlichkeit zugänglich zu machen, einschließlich auf Wegen, auf die die Mitglieder der Öffentlichkeit von einem von ihnen individuell gewählten Ort und zu einer von ihnen individuell gewählten Zeit auf das Material zugreifen können.

k. __Datenbankrechte sui generis__ bezeichnen Rechte, die sich aus der Richtlinie 96/9/EG des Europäischen Parlaments und des Rates vom 11. März 1996 zum rechtlichen Schutz von Datenbanken ergeben, wie sie geändert und/oder nachfolgend sind, sowie andere im Wesentlichen äquivalente Rechte weltweit.

l. __Sie__ bezeichnet die Einzelperson oder Einrichtung, die die Lizenzierten Rechte gemäß dieser Public License ausübt. Ihr hat eine entsprechende Bedeutung.
## Abschnitt 2 – Umfang.

a. ___Lizenzgewährung.___

1. Vorbehaltlich der Bedingungen dieser Öffentlichen Lizenz gewährt der Lizenzgeber Ihnen hiermit eine weltweite, gebührenfreie, nicht unterlizenzierbare, nicht exklusive, unwiderrufliche Lizenz zur Ausübung der Lizenzrechte am lizenzierten Material, um:

A. das lizenzierte Material ganz oder teilweise nur für nicht kommerzielle Zwecke zu vervielfältigen und zu teilen; und

B. angepasstes Material nur für nicht kommerzielle Zwecke zu erstellen, zu vervielfältigen und zu teilen.

2. __Ausnahmen und Einschränkungen.__ Zur Vermeidung von Zweifeln gilt, dass, wenn Ausnahmen und Einschränkungen für Ihre Nutzung gelten, diese Öffentliche Lizenz nicht gilt und Sie nicht verpflichtet sind, deren Bedingungen zu erfüllen.

3. __Laufzeit.__ Die Laufzeit dieser Öffentlichen Lizenz ist in Abschnitt 6(a) festgelegt.

4. __Medien und Formate; technische Modifikationen erlaubt.__ Der Lizenzgeber autorisiert Sie, die Lizenzrechte in allen Medien und Formaten auszuüben, die jetzt bekannt sind oder in Zukunft erstellt werden, und technische Modifikationen vorzunehmen, die dazu erforderlich sind. Der Lizenzgeber verzichtet und/oder stimmt zu, kein Recht oder keine Autorität geltend zu machen, um Sie daran zu hindern, technische Modifikationen vorzunehmen, die erforderlich sind, um die Lizenzrechte auszuüben, einschließlich technischer Modifikationen, die erforderlich sind, um wirksame technologische Maßnahmen zu umgehen. Im Sinne dieser Öffentlichen Lizenz führt allein die Durchführung von Modifikationen, die durch diesen Abschnitt 2(a)(4) autorisiert sind, niemals zu angepasstem Material.

5. __Empfänger nachgelagerter Rechte.__

A. __Angebot des Lizenzgebers – Lizenziertes Material.__ Jeder Empfänger des lizenzierten Materials erhält automatisch ein Angebot des Lizenzgebers, die Lizenzrechte unter den Bedingungen dieser Öffentlichen Lizenz auszuüben.

B. __Keine nachgelagerten Beschränkungen.__ Sie dürfen keine zusätzlichen oder abweichenden Bedingungen oder Bedingungen anwenden oder wirksame technologische Maßnahmen auf das lizenzierte Material anwenden, wenn dadurch die Ausübung der Lizenzrechte durch jeden Empfänger des lizenzierten Materials eingeschränkt wird.

6. __Keine Unterstützung.__ Nichts in dieser Öffentlichen Lizenz stellt eine Erlaubnis dar oder kann so ausgelegt werden, dass Sie oder dass Ihre Nutzung des lizenzierten Materials mit dem Lizenzgeber oder anderen, die berechtigt sind, eine Zuschreibung gemäß Abschnitt 3(a)(1)(A)(i) zu erhalten, verbunden ist oder gesponsert, befürwortet oder offiziellen Status erhalten hat.

b. ___Andere Rechte.___

1. Moralrechte, wie das Recht auf Integrität, sind nicht durch diese Öffentliche Lizenz lizenziert, ebenso wenig wie Persönlichkeitsrechte, Publicity- und/oder ähnliche Persönlichkeitsrechte; jedoch verzichtet der Lizenzgeber und/oder stimmt zu, keine solchen Rechte, die vom Lizenzgeber gehalten werden, in dem begrenzten Umfang geltend zu machen, der erforderlich ist, um Ihnen die Ausübung der Lizenzrechte zu ermöglichen, jedoch nicht darüber hinaus.

2. Patent- und Markenrechte sind nicht durch diese Öffentliche Lizenz lizenziert.

3. Soweit möglich, verzichtet der Lizenzgeber auf das Recht, von Ihnen Lizenzgebühren für die Ausübung der Lizenzrechte zu erheben, sei es direkt oder über eine Verwertungsgesellschaft im Rahmen eines freiwilligen oder verzichtbaren gesetzlichen oder obligatorischen Lizenzierungssystems. In allen anderen Fällen behält sich der Lizenzgeber ausdrücklich das Recht vor, solche Lizenzgebühren zu erheben, auch wenn das lizenzierte Material nicht für nicht kommerzielle Zwecke verwendet wird.

## Abschnitt 3 – Lizenzbedingungen.

Die Ausübung der Lizenzrechte unterliegt ausdrücklich den folgenden Bedingungen.

a. ___Zuschreibung.___

1. Wenn Sie das lizenzierte Material teilen (auch in modifizierter Form), müssen Sie:

A. Folgendes beibehalten, wenn es vom Lizenzgeber mit dem lizenzierten Material bereitgestellt wird:

i. Identifizierung der Urheber des lizenzierten Materials und anderer, die berechtigt sind, eine Zuschreibung zu erhalten, in jeder zumutbaren Weise, die vom Lizenzgeber angefordert wird (auch unter Pseudonym, wenn festgelegt);

ii. einen Urheberrechtsvermerk;

iii. einen Hinweis, der auf diese Öffentliche Lizenz verweist;

iv. einen Hinweis, der auf den Haftungsausschluss hinweist;

v. eine URI oder Hyperlink zum lizenzierten Material, soweit dies vernünftigerweise möglich ist;

B. angeben, ob Sie das lizenzierte Material modifiziert haben, und eine Angabe zu früheren Modifikationen beibehalten; und

C. angeben, dass das lizenzierte Material unter dieser Öffentlichen Lizenz lizenziert ist, und den Text dieser Öffentlichen Lizenz oder die URI oder den Hyperlink zu dieser Öffentlichen Lizenz einschließen.

2. Sie können die Bedingungen in Abschnitt 3(a)(1) in jeder zumutbaren Weise basierend auf dem Medium, den Mitteln und dem Kontext, in dem Sie das lizenzierte Material teilen, erfüllen. Es kann beispielsweise vernünftig sein, die Bedingungen zu erfüllen, indem Sie eine URI oder einen Hyperlink zu einer Ressource bereitstellen, die die erforderlichen Informationen enthält.

3. Wenn vom Lizenzgeber angefordert, müssen Sie alle Informationen entfernen, die gemäß Abschnitt 3(a)(1)(A) erforderlich sind, soweit dies vernünftigerweise möglich ist.

4. Wenn Sie angepasstes Material teilen, das Sie erstellt haben, darf die Lizenz des Adapters, die Sie anwenden, Empfänger des angepassten Materials nicht daran hindern, diese Öffentliche Lizenz einzuhalten.

## Abschnitt 4 – Sui Generis Datenbankrechte.

Wenn die Lizenzrechte Sui Generis Datenbankrechte umfassen, die sich auf Ihre Nutzung des lizenzierten Materials beziehen:

a. Zur Vermeidung von Zweifeln gewährt Ihnen Abschnitt 2(a)(1) das Recht, alle oder einen wesentlichen Teil des Inhalts der Datenbank nur für nicht kommerzielle Zwecke zu extrahieren, wiederzuverwenden, zu vervielfältigen und zu teilen;

b. Wenn Sie den gesamten oder einen wesentlichen Teil des Datenbankinhalts in einer Datenbank einschließen, für die Sie Sui Generis Datenbankrechte haben, dann ist die Datenbank, für die Sie Sui Generis Datenbankrechte haben (aber nicht ihre einzelnen Inhalte), angepasstes Material; und

c. Sie müssen die Bedingungen in Abschnitt 3(a) einhalten, wenn Sie den gesamten oder einen wesentlichen Teil des Datenbankinhalts teilen.

Zur Vermeidung von Zweifeln ergänzt dieser Abschnitt 4 und ersetzt nicht Ihre Verpflichtungen unter dieser Öffentlichen Lizenz, wenn die Lizenzrechte auch andere Urheberrechte und ähnliche Rechte umfassen.

## Abschnitt 5 – Haftungsausschluss und Haftungsbeschränkung.

a. __Sofern nicht gesondert vom Lizenzgeber übernommen, bietet der Lizenzgeber das lizenzierte Material nach Möglichkeit so wie es ist und wie verfügbar an und gibt keine Zusicherungen oder Gewährleistungen jeglicher Art bezüglich des lizenzierten Materials ab, sei es ausdrücklich, implizit, gesetzlich oder anderweitig. Dies umfasst unter anderem, ohne Einschränkung, Gewährleistungen hinsichtlich des Titels, der Marktgängigkeit, der Eignung für einen bestimmten Zweck, der Nichtverletzung, des Vorhandenseins oder Nichtvorhandenseins von versteckten oder anderen Mängeln, der Genauigkeit oder des Vorhandenseins oder Nichtvorhandenseins von Fehlern, ob bekannt oder entdeckbar. Wenn Haftungsausschlüsse in vollem Umfang oder teilweise nicht zulässig sind, ist dieser Haftungsausschluss möglicherweise nicht auf Sie anwendbar.__

b. __Soweit gesetzlich zulässig, haftet der Lizenzgeber Ihnen auf keiner Rechtsgrundlage (einschließlich, aber nicht beschränkt auf Fahrlässigkeit) oder anderweitig für direkte, besondere, indirekte, zufällige, Folge-, Straf- oder sonstige Verluste, Kosten, Ausgaben oder Schäden, die sich aus dieser Öffentlichen Lizenz oder der Nutzung des lizenzierten Materials ergeben, selbst wenn der Lizenzgeber auf die Möglichkeit solcher Verluste, Kosten, Ausgaben oder Schäden hingewiesen wurde. Wenn eine Haftungsbeschränkung in vollem Umfang oder teilweise nicht zulässig ist, ist diese Beschränkung möglicherweise nicht auf Sie anwendbar.__

c. Der oben bereitgestellte Haftungsausschluss und die Haftungsbeschränkung sind so auszulegen, dass sie, soweit möglich, einer absoluten Haftungsfreistellung und dem Verzicht auf alle Haftungen am nächsten kommen.

## Abschnitt 6 – Laufzeit und Beendigung.

a. Diese Öffentliche Lizenz gilt für die Laufzeit der hier lizenzierten Urheberrechte und ähnlichen Rechte. Wenn Sie jedoch gegen diese Öffentliche Lizenz verstoßen, erlöschen Ihre Rechte unter dieser Öffentlichen Lizenz automatisch.

b. Wenn Ihr Recht zur Nutzung des lizenzierten Materials gemäß Abschnitt 6(a) erloschen ist, wird es wiederhergestellt:

1. automatisch ab dem Datum, an dem der Verstoß behoben ist, vorausgesetzt, er wird innerhalb von 30 Tagen nach Ihrer Entdeckung des Verstoßes behoben; oder

2. auf ausdrückliche Wiederherstellung durch den Lizenzgeber.

Zur Vermeidung von Zweifeln beeinträchtigt dieser Abschnitt 6(b) nicht das Recht des Lizenzgebers, Maßnahmen gegen Ihre Verstöße gegen diese Öffentliche Lizenz zu ergreifen.

c. Zur Vermeidung von Zweifeln kann der Lizenzgeber das lizenzierte Material auch unter separaten Bedingungen anbieten oder die Verbreitung des lizenzierten Materials jederzeit einstellen; dies beendet jedoch nicht diese Öffentliche Lizenz.

d. Abschnitte 1, 5, 6, 7 und 8 überdauern die Beendigung dieser Öffentlichen Lizenz.
## Abschnitt 7 – Weitere Bedingungen.

a. Der Lizenzgeber ist nicht an zusätzliche oder abweichende Bedingungen gebunden, die von Ihnen mitgeteilt werden, es sei denn, es wurde ausdrücklich vereinbart.

b. Alle Vereinbarungen, Verständnisse oder Abmachungen bezüglich des lizenzierten Materials, die hier nicht aufgeführt sind, sind von den Bedingungen dieser öffentlichen Lizenz getrennt und unabhängig.

## Abschnitt 8 – Auslegung.

a. Zur Vermeidung von Zweifeln reduziert, beschränkt, begrenzt oder legt diese öffentliche Lizenz nicht Bedingungen für die Nutzung des lizenzierten Materials fest, die rechtmäßig ohne Genehmigung gemäß dieser öffentlichen Lizenz vorgenommen werden könnten.

b. Soweit möglich wird eine Bestimmung dieser öffentlichen Lizenz automatisch in dem minimal erforderlichen Umfang umgestaltet, um sie durchsetzbar zu machen, wenn sie als nicht durchsetzbar erachtet wird. Kann die Bestimmung nicht umgestaltet werden, wird sie von dieser öffentlichen Lizenz abgetrennt, ohne die Durchsetzbarkeit der verbleibenden Bedingungen zu beeinträchtigen.

c. Keine Bestimmung dieser öffentlichen Lizenz wird aufgehoben und kein Verstoß wird geduldet, es sei denn, der Lizenzgeber hat ausdrücklich zugestimmt.

d. Nichts in dieser öffentlichen Lizenz stellt eine Beschränkung oder einen Verzicht auf etwaige Privilegien und Immunitäten dar, die dem Lizenzgeber oder Ihnen zustehen, einschließlich der rechtlichen Verfahren jeder Gerichtsbarkeit oder Behörde.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}
