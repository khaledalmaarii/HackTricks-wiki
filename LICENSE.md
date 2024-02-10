<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons-Lizenz" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Urheberrecht © Carlos Polop 2021. Sofern nicht anders angegeben (die in das Buch kopierten externen Informationen gehören den ursprünglichen Autoren), steht der Text auf <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> von Carlos Polop unter der <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)</a>-Lizenz.

Lizenz: Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)<br>
Lesbare Lizenz: https://creativecommons.org/licenses/by-nc/4.0/<br>
Vollständige rechtliche Bedingungen: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formatierung: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# Creative Commons

# Attribution-NonCommercial 4.0 International

Die Creative Commons Corporation ("Creative Commons") ist keine Anwaltskanzlei und bietet keine Rechtsberatung oder Rechtsdienstleistungen an. Die Verbreitung von Creative Commons-Lizenzen schafft keine Anwaltsmandats- oder sonstige Beziehung. Creative Commons stellt seine Lizenzen und zugehörigen Informationen "wie besehen" zur Verfügung. Creative Commons übernimmt keine Gewährleistung für seine Lizenzen, Materialien, die gemäß ihren Bedingungen und Konditionen lizenziert sind, oder zugehörige Informationen. Creative Commons lehnt jegliche Haftung für Schäden ab, die sich aus ihrer Verwendung ergeben, soweit dies rechtlich möglich ist.

## Verwendung von Creative Commons-Lizenzen

Creative Commons-Lizenzen bieten einen standardisierten Satz von Bedingungen, die Urheber und andere Rechteinhaber verwenden können, um originelle Werke des Urheberrechts und andere Materialien, die dem Urheberrecht und bestimmten anderen Rechten unterliegen, zu teilen. Die folgenden Überlegungen dienen nur zu Informationszwecken, sind nicht abschließend und sind kein Bestandteil unserer Lizenzen.

* __Überlegungen für Lizenzgeber:__ Unsere öffentlichen Lizenzen sind für die Verwendung durch diejenigen vorgesehen, die berechtigt sind, der Öffentlichkeit die Erlaubnis zur Nutzung von Material auf Arten zu erteilen, die sonst durch das Urheberrecht und bestimmte andere Rechte eingeschränkt wären. Unsere Lizenzen sind unwiderruflich. Lizenzgeber sollten die Bedingungen der von ihnen gewählten Lizenz lesen und verstehen, bevor sie sie anwenden. Lizenzgeber sollten auch alle erforderlichen Rechte sichern, bevor sie unsere Lizenzen anwenden, damit die Öffentlichkeit das Material wie erwartet wiederverwenden kann. Lizenzgeber sollten deutlich kennzeichnen, welches Material nicht der Lizenz unterliegt. Dies umfasst anderes CC-lizenziertes Material oder Material, das unter eine Ausnahme oder Beschränkung des Urheberrechts fällt. [Weitere Überlegungen für Lizenzgeber](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Überlegungen für die Öffentlichkeit:__ Durch die Verwendung einer unserer öffentlichen Lizenzen erteilt ein Lizenzgeber der Öffentlichkeit die Erlaubnis, das lizenzierte Material unter bestimmten Bedingungen zu nutzen. Wenn die Erlaubnis des Lizenzgebers aus irgendeinem Grund nicht erforderlich ist - zum Beispiel aufgrund einer anwendbaren Ausnahme oder Beschränkung des Urheberrechts - unterliegt diese Nutzung nicht der Lizenz. Unsere Lizenzen gewähren nur Berechtigungen im Rahmen des Urheberrechts und bestimmter anderer Rechte, die ein Lizenzgeber gewähren darf. Die Verwendung des lizenzierten Materials kann aus anderen Gründen immer noch eingeschränkt sein, zum Beispiel weil andere Urheberrechte oder andere Rechte an dem Material bestehen. Ein Lizenzgeber kann besondere Anfragen stellen, z.B. dass alle Änderungen gekennzeichnet oder beschrieben werden. Obwohl dies von unseren Lizenzen nicht verlangt wird, wird empfohlen, diese Anfragen nach Möglichkeit zu respektieren. [Weitere Überlegungen für die Öffentlichkeit](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Attribution-NonCommercial 4.0 International Public License

Durch die Ausübung der lizenzierten Rechte (wie unten definiert) akzeptieren und stimmen Sie den Bedingungen dieser Creative Commons Attribution-NonCommercial 4.0 International Public License ("Public License") zu. Soweit diese Public License als Vertrag ausgelegt werden kann, werden Ihnen die lizenzierten Rechte als Gegenleistung für Ihre Annahme dieser Bedingungen gewährt, und der Lizenzgeber gewährt Ihnen solche Rechte als Gegenleistung für die Vorteile, die der Lizenzgeber aus der Bereitstellung des lizenzierten Materials unter diesen Bedingungen erhält.

## Abschnitt 1 - Definitionen.

a. __Adaptiertes Material__ bezeichnet Material, das dem Urheberrecht und ähnlichen Rechten unterliegt und das aus dem lizenzierten Material abgeleitet oder auf ihm basiert und in dem das lizenzierte Material in einer Weise übersetzt, verändert, angeordnet, transformiert oder anderweitig modifiziert wird, die eine Genehmigung gemäß den Urheberrechten und ähnlichen Rechten, die der Lizenzgeber besitzt, erfordert. Im Sinne dieser Public License wird bei einem musikalischen Werk, einer Aufführung oder einer Tonaufnahme immer adaptiertes Material erzeugt, wenn das lizenzierte Material in zeitlicher Beziehung zu einem bewegten Bild synchronisiert wird.

b. __Lizenz des Anpassers__ bezeichnet die Lizenz, die Sie auf Ihre Urheberrechte und ähnlichen Rechte an Ihren Beiträgen zu adaptiertem Material gemäß den Bedingungen dieser Public License anwenden.

c. __Urheberrecht und ähnliche Rechte__ bezeichnet das Urheberrecht und/oder ähnliche Rechte, die eng mit dem Urheberrecht verbunden sind, einschließlich, aber nicht beschränkt auf Leistung, Rundfunk, Tonaufnahme und Sui Generis-Datenbankrechte, unabhängig davon, wie die Rechte bezeichnet oder kategorisiert sind. Im Sinne dieser Public License gelten die in Abschnitt 2(b)(1)-(2) genannten Rechte nicht als Urheberrecht und ähnliche Rechte.

d. __Wirksame technische Maßnahmen__ bezeichnet Maßnahmen, die ohne ordnungsgemäße Autorisierung nicht umgangen werden dürfen und die den Verpflichtungen aus Artikel 11 des am 20. Dezember 199
## Abschnitt 2 - Geltungsbereich.

a. ___Lizenzgewährung.___

1. Vorbehaltlich der Bedingungen dieser Public License gewährt der Lizenzgeber Ihnen hiermit eine weltweite, gebührenfreie, nicht übertragbare, nicht exklusive, unwiderrufliche Lizenz zur Ausübung der lizenzierten Rechte am lizenzierten Material, um:

A. das lizenzierte Material ganz oder teilweise für nicht kommerzielle Zwecke zu vervielfältigen und zu teilen; und

B. angepasstes Material für nicht kommerzielle Zwecke zu erstellen, zu vervielfältigen und zu teilen.

2. __Ausnahmen und Einschränkungen.__ Um Missverständnisse zu vermeiden, gilt diese Public License nicht, wenn Ausnahmen und Einschränkungen für Ihre Nutzung gelten, und Sie müssen deren Bedingungen nicht einhalten.

3. __Laufzeit.__ Die Laufzeit dieser Public License ist in Abschnitt 6(a) festgelegt.

4. __Medien und Formate; technische Änderungen erlaubt.__ Der Lizenzgeber ermächtigt Sie, die lizenzierten Rechte in allen Medien und Formaten, die jetzt bekannt sind oder in Zukunft erstellt werden, auszuüben und technische Änderungen vorzunehmen, die dafür erforderlich sind. Der Lizenzgeber verzichtet darauf und/oder erklärt sich damit einverstanden, Ihnen das Recht oder die Befugnis zu untersagen, technische Änderungen vorzunehmen, die zur Ausübung der lizenzierten Rechte erforderlich sind, einschließlich technischer Änderungen, die erforderlich sind, um wirksame technische Maßnahmen zu umgehen. Im Sinne dieser Public License führen alleinige Änderungen, die gemäß diesem Abschnitt 2(a)(4) autorisiert sind, niemals zu angepasstem Material.

5. __Empfänger nachgelagerter Stufen.__

A. __Angebot des Lizenzgebers - Lizenziertes Material.__ Jeder Empfänger des lizenzierten Materials erhält automatisch ein Angebot des Lizenzgebers, die lizenzierten Rechte gemäß den Bedingungen dieser Public License auszuüben.

B. __Keine nachgelagerten Einschränkungen.__ Sie dürfen keine zusätzlichen oder abweichenden Bedingungen oder Einschränkungen für das lizenzierte Material anbieten oder auferlegen, wenn dadurch die Ausübung der lizenzierten Rechte durch jeden Empfänger des lizenzierten Materials eingeschränkt wird.

6. __Keine Unterstützung.__ Nichts in dieser Public License stellt eine Genehmigung oder einen Hinweis darauf dar oder darf so ausgelegt werden, dass Sie oder Ihre Nutzung des lizenzierten Materials mit dem Lizenzgeber oder anderen Personen verbunden ist, gesponsert, unterstützt oder offiziellen Status gewährt wird, wie in Abschnitt 3(a)(1)(A)(i) vorgesehen.

b. ___Andere Rechte.___

1. Moralische Rechte, wie das Recht auf Unversehrtheit, sind durch diese Public License nicht lizenziert, ebenso wenig wie Veröffentlichungs-, Datenschutz- und/oder andere ähnliche Persönlichkeitsrechte. Soweit möglich, verzichtet der Lizenzgeber darauf und/oder erklärt sich damit einverstanden, solche Rechte, die ihm gehören, in dem Umfang einzuschränken, der erforderlich ist, um Ihnen die Ausübung der lizenzierten Rechte zu ermöglichen, jedoch nicht darüber hinaus.

2. Patent- und Markenrechte sind durch diese Public License nicht lizenziert.

3. Soweit möglich, verzichtet der Lizenzgeber auf das Recht, von Ihnen Lizenzgebühren für die Ausübung der lizenzierten Rechte zu erheben, sei es direkt oder über eine Verwertungsgesellschaft im Rahmen eines freiwilligen oder verzichtbaren gesetzlichen oder obligatorischen Lizenzierungssystems. In allen anderen Fällen behält sich der Lizenzgeber ausdrücklich das Recht vor, solche Lizenzgebühren zu erheben, auch wenn das lizenzierte Material nicht für nicht kommerzielle Zwecke verwendet wird.

## Abschnitt 3 - Lizenzbedingungen.

Die Ausübung der lizenzierten Rechte unterliegt ausdrücklich den folgenden Bedingungen.

a. ___Zuschreibung.___

1. Wenn Sie das lizenzierte Material (einschließlich in geänderter Form) teilen, müssen Sie:

A. Folgendes beibehalten, wenn es vom Lizenzgeber mit dem lizenzierten Material bereitgestellt wird:

i. Identifizierung der Urheber des lizenzierten Materials und aller anderen Personen, die berechtigt sind, eine Zuschreibung zu erhalten, auf jede zumutbare Weise, die vom Lizenzgeber angefordert wird (einschließlich unter einem Pseudonym, wenn dies vorgesehen ist);

ii. einen Urheberrechtsvermerk;

iii. einen Hinweis auf diese Public License;

iv. einen Hinweis auf den Haftungsausschluss;

v. eine URI oder einen Hyperlink zum lizenzierten Material, soweit dies zumutbar möglich ist;

B. angeben, ob Sie das lizenzierte Material geändert haben, und einen Hinweis auf frühere Änderungen beibehalten; und

C. angeben, dass das lizenzierte Material unter dieser Public License lizenziert ist, und den Text dieser Public License oder die URI oder den Hyperlink zu dieser Public License einschließen.

2. Sie können die Bedingungen in Abschnitt 3(a)(1) auf jede zumutbare Weise erfüllen, die auf dem Medium, den Mitteln und dem Kontext basiert, in dem Sie das lizenzierte Material teilen. Es kann beispielsweise angemessen sein, die Bedingungen zu erfüllen, indem Sie eine URI oder einen Hyperlink zu einer Ressource bereitstellen, die die erforderlichen Informationen enthält.

3. Wenn der Lizenzgeber dies verlangt, müssen Sie alle Informationen gemäß Abschnitt 3(a)(1)(A) entfernen, soweit dies zumutbar möglich ist.

4. Wenn Sie angepasstes Material teilen, das Sie erstellt haben, darf die Lizenz des Anpassers Empfängern des angepassten Materials nicht die Einhaltung dieser Public License verhindern.

## Abschnitt 4 - Sui Generis Datenbankrechte.

Wenn die lizenzierten Rechte Sui Generis Datenbankrechte umfassen, die sich auf Ihre Nutzung des lizenzierten Materials beziehen:

a. Um Missverständnisse zu vermeiden, gewährt Ihnen Abschnitt 2(a)(1) das Recht, den gesamten Inhalt der Datenbank oder einen wesentlichen Teil davon für nicht kommerzielle Zwecke zu extrahieren, wiederzuverwenden, zu vervielfältigen und zu teilen;

b. Wenn Sie den gesamten Inhalt der Datenbank oder einen wesentlichen Teil davon in einer Datenbank verwenden, für die Sie Sui Generis Datenbankrechte haben, dann ist die Datenbank, für die Sie Sui Generis Datenbankrechte haben (aber nicht deren einzelne Inhalte), angepasstes Material; und

c. Sie müssen die Bedingungen in Abschnitt 3(a) einhalten, wenn Sie den gesamten Inhalt der Datenbank oder einen wesentlichen Teil davon teilen.

Um Missverständnisse zu vermeiden, ergänzt dieser Abschnitt 4 die Verpflichtungen gemäß dieser Public License und ersetzt sie nicht, wenn die lizenzierten Rechte andere Urheberrechte und ähnliche Rechte umfassen.

## Abschnitt 5 - Haftungsausschluss und Haftungsbeschränkung.

a. __Sofern der Lizenzgeber nicht ausdrücklich etwas anderes übernimmt, bietet der Lizenzgeber das lizenzierte Material nach Möglichkeit "wie es ist" und "wie verfügbar" an und gibt keine Zusicherungen oder Gewährleistungen jeglicher Art in Bezug auf das lizenzierte Material ab, ob ausdrücklich, stillschweigend, gesetzlich oder anderweitig. Dies umfasst unter anderem keine Gewährleistungen hinsichtlich des Titels, der Verkehrsfähigkeit, der Eignung für einen bestimmten Zweck, der Nichtverletzung von Rechten, dem Vorhandensein oder Nichtvorhandensein von versteckten oder anderen Mängeln, der Genauigkeit oder des Vorhandenseins oder Nichtvorhandenseins von Fehlern, ob bekannt oder entdeckbar. Soweit der vollständige oder teilweise Haftungsausschluss von Gewährleistungen nicht zulässig ist, gilt dieser Haftungsausschluss möglicherweise nicht für Sie.__

b. __Soweit gesetzlich zulässig, haftet der Lizenzgeber Ihnen gegenüber aufgrund einer Rechtsgrundlage (einschließlich, aber nicht beschränkt auf Fahrlässigkeit) oder anderweitig nicht für direkte, besondere, indirekte, zufällige, Folge-, Straf-, exemplarische oder andere Verluste, Kosten, Ausgaben oder Schäden, die sich aus dieser Public License oder der Nutzung des lizenzierten Materials ergeben, selbst wenn der Lizenzgeber auf die Möglichkeit solcher Verluste, Kosten, Ausgaben oder Schäden hingewiesen wurde. Soweit eine Haftungsbeschränkung ganz oder teilweise nicht zulässig ist, gilt diese Beschränkung möglicherweise nicht für Sie.__

c. Der oben genannte Haftungsausschluss und die Haftungsbeschränkung sind so auszulegen, dass sie, soweit möglich, einer absoluten Haftungsfreistellung und dem Verzicht auf jegliche Haftung am nächsten kommen
## Abschnitt 7 - Weitere Bedingungen.

a. Der Lizenzgeber ist nicht an zusätzliche oder abweichende Bedingungen gebunden, die von Ihnen mitgeteilt werden, es sei denn, dies wurde ausdrücklich vereinbart.

b. Alle Vereinbarungen, Verständigungen oder Abmachungen bezüglich des lizenzierten Materials, die hier nicht angegeben sind, sind von den Bedingungen dieser öffentlichen Lizenz getrennt und unabhängig.

## Abschnitt 8 - Auslegung.

a. Zur Vermeidung von Zweifeln reduziert, begrenzt, beschränkt oder legt diese öffentliche Lizenz keine Bedingungen für die Nutzung des lizenzierten Materials fest, die ohne Genehmigung gemäß dieser öffentlichen Lizenz rechtmäßig vorgenommen werden könnten.

b. Soweit möglich wird eine Bestimmung dieser öffentlichen Lizenz, die für nicht durchsetzbar erachtet wird, automatisch in dem erforderlichen Mindestmaß reformiert, um sie durchsetzbar zu machen. Kann die Bestimmung nicht reformiert werden, wird sie ohne Auswirkung auf die Durchsetzbarkeit der verbleibenden Bedingungen dieser öffentlichen Lizenz abgetrennt.

c. Keine Bestimmung dieser öffentlichen Lizenz wird aufgehoben und kein Verstoß wird geduldet, es sei denn, dies wurde ausdrücklich vom Lizenzgeber vereinbart.

d. Nichts in dieser öffentlichen Lizenz stellt eine Beschränkung oder einen Verzicht auf etwaige Privilegien und Immunitäten dar, die für den Lizenzgeber oder Sie gelten, einschließlich der rechtlichen Verfahren jeder Gerichtsbarkeit oder Behörde.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
