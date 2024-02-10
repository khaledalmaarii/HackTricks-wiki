<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


## Grundlegende Konzepte

- **Smart Contracts** werden als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, um Vereinbarungen ohne Vermittler zu automatisieren.
- **Dezentrale Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über eine benutzerfreundliche Benutzeroberfläche und eine transparente, überprüfbare Backend.
- **Tokens & Coins** unterscheiden sich, wobei Coins als digitales Geld dienen, während Tokens Wert oder Eigentum in bestimmten Kontexten repräsentieren.
- **Utility Tokens** gewähren Zugang zu Dienstleistungen, und **Security Tokens** bedeuten Eigentumsrechte an Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** beziehen sich auf dezentrale Börsenplattformen und dezentrale autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und vereinbarte Transaktionsvalidierungen auf der Blockchain:
- **Proof of Work (PoW)** basiert auf Rechenleistung zur Überprüfung von Transaktionen.
- **Proof of Stake (PoS)** erfordert, dass Validatoren eine bestimmte Menge an Tokens halten, wodurch der Energieverbrauch im Vergleich zu PoW reduziert wird.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Geldern zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, um sicherzustellen, dass nur der Besitzer des privaten Schlüssels Überweisungen initiieren kann.

#### Schlüsselkomponenten:

- **Multisignature-Transaktionen** erfordern mehrere Signaturen zur Autorisierung einer Transaktion.
- Transaktionen bestehen aus **Eingängen** (Quelle der Mittel), **Ausgängen** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Ziel ist es, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden, wobei nur der endgültige Zustand an die Blockchain übertragen wird.

## Bitcoin-Privatsphäre-Bedenken

Privatsphäre-Angriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Benutzern verschleiern.

## Anonymes Erwerben von Bitcoins

Methoden umfassen Bargeldhandel, Mining und die Verwendung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt, um die Privatsphäre zu erhöhen.


# Bitcoin-Privatsphäre-Angriffe

# Zusammenfassung der Bitcoin-Privatsphäre-Angriffe

In der Welt von Bitcoin sind die Privatsphäre von Transaktionen und die Anonymität der Benutzer oft Gegenstand von Bedenken. Hier ist ein vereinfachter Überblick über verschiedene gängige Methoden, mit denen Angreifer die Bitcoin-Privatsphäre gefährden können.

## **Annahme gemeinsamer Eingabe-Besitz**

Es ist in der Regel selten, dass Eingaben von verschiedenen Benutzern in einer einzigen Transaktion kombiniert werden, aufgrund der damit verbundenen Komplexität. Daher wird oft angenommen, dass **zwei Eingabeadressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Eine UTXO, oder **Unspent Transaction Output**, muss vollständig in einer Transaktion ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Wechseladresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört und somit die Privatsphäre gefährden.

### Beispiel
Um dies zu verhindern, können Mischdienste oder die Verwendung mehrerer Adressen helfen, den Besitz zu verschleiern.

## **Exposition in sozialen Netzwerken und Foren**

Benutzer teilen manchmal ihre Bitcoin-Adressen online, was es **einfach macht, die Adresse ihrem Besitzer zuzuordnen**.

## **Analyse des Transaktionsgraphen**

Transaktionen können als Graphen visualisiert werden, der potenzielle Verbindungen zwischen Benutzern aufgrund des Geldflusses aufzeigt.

## **Unnötige Eingabe-Heuristik (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Eingängen und Ausgängen, um zu erraten, welcher Ausgang die Rückgabe an den Absender ist.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Eingaben dazu führt, dass die Ausgabe größer ist als jeder einzelne Eingabe, kann dies die Heuristik verwirren.

## **Erzwungene Adresswiederverwendung**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Eingaben kombiniert und somit die Adressen miteinander verknüpft.

### Korrektes Verhalten der Wallet
Wallets sollten vermeiden, Münzen, die auf bereits verwendeten, leeren Adressen empfangen wurden, zu verwenden, um dieses Datenschutzleck zu verhindern.

## **Andere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld stammen wahrscheinlich von zwei Adressen, die demselben Benutzer gehören.
- **Runde Zahlen:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei die nicht runde Ausgabe wahrscheinlich das Wechselgeld ist.
- **Wallet-Fingerprinting:** Unterschiedliche Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, was Analysten ermöglicht, die verwendete Software und möglicherweise die Wechseladresse zu identifizieren.
- **Korrelation von Beträgen und Zeitpunkten:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Traffic-Analyse**

Durch Überwachung des Netzwerkverkehrs können Angreifer potenziell Transaktionen oder Blöcke mit IP-Adressen verknüpfen und die Privatsphäre der Benutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Knoten betreibt und so ihre Fähigkeit zur Überwachung von Transaktionen erhöht.

## Mehr
Für eine umfassende Liste von Angriffen auf die Privatsphäre und Verteidigungsmöglichkeiten besuchen Sie [Bitcoin Privacy auf Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Erwerb von Bitcoin gegen Bargeld.
- **Bargeldalternativen**: Kauf von Geschenkkarten und Umtausch gegen Bitcoin im Internet.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist das Mining, insbesondere wenn es alleine durchgeführt wird, da Mining-Pools die IP-Adresse des Miners kennen könnten. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Methode sein, um es anonym zu erwerben, obwohl dies illegal ist und nicht empfohlen wird.

## Mixing-Services

Durch die Verwendung eines Mixing-Services kann ein Benutzer **Bitcoins senden** und **verschiedene Bitcoins als Gegenleistung erhalten**, was die Rückverfolgung des ursprünglichen Eigentümers erschwert. Dies erfordert jedoch Vertrauen in den Service, dass er keine Protokolle führt und die Bitcoins tatsächlich zurückgibt. Alternative Mixing-Optionen umfassen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** vereint mehrere Transaktionen von verschiedenen Benutzern zu einer einzigen, was den Prozess für jeden erschwert, der versucht, Eingaben mit Ausgaben abzugleichen. Trotz seiner Effektivität können Transaktionen mit eindeutigen Eingabe- und Ausgabegrößen immer noch potenziell zurückverfolgt werden.

Beispieltransaktionen, die möglicherweise CoinJoin verwendet haben, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Für weitere Informationen besuchen Sie [CoinJoin](https://coinjoin.io/en). Für einen ähnlichen Service auf Ethereum schauen Sie sich [Tornado Cash](https://tornado.cash) an, der Transaktionen mit Mitteln von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die charakteristische Gleichheit der Ausgaben von CoinJoin. Dadurch wird es äußerst schwierig zu erkennen und könnte die von Transaktionsüberwachungseinheiten verwendete Heuristik zur gemeinsamen Eingabe-Eigentümerschaft ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben genannte könnten PayJoin sein, was die Privatsphäre erhöht, während sie von herkömmlichen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Verwendung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich stören**, was eine vielversprechende Entwicklung in Bezug auf die Wahrung der Transaktionsprivatsphäre darstellt.


# Best Practices für Privatsphäre in Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Privatsphäre und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden sind besonders herausragend:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain stellt ein Full Node maximale Privatsphäre sicher. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass es für Angreifer unmöglich ist, herauszufinden, an welchen Transaktionen oder Adressen der Benutzer interessiert ist.
- **Client-seitige Blockfilterung**: Diese Methode beinhaltet das Erstellen von Filtern für jeden Block in der Blockchain, sodass Wallets relevante Transaktionen identifizieren können, ohne spezifische Interessen für Netzwerkbeobachter preiszugeben. Leichte Wallets laden diese Filter herunter und holen nur vollständige Blöcke ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin auf einem Peer-to-Peer-Netzwerk basiert, wird die Verwendung von Tor empfohlen, um Ihre IP-Adresse zu verschleiern und die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Vermeidung von Adresswiederverwendung**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets entmutigen die Adresswiederverwendung durch ihr Design.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Die Aufteilung einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Privatsphäreangriffe vereiteln.
- **Vermeidung von Wechselgeld**: Die Wahl von Transaktionen, die kein Wechselgeld erfordern, erhöht die Privatsphäre, indem Wechselgeld-Erkennungsmethoden gestört werden.
- **Mehrere Wechselgeldausgaben**: Wenn das Vermeiden von Wechselgeld nicht möglich ist, kann die Generierung mehrerer Wechselgeldausgaben die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero adressiert das Bedürfnis nach absoluter Anonymität bei digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Verständnis von Gas**

Gas misst den Rechenaufwand, der für die Ausführung von Operationen auf Ethereum erforderlich ist, und wird in **Gwei** berechnet. Eine Transaktion, die 2.310.000 Gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Basisgebühr sowie ein Trinkgeld zur Anreizung der Miner. Benutzer können eine maximale Gebühr festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen, wobei der Überschuss zurückerstattet wird.

## **Ausführung von Transaktionen**

Transaktionen in Ethereum umfassen einen Absender und einen Empfänger, die entweder Benutzer- oder Smart Contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemint werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Absenders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Beachtenswert ist, dass die Adresse des Absenders aus der Signatur abgeleitet wird und daher nicht in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für jeden, der sich mit Kryptowährungen beschäftigen möchte und dabei Privatsphäre und Sicherheit priorisiert.


## Referenzen

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
