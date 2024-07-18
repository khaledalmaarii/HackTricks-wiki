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


## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und Vereinbarungsausführungen ohne Vermittler automatisieren.
- **Dezentralisierte Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über eine benutzerfreundliche Oberfläche und ein transparentes, überprüfbares Backend.
- **Tokens & Coins** unterscheiden sich, wobei Münzen als digitales Geld dienen, während Tokens Wert oder Eigentum in spezifischen Kontexten repräsentieren.
- **Utility Tokens** gewähren Zugang zu Dienstleistungen, und **Security Tokens** bedeuten Eigentumsrechte an Vermögenswerten.
- **DeFi** steht für Dezentralisierte Finanzen und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** beziehen sich auf Dezentralisierte Börsenplattformen und Dezentralisierte Autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und vereinbarte Transaktionsvalidierungen auf der Blockchain:
- **Proof of Work (PoW)** basiert auf Rechenleistung zur Transaktionsverifizierung.
- **Proof of Stake (PoS)** erfordert, dass Validatoren eine bestimmte Menge an Tokens halten, was den Energieverbrauch im Vergleich zu PoW reduziert.

## Bitcoin Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Geldern zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch nur der Besitzer des privaten Schlüssels Überweisungen initiieren kann.

#### Schlüsselkomponenten:

- **Multisignature-Transaktionen** erfordern mehrere Signaturen zur Autorisierung einer Transaktion.
- Transaktionen bestehen aus **Inputs** (Quelle der Gelder), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning-Netzwerk

Ziel ist es, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden, wobei nur der endgültige Zustand an die Blockchain übertragen wird.

## Bitcoin Datenschutzbedenken

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Benutzern verschleiern.

## Anonymes Erwerben von Bitcoins

Methoden umfassen Bargeldgeschäfte, Mining und die Verwendung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt, um die Privatsphäre zu erhöhen.


# Bitcoin Datenschutzangriffe

# Zusammenfassung der Bitcoin Datenschutzangriffe

In der Welt von Bitcoin sind die Privatsphäre von Transaktionen und die Anonymität der Benutzer oft Gegenstand von Bedenken. Hier ist ein vereinfachter Überblick über mehrere gängige Methoden, durch die Angreifer die Bitcoin-Privatsphäre kompromittieren können.

## **Annahme gemeinsamer Input-Eigentümerschaft**

Es ist in der Regel selten, dass Inputs von verschiedenen Benutzern in einer einzigen Transaktion kombiniert werden, aufgrund der damit verbundenen Komplexität. Daher wird angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO-Änderungsadressenerkennung**

Ein UTXO oder **Unspent Transaction Output** muss vollständig in einer Transaktion ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Änderungsadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, was die Privatsphäre gefährdet.

### Beispiel
Um dies zu mildern, können Mischdienste oder die Verwendung mehrerer Adressen helfen, die Eigentumsverhältnisse zu verschleiern.

## **Soziale Netzwerke & Foren-Exposition**

Benutzer teilen manchmal ihre Bitcoin-Adressen online, was es **einfach macht, die Adresse ihrem Besitzer zuzuordnen**.

## **Transaktionsgraphenanalyse**

Transaktionen können als Graphen visualisiert werden, wodurch potenzielle Verbindungen zwischen Benutzern basierend auf dem Geldfluss sichtbar werden.

## **Unnötige Input-Heuristik (Optimale Änderungsheuristik)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output die Änderung ist, die an den Absender zurückgeht.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Erzwungene Adresswiederverwendung**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese mit anderen Inputs in zukünftigen Transaktionen kombiniert und somit Adressen miteinander verknüpft.

### Korrektes Verhalten der Wallet
Wallets sollten vermeiden, Münzen, die auf bereits verwendeten, leeren Adressen empfangen wurden, zu verwenden, um dieses Datenschutzleck zu verhindern.

## **Andere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld stammen wahrscheinlich von zwei Adressen, die demselben Benutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei der nicht runde Output wahrscheinlich das Wechselgeld ist.
- **Wallet-Fingerprinting:** Unterschiedliche Wallets haben einzigartige Transaktionsmuster, die es Analysten ermöglichen, die verwendete Software und potenziell die Wechseladresse zu identifizieren.
- **Betrag & Zeitkorrelationen:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Verkehrsanalyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer potenziell Transaktionen oder Blöcke mit IP-Adressen verknüpfen und somit die Privatsphäre der Benutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, was ihre Fähigkeit zur Überwachung von Transaktionen verbessert.

## Mehr
Für eine umfassende Liste von Datenschutzangriffen und -verteidigungen besuchen Sie [Bitcoin Privacy auf Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bartransaktionen**: Bitcoin durch Bargeld erwerben.
- **Baralternativen**: Kauf von Geschenkkarten und Umtausch gegen Bitcoin online.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist das Mining, insbesondere wenn es alleine durchgeführt wird, da Mining-Pools die IP-Adresse des Miners kennen könnten. [Mining-Pool-Informationen](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Methode sein, um sie anonym zu erwerben, obwohl dies illegal ist und nicht empfohlen wird.

## Mixing-Services

Durch die Verwendung eines Mixing-Services kann ein Benutzer **Bitcoins senden** und **verschiedene Bitcoins als Gegenleistung erhalten**, was es schwierig macht, den ursprünglichen Besitzer zurückzuverfolgen. Dies erfordert jedoch Vertrauen in den Service, keine Logs zu behalten und tatsächlich die Bitcoins zurückzugeben. Alternative Mixing-Optionen umfassen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** vereint mehrere Transaktionen von verschiedenen Benutzern zu einer einzigen, was den Prozess für jeden erschwert, der versucht, Inputs mit Outputs abzugleichen. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen potenziell immer noch zurückverfolgt werden.

Beispieltransaktionen, die möglicherweise CoinJoin verwendet haben, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Für weitere Informationen besuchen Sie [CoinJoin](https://coinjoin.io/en). Für einen ähnlichen Service auf Ethereum werfen Sie einen Blick auf [Tornado Cash](https://tornado.cash), der Transaktionen mit Mitteln von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die charakteristischen gleichen Outputs von CoinJoin. Dies macht es äußerst schwer zu erkennen und könnte die von Transaktionsüberwachungseinheiten verwendete Heuristik zur gemeinsamen Input-Zugehörigkeit ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben genannte könnten PayJoin sein, was die Privatsphäre verbessert, während sie von Standard-Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich stören**, was eine vielversprechende Entwicklung in der Verfolgung der Transaktionsprivatsphäre darstellt.


# Best Practices für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisationstechniken**

Um die Privatsphäre und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden zeichnen sich aus:

- **Full Node**: Durch den Download der gesamten Blockchain stellt ein Full Node maximale Privatsphäre sicher. Alle jemals getätigten Transaktionen werden lokal gespeichert, was es für Angreifer unmöglich macht, zu identifizieren, an welchen Transaktionen oder Adressen der Benutzer interessiert ist.
- **Client-seitige Blockfilterung**: Diese Methode beinhaltet die Erstellung von Filtern für jeden Block in der Blockchain, die es Wallets ermöglichen, relevante Transaktionen zu identifizieren, ohne spezifische Interessen für Netzwerkbeobachter preiszugeben. Leichte Wallets laden diese Filter herunter und holen nur vollständige Blöcke ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin auf einem Peer-to-Peer-Netzwerk basiert, wird die Verwendung von Tor empfohlen, um Ihre IP-Adresse zu verschleiern und die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Vermeidung von Adresswiederverwendung**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets entmutigen die Adresswiederverwendung durch ihr Design.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Die Aufteilung einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Datenschutzangriffe vereiteln.
- **Vermeidung von Wechselgeld**: Die Wahl von Transaktionen, die keine Wechselgeldausgaben erfordern, erhöht die Privatsphäre, indem Wechselgelderfassungsmethoden gestört werden.
- **Mehrere Wechselgeldausgaben**: Wenn die Vermeidung von Wechselgeld nicht möglich ist, kann die Generierung mehrerer Wechselgeldausgaben die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero deckt den Bedarf an absoluter Anonymität bei digitalen Transaktionen ab und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Verständnis von Gas**

Gas misst den Rechenaufwand, der benötigt wird, um Operationen auf Ethereum auszuführen, und wird in **Gwei** bemessen. Zum Beispiel erfordert eine Transaktion, die 2.310.000 Gwei (oder 0,00231 ETH) kostet, ein Gaslimit und eine Grundgebühr sowie ein Trinkgeld zur Anreizsetzung für Miner. Benutzer können eine maximale Gebühr festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen, wobei der Überschuss zurückerstattet wird.

## **Ausführung von Transaktionen**

Transaktionen in Ethereum beinhalten einen Absender und einen Empfänger, die entweder Benutzer- oder Smart-Vertragsadressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Absenders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Bemerkenswert ist, dass die Adresse des Absenders aus der Signatur abgeleitet wird, was die Notwendigkeit dafür in den Transaktionsdaten eliminiert.

Diese Praktiken und Mechanismen sind grundlegend für jeden, der sich mit Kryptowährungen beschäftigen möchte, während er Privatsphäre und Sicherheit priorisiert.


## Referenzen

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
