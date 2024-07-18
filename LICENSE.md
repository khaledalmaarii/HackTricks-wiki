{% hint style="success" %}
Impara e pratica l'hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) nei repository di github.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Licenza Creative Commons" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Copyright © Carlos Polop 2021.  Salvo diversamente specificato (le informazioni esterne copiate nel libro appartengono agli autori originali), il testo su <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> di Carlos Polop è concesso in licenza ai sensi della <a href="https://creativecommons.org/licenses/by-nc/4.0/">Licenza Creative Commons Attribuzione-Non commerciale 4.0 Internazionale (CC BY-NC 4.0)</a>.

Licenza: Attribuzione-Non commerciale 4.0 Internazionale (CC BY-NC 4.0)<br>
Licenza Leggibile da Persone: https://creativecommons.org/licenses/by-nc/4.0/<br>
Termini Legali Completi: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formattazione: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Attribuzione-Non commerciale 4.0 Internazionale

Creative Commons Corporation ("Creative Commons") non è uno studio legale e non fornisce servizi legali o consulenza legale. La distribuzione delle licenze pubbliche di Creative Commons non crea un rapporto avvocato-cliente o altro tipo di relazione. Creative Commons mette a disposizione le sue licenze e le informazioni correlate "così come sono". Creative Commons non fornisce garanzie in merito alle sue licenze, a qualsiasi materiale concesso in licenza ai sensi delle relative condizioni, o a qualsiasi informazione correlata. Creative Commons declina ogni responsabilità per danni derivanti dal loro utilizzo nella misura massima consentita.

## Utilizzo delle Licenze Pubbliche Creative Commons

Le licenze pubbliche di Creative Commons forniscono un insieme standard di termini e condizioni che i creatori e altri titolari di diritti possono utilizzare per condividere opere originali soggette a copyright e ad altri diritti specificati nella licenza pubblica qui di seguito. Le seguenti considerazioni sono solo a scopo informativo, non sono esaustive e non fanno parte delle nostre licenze.

* __Considerazioni per i concedenti:__ Le nostre licenze pubbliche sono destinate all'uso da parte di coloro autorizzati a concedere al pubblico il permesso di utilizzare materiale in modi altrimenti limitati dal copyright e da certi altri diritti. Le nostre licenze sono irrevocabili. I concedenti dovrebbero leggere e comprendere i termini e le condizioni della licenza scelta prima di applicarla. I concedenti dovrebbero anche ottenere tutti i diritti necessari prima di applicare le nostre licenze in modo che il pubblico possa riutilizzare il materiale come previsto. I concedenti dovrebbero contrassegnare chiaramente qualsiasi materiale non soggetto alla licenza. Questo include altri materiali con licenza CC, o materiali utilizzati in base a un'eccezione o limitazione al copyright. [Ulteriori considerazioni per i concedenti](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Considerazioni per il pubblico:__ Utilizzando una delle nostre licenze pubbliche, un concedente concede al pubblico il permesso di utilizzare il materiale concesso in licenza secondo termini e condizioni specifici. Se il permesso del concedente non è necessario per qualsiasi motivo - ad esempio, a causa di qualsiasi eccezione o limitazione applicabile al copyright - allora tale utilizzo non è regolato dalla licenza. Le nostre licenze concedono solo autorizzazioni in base al copyright e a certi altri diritti che un concedente ha il potere di concedere. L'uso del materiale concesso in licenza potrebbe comunque essere limitato per altri motivi, inclusi i diritti di copyright o altri diritti sul materiale. Un concedente può fare richieste speciali, ad esempio chiedendo che tutte le modifiche siano contrassegnate o descritte. Anche se non richiesto dalle nostre licenze, ti incoraggiamo a rispettare tali richieste quando ragionevoli. [Ulteriori considerazioni per il pubblico](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Licenza Pubblica Creative Commons Attribuzione-Non commerciale 4.0 Internazionale

Esercitando i Diritti Concessi (definiti di seguito), accetti e accetti di essere vincolato dai termini e dalle condizioni di questa Licenza Pubblica Creative Commons Attribuzione-Non commerciale 4.0 Internazionale ("Licenza Pubblica"). Nella misura in cui questa Licenza Pubblica possa essere interpretata come un contratto, ti vengono concessi i Diritti Concessi in considerazione della tua accettazione di questi termini e condizioni, e il Concedente ti concede tali diritti in considerazione dei benefici che il Concedente riceve mettendo il Materiale Concesso in licenza a norma di questi termini e condizioni.

## Sezione 1 - Definizioni.

a. __Materiale Adattato__ significa materiale soggetto a Copyright e Diritti Simili che deriva dal Materiale Concesso in licenza e in cui il Materiale Concesso in licenza è tradotto, alterato, organizzato, trasformato o altrimenti modificato in modo che richieda il permesso ai sensi dei Diritti d'Autore e Simili detenuti dal Concedente. Ai fini di questa Licenza Pubblica, quando il Materiale Concesso in licenza è un'opera musicale, una performance o una registrazione sonora, il Materiale Adattato viene sempre prodotto quando il Materiale Concesso in licenza è sincronizzato in relazione temporale con un'immagine in movimento.

b. __Licenza dell'Adattatore__ significa la licenza che applichi ai tuoi Diritti d'Autore e Simili nelle tue contribuzioni al Materiale Adattato in conformità ai termini e alle condizioni di questa Licenza Pubblica.

c. __Copyright e Diritti Simili__ significa diritti d'autore e/o diritti simili strettamente correlati al diritto d'autore, compresi, a titolo esemplificativo, i diritti di esecuzione, di trasmissione, di registrazione sonora e i Diritti di Database Sui Generis, indipendentemente dal modo in cui i diritti sono etichettati o categorizzati. Ai fini di questa Licenza Pubblica, i diritti specificati nella Sezione 2(b)(1)-(2) non sono Diritti d'Autore e Simili.

d. __Misure Tecnologiche Efficaci__ significa quelle misure che, in assenza di un'autorizzazione adeguata, non possono essere aggirate ai sensi delle leggi che adempiono agli obblighi di cui all'articolo 11 del Trattato sul diritto d'autore dell'OMPI adottato il 20 dicembre 1996 e/o di accordi internazionali simili.

e. __Eccezioni e Limitazioni__ significa uso lecito, fair dealing e/o qualsiasi altra eccezione o limitazione ai Diritti d'Autore e Simili che si applica al tuo utilizzo del Materiale Concesso in licenza.

f. __Materiale Concesso in licenza__ significa l'opera artistica o letteraria, il database o altro materiale a cui il Concedente ha applicato questa Licenza Pubblica.

g. __Diritti Concessi__ significa i diritti concessi a te a condizione dei termini e delle condizioni di questa Licenza Pubblica, che sono limitati a tutti i Diritti d'Autore e Simili che si applicano al tuo utilizzo del Materiale Concesso in licenza e che il Concedente ha il potere di concedere in licenza.

h. __Concedente__ significa l'individuo/i o l'entità/i che concedono i diritti ai sensi di questa Licenza Pubblica.

i. __Non commerciale__ significa non principalmente destinato a o diretto a vantaggio commerciale o compensazione monetaria. Ai fini di questa Licenza Pubblica, lo scambio del Materiale Concesso in licenza con altro materiale soggetto a Copyright e Diritti Simili tramite condivisione di file digitali o mezzi simili è Non commerciale a condizione che non vi sia pagamento di compensazione monetaria in relazione allo scambio.

j. __Condividere__ significa fornire materiale al pubblico con qualsiasi mezzo o processo che richiede il permesso ai sensi dei Diritti Concessi, come riproduzione, esposizione pubblica, esecuzione pubblica, distribuzione, diffusione, comunicazione o importazione, e rendere il materiale disponibile al pubblico anche in modi che i membri del pubblico possono accedere al materiale da un luogo e in un momento scelti individualmente da loro.

k. __Diritti di Database Sui Generis__ significa diritti diversi dal copyright derivanti dalla Direttiva 96/9/CE del Parlamento europeo e del Consiglio del 11 marzo 1996 sulla protezione giuridica delle basi di dati, come modificata e/o succeduta, nonché altri diritti essenzialmente equivalenti in qualsiasi parte del mondo.

l. __Tu__ significa l'individuo o l'entità che esercita i Diritti Concessi ai sensi di questa Licenza Pubblica. Il termine "Tuo" ha un significato corrispondente.
## Sezione 2 – Ambito.

a. ___Concessione di licenza.___

1. Soggetto ai termini e alle condizioni di questa Licenza Pubblica, il Concedente concede a Te una licenza mondiale, gratuita, non sublicenziabile, non esclusiva, irrevocabile per esercitare i Diritti di Licenza sul Materiale concesso in licenza per:

A. riprodurre e Condividere il Materiale concesso in licenza, interamente o in parte, solo per scopi NonCommercial; e

B. produrre, riprodurre e Condividere Materiale Adattato solo per scopi NonCommercial.

2. __Eccezioni e Limitazioni.__ Per evitare equivoci, qualora le Eccezioni e Limitazioni si applichino al Tuo utilizzo, questa Licenza Pubblica non si applica e non è necessario conformarsi ai suoi termini e condizioni.

3. __Termine.__ Il termine di questa Licenza Pubblica è specificato nella Sezione 6(a).

4. __Supporti e formati; modifiche tecniche consentite.__ Il Concedente autorizza Te ad esercitare i Diritti di Licenza in tutti i supporti e formati, sia attuali che creati in futuro, e a effettuare le modifiche tecniche necessarie per farlo. Il Concedente rinuncia e/o accetta di non far valere alcun diritto o autorità per vietare a Te di apportare le modifiche tecniche necessarie per esercitare i Diritti di Licenza, comprese le modifiche tecniche necessarie per aggirare le Misure Tecnologiche Efficaci. Ai fini di questa Licenza Pubblica, apportare semplicemente modifiche autorizzate da questa Sezione 2(a)(4) non produce mai Materiale Adattato.

5. __Destinatari successivi.__

A. __Offerta da parte del Concedente – Materiale concesso in licenza.__ Ogni destinatario del Materiale concesso in licenza riceve automaticamente un'offerta da parte del Concedente per esercitare i Diritti di Licenza nei termini e alle condizioni di questa Licenza Pubblica.

B. __Nessuna restrizione per i destinatari successivi.__ Non puoi offrire o imporre termini o condizioni aggiuntivi o diversi, o applicare Misure Tecnologiche Efficaci al Materiale concesso in licenza se ciò limita l'esercizio dei Diritti di Licenza da parte di qualsiasi destinatario del Materiale concesso in licenza.

6. __Nessuna approvazione.__ Nulla in questa Licenza Pubblica costituisce o può essere interpretato come autorizzazione a sostenere o implicare che Tu sei, o che il Tuo utilizzo del Materiale concesso in licenza è, collegato, sponsorizzato, approvato o ha ottenuto uno status ufficiale da parte del Concedente o di altri designati a ricevere l'attribuzione come previsto nella Sezione 3(a)(1)(A)(i).

b. ___Altri diritti.___

1. I diritti morali, come il diritto di integrità, non sono concessi in licenza con questa Licenza Pubblica, né lo sono i diritti di pubblicità, privacy e/o altri diritti simili alla personalità; tuttavia, per quanto possibile, il Concedente rinuncia e/o accetta di non far valere tali diritti detenuti dal Concedente nella misura strettamente necessaria per consentire a Te di esercitare i Diritti di Licenza, ma non diversamente.

2. I diritti brevettuali e di marchio non sono concessi in licenza con questa Licenza Pubblica.

3. Per quanto possibile, il Concedente rinuncia a qualsiasi diritto di riscuotere royalty da Te per l'esercizio dei Diritti di Licenza, direttamente o tramite una società di gestione ai sensi di qualsiasi regime di licenza volontaria o obbligatoria rinunciabile. In tutti gli altri casi il Concedente si riserva espressamente il diritto di riscuotere tali royalty, anche quando il Materiale concesso in licenza è utilizzato diversamente per scopi NonCommercial.

## Sezione 3 – Condizioni della Licenza.

L'esercizio dei Diritti di Licenza è espressamente soggetto alle seguenti condizioni.

a. ___Attribuzione.___

1. Se Condividi il Materiale concesso in licenza (anche in forma modificata), devi:

A. mantenere quanto segue se è fornito dal Concedente insieme al Materiale concesso in licenza:

i. identificazione del/i creatore/i del Materiale concesso in licenza e di altri designati a ricevere l'attribuzione, in qualsiasi modo ragionevolmente richiesto dal Concedente (anche con pseudonimo se designato);

ii. un avviso di copyright;

iii. un avviso che si riferisce a questa Licenza Pubblica;

iv. un avviso che si riferisce alla esclusione di garanzie;

v. un URI o un collegamento ipertestuale al Materiale concesso in licenza nella misura ragionevolmente praticabile;

B. indicare se hai modificato il Materiale concesso in licenza e mantenere un'indicazione di eventuali modifiche precedenti; e

C. indicare che il Materiale concesso in licenza è concesso in licenza in base a questa Licenza Pubblica e includere il testo o l'URI o il collegamento ipertestuale a questa Licenza Pubblica.

2. Puoi soddisfare le condizioni della Sezione 3(a)(1) in qualsiasi modo ragionevole in base al supporto, ai mezzi e al contesto in cui Condividi il Materiale concesso in licenza. Ad esempio, può essere ragionevole soddisfare le condizioni fornendo un URI o un collegamento ipertestuale a una risorsa che include le informazioni richieste.

3. Se richiesto dal Concedente, devi rimuovere qualsiasi informazione richiesta dalla Sezione 3(a)(1)(A) nella misura ragionevolmente praticabile.

4. Se Condividi Materiale Adattato che hai prodotto, la Licenza dell'Adattatore che applichi non deve impedire ai destinatari del Materiale Adattato di conformarsi a questa Licenza Pubblica.

## Sezione 4 – Diritti del Database Sui Generis.

Qualora i Diritti di Licenza includano Diritti del Database Sui Generis che si applicano al Tuo utilizzo del Materiale concesso in licenza:

a. per evitare equivoci, la Sezione 2(a)(1) ti concede il diritto di estrarre, riutilizzare, riprodurre e Condividere tutto o una parte sostanziale dei contenuti del database solo per scopi NonCommercial;

b. se includi tutto o una parte sostanziale dei contenuti del database in un database in cui hai Diritti del Database Sui Generis, allora il database in cui hai Diritti del Database Sui Generis (ma non i suoi contenuti individuali) è considerato Materiale Adattato; e

c. devi conformarti alle condizioni della Sezione 3(a) se Condividi tutto o una parte sostanziale dei contenuti del database.

Per evitare equivoci, questa Sezione 4 integra e non sostituisce i Tuoi obblighi ai sensi di questa Licenza Pubblica qualora i Diritti di Licenza includano altri Diritti d'Autore e Diritti Simili.

## Sezione 5 – Esclusione di Garanzie e Limitazione di Responsabilità.

a. __Salvo diversamente concordato separatamente dal Concedente, per quanto possibile, il Concedente offre il Materiale concesso in licenza così com'è e come disponibile, e non rilascia dichiarazioni o garanzie di alcun tipo riguardanti il Materiale concesso in licenza, che siano esplicite, implicite, statutarie o altro. Ciò include, senza limitazioni, garanzie di titolo, commerciabilità, idoneità per uno scopo particolare, non violazione, assenza di difetti latenti o altri difetti, accuratezza, o la presenza o assenza di errori, che siano noti o scopribili. Qualora le esclusioni di garanzie non siano consentite integralmente o in parte, questa esclusione potrebbe non applicarsi a Te.__

b. __Per quanto possibile, in nessun caso il Concedente sarà responsabile nei Tuoi confronti per qualsiasi teoria legale (inclusa, senza limitazioni, la negligenza) o in altro modo per qualsiasi perdita diretta, speciale, indiretta, incidentale, consequenziale, punitiva, esemplare o altre perdite, costi, spese o danni derivanti da questa Licenza Pubblica o dall'uso del Materiale concesso in licenza, anche se il Concedente è stato informato della possibilità di tali perdite, costi, spese o danni. Qualora una limitazione di responsabilità non sia consentita integralmente o in parte, questa limitazione potrebbe non applicarsi a Te.__

c. L'esclusione di garanzie e la limitazione di responsabilità fornite sopra devono essere interpretate in modo che, per quanto possibile, si avvicinino il più possibile a una esclusione assoluta e rinuncia di ogni responsabilità.

## Sezione 6 – Termine e Risoluzione.

a. Questa Licenza Pubblica si applica per il termine dei Diritti d'Autore e Diritti Simili concessi qui. Tuttavia, se non rispetti questa Licenza Pubblica, i Tuoi diritti ai sensi di questa Licenza Pubblica terminano automaticamente.

b. Qualora il Tuo diritto di utilizzare il Materiale concesso in licenza sia terminato ai sensi della Sezione 6(a), esso viene ripristinato:

1. automaticamente alla data in cui la violazione viene sanata, a condizione che sia sanata entro 30 giorni dalla scoperta della violazione da parte Tua; o

2. su esplicito ripristino da parte del Concedente.

Per evitare equivoci, questa Sezione 6(b) non influisce su eventuali diritti che il Concedente potrebbe avere per richiedere rimedi per le Tue violazioni di questa Licenza Pubblica.

c. Per evitare equivoci, il Concedente potrebbe offrire il Materiale concesso in licenza con termini o condizioni separati o interrompere la distribuzione del Materiale concesso in licenza in qualsiasi momento; tuttavia, ciò non comporterà la risoluzione di questa Licenza Pubblica.

d. Le Sezioni 1, 5, 6, 7 e 8 sopravvivono alla risoluzione di questa Licenza Pubblica.
## Sezione 7 - Altri Termini e Condizioni.

a. Il Concedente non sarà vincolato da eventuali termini o condizioni aggiuntivi o diversi comunicati da Te a meno che non siano espressamente concordati.

b. Eventuali disposizioni, intese o accordi riguardanti il Materiale concesso in licenza non indicati qui sono separati e indipendenti dai termini e condizioni di questa Licenza Pubblica.

## Sezione 8 - Interpretazione.

a. Per evitare equivoci, questa Licenza Pubblica non riduce, limita, restrige o impone condizioni su qualsiasi utilizzo del Materiale concesso in licenza che potrebbe essere legalmente effettuato senza autorizzazione in base a questa Licenza Pubblica.

b. Nella misura del possibile, se una disposizione di questa Licenza Pubblica viene considerata inapplicabile, sarà automaticamente riformata al minimo necessario per renderla applicabile. Se la disposizione non può essere riformata, sarà scissa da questa Licenza Pubblica senza influire sulla possibilità di far rispettare i restanti termini e condizioni.

c. Nessun termine o condizione di questa Licenza Pubblica sarà rinunciato e nessun mancato rispetto sarà consentito a meno che non sia espressamente concordato dal Concedente.

d. Nulla in questa Licenza Pubblica costituisce o può essere interpretato come una limitazione o rinuncia a privilegi e immunità che si applicano al Concedente o a Te, compresi dai processi legali di qualsiasi giurisdizione o autorità.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Impara e pratica l'hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
