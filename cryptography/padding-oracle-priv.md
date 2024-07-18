{% hint style="success" %}
Impara e pratica l'hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}

# CBC - Cipher Block Chaining

Nel modo CBC il **blocco crittografato precedente viene utilizzato come IV** per fare XOR con il blocco successivo:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Per decrittare CBC vengono eseguite le **operazioni opposte**:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Nota come sia necessario utilizzare una **chiave di crittografia** e un **IV**.

# Message Padding

Poiché la crittografia avviene in **blocchi di dimensioni fisse**, di solito è necessario un **padding** nell'**ultimo blocco** per completarne la lunghezza.\
Di solito si utilizza **PKCS7**, che genera un padding **ripetendo** il **numero di byte necessari** per **completare** il blocco. Ad esempio, se all'ultimo blocco mancano 3 byte, il padding sarà `\x03\x03\x03`.

Vediamo più esempi con **2 blocchi di lunghezza 8 byte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Nota come nell'ultimo esempio l'**ultimo blocco era pieno quindi ne è stato generato un altro solo con il padding**.

# Padding Oracle

Quando un'applicazione decrittografa dati crittografati, prima decifrerà i dati; quindi rimuoverà il padding. Durante la pulizia del padding, se un **padding non valido attiva un comportamento rilevabile**, si ha una **vulnerabilità dell'oracolo di padding**. Il comportamento rilevabile può essere un **errore**, una **mancanza di risultati**, o una **risposta più lenta**.

Se si rileva questo comportamento, è possibile **decrittare i dati crittografati** e persino **crittografare qualsiasi testo in chiaro**.

## Come sfruttare

Potresti utilizzare [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) per sfruttare questo tipo di vulnerabilità o semplicemente fare
```
sudo apt-get install padbuster
```
Per testare se il cookie di un sito è vulnerabile potresti provare:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Codifica 0** significa che viene utilizzato **base64** (ma sono disponibili anche altri, controlla il menu di aiuto).

Potresti anche **sfruttare questa vulnerabilità per crittografare nuovi dati. Ad esempio, immagina che il contenuto del cookie sia "**_**user=MyUsername**_**", allora potresti cambiarlo in "\_user=administrator\_" e ottenere privilegi elevati all'interno dell'applicazione. Potresti farlo anche utilizzando `padbuster` specificando il parametro -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Se il sito è vulnerabile, `padbuster` cercherà automaticamente di individuare quando si verifica l'errore di padding, ma è anche possibile indicare il messaggio di errore utilizzando il parametro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## La teoria

In **sintesi**, puoi iniziare a decifrare i dati crittografati indovinando i valori corretti che possono essere utilizzati per creare tutti i **diversi padding**. Quindi, l'attacco all'oracolo di padding inizierà a decifrare i byte dalla fine all'inizio indovinando quale sarà il valore corretto che **crea un padding di 1, 2, 3, ecc.**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Immagina di avere del testo crittografato che occupa **2 blocchi** formati dai byte da **E0 a E15**.\
Per **decifrare** l'**ultimo blocco** (**E8** a **E15**), l'intero blocco passa attraverso la "decrittografia del cifrario a blocchi" generando gli **intermediari I0 a I15**.\
Infine, ogni byte intermedio viene **XORato** con i byte crittografati precedenti (E0 a E7). Quindi:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Ora, è possibile **modificare `E7` fino a quando `C15` non diventa `0x01`**, che sarà anche un padding corretto. Quindi, in questo caso: `\x01 = I15 ^ E'7`

Quindi, trovando E'7, è **possibile calcolare I15**: `I15 = 0x01 ^ E'7`

Ciò ci permette di **calcolare C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Conoscendo **C15**, ora è possibile **calcolare C14**, ma questa volta forzando il padding `\x02\x02`.

Questo BF è complesso quanto il precedente poiché è possibile calcolare il `E''15` il cui valore è 0x02: `E''7 = \x02 ^ I15` quindi è sufficiente trovare l'**`E'14`** che genera un **`C14` uguale a `0x02`**.\
Quindi, eseguire gli stessi passaggi per decrittare C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Segui questa catena fino a decifrare l'intero testo crittografato.**

## Rilevamento della vulnerabilità

Registrati e accedi con questo account.\
Se effettui il **login molte volte** e ottieni sempre lo stesso cookie, probabilmente c'è **qualcosa di sbagliato** nell'applicazione. Il **cookie inviato dovrebbe essere unico** ogni volta che effettui il login. Se il cookie è **sempre** lo **stesso**, probabilmente sarà sempre valido e non ci sarà modo di invalidarlo.

Ora, se provi a **modificare** il **cookie**, vedrai che ricevi un **errore** dall'applicazione.\
Ma se forzi il padding (usando padbuster ad esempio) riesci a ottenere un altro cookie valido per un utente diverso. Questo scenario è molto probabilmente vulnerabile a padbuster.

## Riferimenti

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
