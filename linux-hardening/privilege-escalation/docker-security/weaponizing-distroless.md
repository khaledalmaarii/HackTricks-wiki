# Armatizzazione di Distroless

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di GitHub.

</details>

## Cos'è Distroless

Un container Distroless è un tipo di container che **contiene solo le dipendenze necessarie per eseguire un'applicazione specifica**, senza alcun software o strumento aggiuntivo non richiesto. Questi container sono progettati per essere il più **leggeri** e **sicuri** possibile e mirano a **ridurre al minimo la superficie di attacco** rimuovendo eventuali componenti non necessari.

I container Distroless sono spesso utilizzati in **ambienti di produzione in cui la sicurezza e l'affidabilità sono fondamentali**.

Alcuni **esempi** di **container Distroless** sono:

* Forniti da **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Forniti da **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armatizzazione di Distroless

L'obiettivo dell'armatizzazione di un container Distroless è quello di essere in grado di **eseguire binari e payload arbitrari anche con le limitazioni** implicite di **Distroless** (mancanza di binari comuni nel sistema) e anche le protezioni comunemente presenti nei container come **sola lettura** o **non eseguibile** in `/dev/shm`.

### Attraverso la memoria

Disponibile in qualche momento del 2023...

### Attraverso binari esistenti

#### openssl

****[**In questo post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) viene spiegato che il binario **`openssl`** viene spesso trovato in questi container, potenzialmente perché è **necessario** per il software che verrà eseguito all'interno del container.

Sfruttando il binario **`openssl`** è possibile **eseguire cose arbitrarie**.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di GitHub.

</details>
