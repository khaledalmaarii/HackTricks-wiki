# Rozszerzenia jądra macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą ekskluzywną kolekcję [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź oficjalny [**swag PEASS i HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) **grupy Discord** lub [**grupy telegram**](https://t.me/peass) albo **śledź mnie** na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podziel się swoimi sztuczkami hakowania, wysyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Podstawowe informacje

Rozszerzenia jądra (Kexts) to **pakiety** z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, zapewniając dodatkową funkcjonalność głównemu systemowi operacyjnemu.

### Wymagania

Oczywiście jest to tak potężne, że **ładowanie rozszerzenia jądra jest skomplikowane**. Oto **wymagania**, które musi spełnić rozszerzenie jądra, aby zostało załadowane:

* Podczas **wejścia w tryb odzyskiwania**, rozszerzenia **muszą być zezwolone** na załadowanie:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Rozszerzenie jądra musi być **podpisane certyfikatem podpisywania kodu jądra**, który może być **udzielony tylko przez Apple**. Firma dokładnie przeanalizuje, dlaczego jest to potrzebne.
* Rozszerzenie jądra musi również być **znotaryzowane**, aby Apple mogło sprawdzić je pod kątem złośliwego oprogramowania.
* Następnie **użytkownik root** może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do roota**.
* Podczas procesu ładowania pakiet musi być przygotowany w **chronionym miejscu niebędącym rootem**: `/Library/StagedExtensions` (wymaga uprawnienia `com.apple.rootless.storage.KernelExtensionManagement`).
* Wreszcie, podczas próby załadowania, użytkownik otrzyma [**prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html), a jeśli zostanie zaakceptowana, komputer musi zostać **ponownie uruchomiony**, aby załadować rozszerzenie.

### Proces ładowania

W przypadku systemu Catalina wyglądało to tak: Warto zauważyć, że proces **weryfikacji** zachodzi w **userlandzie**. Jednak tylko aplikacje z uprawnieniem **`com.apple.private.security.kext-management`** mogą **żądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** wiersz poleceń **rozpoczyna** proces **weryfikacji** ładowania rozszerzenia
* Skontaktuje się z **`kextd`**, wysyłając żądanie za pomocą **usługi Mach**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **podpis**
* Skontaktuje się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może być **załadowane**.
3. **`syspolicyd`** **poprosi użytkownika**, jeśli rozszerzenie nie zostało wcześniej załadowane.
* **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** w końcu będzie mógł **powiedzieć jądrze, aby załadowało** rozszerzenie

Jeśli **`kextd`** nie jest dostępne, **`kextutil`** może przeprowadzić te same kontrole.

## Referencje

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą ekskluzywną kolekcję [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź oficjalny [**swag PEASS i HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) **grupy Discord** lub [**grupy telegram**](https://t.me/peass) albo **śledź mnie** na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podziel się swoimi sztuczkami hakowania, wysyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
