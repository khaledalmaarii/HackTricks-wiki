# Rozszerzenia jądra macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą ekskluzywną kolekcję [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS i HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) **grupy Discord** lub [**grupy telegram**](https://t.me/peass) lub **śledź mnie** na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podziel się swoimi sztuczkami hakerskimi, wysyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Podstawowe informacje

Rozszerzenia jądra (Kexts) to **pakiet** o rozszerzeniu **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, dostarczając dodatkowej funkcjonalności głównemu systemowi operacyjnemu.

### Wymagania

Oczywiście, jest to tak potężne, że **ładowanie rozszerzenia jądra jest skomplikowane**. Oto **wymagania**, które musi spełnić rozszerzenie jądra, aby mogło być załadowane:

* Podczas **wejścia w tryb odzyskiwania**, rozszerzenia **muszą być dozwolone** do załadowania:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Rozszerzenie jądra musi być **podpisane certyfikatem podpisu kodu jądra**, który może być przyznany tylko przez Apple. Apple szczegółowo przeanalizuje firmę i powody, dla których jest to potrzebne.
* Rozszerzenie jądra musi również być **zatwierdzone** przez Apple w celu sprawdzenia, czy nie zawiera złośliwego oprogramowania.
* Następnie **użytkownik root** jest tym, który może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do roota**.
* Podczas procesu ładowania pakiet musi być przygotowany w **chronionym miejscu bez uprawnień roota**: `/Library/StagedExtensions` (wymaga uprawnienia `com.apple.rootless.storage.KernelExtensionManagement`).
* Ostatecznie, podczas próby załadowania użytkownik otrzyma [**prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html), a jeśli zostanie zaakceptowana, komputer musi zostać **ponownie uruchomiony**, aby załadować rozszerzenie.

### Proces ładowania

W przypadku systemu Catalina wyglądało to tak: Warto zauważyć, że proces **weryfikacji** odbywa się w **userlandzie**. Jednak tylko aplikacje posiadające uprawnienie **`com.apple.private.security.kext-management`** mogą **poprosić jądro o załadowanie rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. Wiersz poleceń **`kextutil`** **rozpoczyna** proces **weryfikacji** dla załadowania rozszerzenia
* Komunikuje się z **`kextd`** za pomocą **usługi Mach**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **podpis**
* Komunikuje się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może być **załadowane**.
3. **`syspolicyd`** **poprosi użytkownika**, jeśli rozszerzenie nie zostało wcześniej załadowane.
* **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** w końcu będzie mógł **powiedzieć jądrze, aby załadowało** rozszerzenie

Jeśli **`kextd`** nie jest dostępne, **`kextutil`** może wykonać te same sprawdzenia.

## Referencje

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą ekskluzywną kolekcję [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS i HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) **grupy Discord** lub [**grupy telegram**](https://t.me/peass) lub **śledź mnie** na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podziel się swoimi sztuczkami hakerskimi, wysyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
