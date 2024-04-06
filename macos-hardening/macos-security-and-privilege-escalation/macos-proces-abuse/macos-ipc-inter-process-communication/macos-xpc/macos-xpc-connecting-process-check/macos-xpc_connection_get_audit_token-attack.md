# macOS xpc\_connection\_get\_audit\_token Attack

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Aby uzyskać więcej informacji, sprawdź oryginalny post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Oto streszczenie:

## Podstawowe informacje o wiadomościach Mach

Jeśli nie wiesz, czym są wiadomości Mach, zacznij od sprawdzenia tej strony:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

Na chwilę obecną pamiętaj ([definicja stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Wiadomości Mach są wysyłane przez _port mach_, który jest **kanałem komunikacyjnym jednego odbiorcy, wielu nadawców** wbudowanym w jądro mach. **Wiele procesów może wysyłać wiadomości** do portu mach, ale w dowolnym momencie **tylko jeden proces może je czytać**. Podobnie jak deskryptory plików i gniazda, porty mach są przydzielane i zarządzane przez jądro, a procesy widzą tylko liczbę całkowitą, którą mogą użyć do wskazania jądru, który z ich portów mach chcą użyć.

## Połączenie XPC

Jeśli nie wiesz, jak jest nawiązywane połączenie XPC, sprawdź:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Podsumowanie podatności

Co jest dla Ciebie interesujące, to że **abstrakcja XPC to połączenie jeden do jednego**, ale opiera się na technologii, która **może mieć wielu nadawców, więc:**

* Porty mach są jednym odbiorcą, **wieloma nadawcami**.
* Token audytu połączenia XPC to token audytu **skopiowany z ostatniej otrzymanej wiadomości**.
* Uzyskanie **tokena audytu** połączenia XPC jest kluczowe dla wielu **kontroli bezpieczeństwa**.

Mimo że poprzednia sytuacja wydaje się obiecująca, istnieją scenariusze, w których to nie spowoduje problemów ([stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Tokeny audytu są często używane do sprawdzenia autoryzacji, aby zdecydować, czy zaakceptować połączenie. Ponieważ dzieje się to za pomocą wiadomości do portu usługi, **jeszcze nie zostało nawiązane połączenie**. Więcej wiadomości na tym porcie będzie po prostu obsługiwane jako dodatkowe żądania połączenia. Dlatego **kontrole przed zaakceptowaniem połączenia nie są podatne** (oznacza to również, że wewnątrz `-listener:shouldAcceptNewConnection:` token audytu jest bezpieczny). Szukamy zatem **połączeń XPC, które weryfikują konkretne działania**.
* Obsługa zdarzeń XPC jest obsługiwana synchronicznie. Oznacza to, że obsługa zdarzenia dla jednej wiadomości musi zostać zakończona przed jej wywołaniem dla następnej, nawet na równoległych kolejkach dystrybucji. Dlatego wewnątrz **obsługi zdarzeń XPC token audytu nie może zostać nadpisany** przez inne normalne (nie-odpowiedzi!) wiadomości.

Dwa różne sposoby, w jakie to może być wykorzystane:

1. Wariant 1:

* **Exploit** **łączy się** z usługą **A** i usługą **B**
* Usługa **B** może wywołać **uprzywilejowaną funkcjonalność** w usłudze A, której użytkownik nie może
* Usługa **A** wywołuje **`xpc_connection_get_audit_token`** podczas _**nie**_ znajdowania się w **obsłudze zdarzenia** dla połączenia w **`dispatch_async`**.
* Więc **inna** wiadomość mogłaby **nadpisać Token Audytu**, ponieważ jest wysyłana asynchronicznie poza obsługą zdarzenia.
* Exploit przekazuje **usłudze B prawo DO WYSYŁANIA do usługi A**.
* Więc usługa **B** faktycznie **wysyła** **wiadomości** do usługi **A**.
* **Exploit** próbuje **wywołać** **uprzywilejowaną akcję.** W RC usługa **A sprawdza** autoryzację tej **akcji**, podczas gdy **usługa B nadpisała Token Audytu** (dając exploittowi dostęp do wywołania uprzywilejowanej akcji).

2. Wariant 2:

* Usługa **B** może wywołać **uprzywilejowaną funkcjonalność** w usłudze A, której użytkownik nie może
* Exploit łączy się z **usługą A**, która **wysyła** exploita **wiadomość oczekującą na odpowiedź** w określonym **porcie odpowiedzi**.
* Exploit wysyła **usłudze** B wiadomość przekazującą **ten port odpowiedzi**.
* Gdy usługa **B odpowiada**, **wysyła wiadomość do usługi A**, **podczas gdy** **exploit** wysyła inną **wiadomość do usługi A**, próbując **osiągnąć uprzywilejowaną funkcjonalność** i oczekując, że odpowiedź od usługi B nadpisze Token Audytu w idealnym momencie (Warunki Wyścigu).

## Wariant 1: wywołanie xpc\_connection\_get\_audit\_token poza obsługą zdarzenia <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenariusz:

* Dwie usługi mach **`A`** i **`B`**, do których możemy się obydwoma połączyć (w oparciu o profil piaskownicy i kontrole autoryzacji przed zaakceptowaniem połączenia).
* _**A**_ musi mieć **sprawdzenie autoryzacji** dla konkretnej akcji, którą **`B`** może przekazać (ale nasza aplikacja nie może).
* Na przykład, jeśli B ma pewne **uprawnienia** lub działa jako **root**, może pozwolić mu poprosić A o wykonanie uprzywilejowanej akcji.
* Dla tego sprawdzenia autoryzacji **`A`** asynchronicznie uzyskuje token audytu, na przykład wywołując `xpc_connection_get_audit_token` z **`dispatch_async`**.

{% hint style="danger" %}
W tym przypadku atakujący mógłby wywołać **Warunki Wyścigu**, tworząc **exploit**, który **prosi A o wykonanie akcji** kilkakrotnie, jednocześnie wysyłając **B wiadomości do `A`**. Gdy RC jest **udany**, token audytu **B** zostanie skopiowany w pamięci **podczas** obsługi żądania naszego **exploita** przez A, dając mu **dostęp do akcji uprzywilejowanej, którą mógłby poprosić tylko B**.
{% endhint %}

Do tego doszło z **`A`** jako `smd` i **`B`** jako `diagnosticd`. Funkcja [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) z smb może być użyta do zainstalowania nowego uprzywilejowanego narzędzia pomocniczego (jako **root**). Jeśli **proces działa jako root** i kontaktuje się z **smd**, nie będą wykonywane żadne inne kontrole.

Dlatego usługa **B** to **`diagnosticd`**, ponieważ działa jako **root** i może być używana do **monitorowania** procesu, więc po rozpoczęciu monitorowania będzie **wysyłać wiele wiadomości na sekundę.**

Aby przeprowadzić atak:

1. Nawiąż **połączenie** z usługą o nazwie `smd`, korzystając z standardowego protokołu XPC.
2. Utwórz dodatkowe **połączenie** z `diagnosticd`. W przeciwieństwie do normalnej procedury, zamiast tworzyć i wysyłać dwa nowe porty mach, prawo do wysyłania portu klienta jest zastępowane duplikatem **prawa do wysyłania** skojarzonego z połączeniem `smd`.
3. W rezultacie wiadomości XPC mogą być wysyłane do `diagnosticd`, ale odpowiedzi z `diagnosticd` są przekierowywane do `smd`. Dla `smd` wydaje się, że wiadomości zarówno od użytkownika, jak i `diagnosticd` pochodzą z tego samego połączenia.

![Obraz przedstawiający proces ataku](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png) 4. Następny krok polega na zleceniu `diagnosticd` rozpoczęcia monitorowania wybranego procesu (potencjalnie własnego użytkownika). Jednocześnie wysyłany jest potok rutynowych komunikatów 1004 do `smd`. Celem jest zainstalowanie narzędzia z podwyższonymi uprawnieniami. 5. Ta akcja wywołuje warunkową sytuację w funkcji `handle_bless`. Istotny jest czas: wywołanie funkcji `xpc_connection_get_pid` musi zwrócić PID procesu użytkownika (ponieważ narzędzie z uprawnieniami znajduje się w pakiecie aplikacji użytkownika). Jednakże funkcja `xpc_connection_get_audit_token`, w szczególności w podprogramie `connection_is_authorized`, musi odnosić się do tokenu audytu należącego do `diagnosticd`.

## Wariant 2: przekazywanie odpowiedzi

W środowisku XPC (Cross-Process Communication), chociaż obsługiwacze zdarzeń nie wykonują się równolegle, obsługa komunikatów odpowiedzi ma unikalne zachowanie. W szczególności istnieją dwa różne metody wysyłania komunikatów oczekujących na odpowiedź:

1. **`xpc_connection_send_message_with_reply`**: Tutaj komunikat XPC jest odbierany i przetwarzany w wyznaczonej kolejce.
2. **`xpc_connection_send_message_with_reply_sync`**: Z kolei w tej metodzie komunikat XPC jest odbierany i przetwarzany w bieżącej kolejce dyspozytorskiej.

To rozróżnienie jest istotne, ponieważ pozwala na możliwość **parsowania pakietów odpowiedzi równolegle z wykonaniem obsługacza zdarzeń XPC**. Warto zauważyć, że chociaż `_xpc_connection_set_creds` implementuje blokowanie w celu zabezpieczenia przed częściowym nadpisaniem tokenu audytu, nie rozszerza tej ochrony na cały obiekt połączenia. W rezultacie powstaje podatność, w której token audytu może zostać zastąpiony w okresie między parsowaniem pakietu a wykonaniem jego obsługacza zdarzeń.

Aby wykorzystać tę podatność, wymagane jest następujące przygotowanie:

* Dwa usługi mach, oznaczone jako **`A`** i **`B`**, obie mogą nawiązać połączenie.
* Usługa **`A`** powinna zawierać sprawdzenie autoryzacji dla konkretnej akcji, którą tylko **`B`** może wykonać (aplikacja użytkownika nie może).
* Usługa **`A`** powinna wysłać komunikat, który oczekuje odpowiedzi.
* Użytkownik może wysłać komunikat do **`B`**, na który ten odpowie.

Proces eksploatacji obejmuje następujące kroki:

1. Oczekiwanie, aż usługa **`A`** wyśle komunikat, który oczekuje odpowiedzi.
2. Zamiast bezpośrednio odpowiadać na **`A`**, port odpowiedzi jest przejęty i użyty do wysłania komunikatu do usługi **`B`**.
3. Następnie wysyłany jest komunikat dotyczący zabronionej akcji, z oczekiwaniem, że zostanie przetworzony równolegle z odpowiedzią od **`B`**.

Poniżej znajduje się wizualna reprezentacja opisanego scenariusza ataku:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemy z Odkryciem

* **Trudności w Lokalizowaniu Instancji**: Szukanie instancji użycia `xpc_connection_get_audit_token` było trudne, zarówno statycznie, jak i dynamicznie.
* **Metodologia**: Frida została użyta do podpięcia funkcji `xpc_connection_get_audit_token`, filtrowanie wywołań niepochodzących od obsługaczy zdarzeń. Jednakże ta metoda była ograniczona do podpiętego procesu i wymagała aktywnego użycia.
* **Narzędzia Analizy**: Narzędzia takie jak IDA/Ghidra były używane do badania osiągalnych usług mach, ale proces był czasochłonny, komplikowany przez wywołania związane z pamięcią podręczną dyld.
* **Ograniczenia Skryptowania**: Próby zautomatyzowania analizy wywołań `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione przez złożoności w parsowaniu bloków i interakcje z pamięcią podręczną dyld.

## Naprawa <a href="#the-fix" id="the-fix"></a>

* **Zgłoszone Problemy**: Zgłoszono raport do Apple, w którym szczegółowo opisano ogólne i konkretne problemy znalezione w `smd`.
* **Odpowiedź od Apple**: Apple rozwiązało problem w `smd`, zastępując `xpc_connection_get_audit_token` przez `xpc_dictionary_get_audit_token`.
* **Charakter Naprawy**: Funkcja `xpc_dictionary_get_audit_token` jest uważana za bezpieczną, ponieważ pobiera token audytu bezpośrednio z wiadomości mach powiązanej z otrzymanym komunikatem XPC. Jednakże nie jest to część publicznego interfejsu API, podobnie jak `xpc_connection_get_audit_token`.
* **Brak Szerokiej Naprawy**: Niejasne pozostaje, dlaczego Apple nie zaimplementowało bardziej kompleksowej naprawy, takiej jak odrzucanie komunikatów niezgodnych z zapisanym tokenem audytu połączenia. Może to być spowodowane możliwością prawidłowych zmian tokena audytu w określonych scenariuszach (np. użycie `setuid`).
* **Aktualny Status**: Problem nadal występuje w iOS 17 i macOS 14, stanowiąc wyzwanie dla osób starających się go zidentyfikować i zrozumieć.
