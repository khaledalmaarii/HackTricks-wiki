# Writable Sys Path + Dll Hijacking Privesc

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wprowadzenie

Jeśli odkryłeś, że możesz **pisać w folderze System Path** (zauważ, że to nie zadziała, jeśli możesz pisać w folderze User Path), istnieje możliwość, że możesz **eskalować uprawnienia** w systemie.

Aby to zrobić, możesz wykorzystać **Dll Hijacking**, gdzie **przechwycisz bibliotekę, która jest ładowana** przez usługę lub proces z **większymi uprawnieniami** niż Twoje, a ponieważ ta usługa ładuje Dll, który prawdopodobnie nie istnieje w całym systemie, spróbuje go załadować z System Path, gdzie możesz pisać.

Aby uzyskać więcej informacji na temat **czym jest Dll Hijacking**, sprawdź:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc z Dll Hijacking

### Znalezienie brakującego Dll

Pierwszą rzeczą, którą musisz zrobić, jest **zidentyfikowanie procesu**, który działa z **większymi uprawnieniami** niż Ty i próbuje **załadować Dll z System Path**, w którym możesz pisać.

Problem w tych przypadkach polega na tym, że prawdopodobnie te procesy już działają. Aby dowiedzieć się, które pliki .dll brakuje usługom, musisz uruchomić procmon tak szybko jak to możliwe (przed załadowaniem procesów). Więc, aby znaleźć brakujące .dll, wykonaj:

* **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **zmiennej środowiskowej System Path**. Możesz to zrobić **ręcznie** lub za pomocą **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Uruchom **`procmon`** i przejdź do **`Opcje`** --> **`Włącz logowanie rozruchu`** i naciśnij **`OK`** w oknie dialogowym.
* Następnie **zrestartuj** system. Po ponownym uruchomieniu komputera **`procmon`** rozpocznie **rejestrację** zdarzeń natychmiast.
* Gdy **Windows** się **uruchomi, uruchom ponownie `procmon`**, program poinformuje Cię, że działał i zapyta, czy chcesz **zapisać** zdarzenia w pliku. Wybierz **tak** i **zapisz zdarzenia w pliku**.
* **Po** wygenerowaniu **pliku**, **zamknij** otwarte okno **`procmon`** i **otwórz plik zdarzeń**.
* Dodaj te **filtry**, aby znaleźć wszystkie biblioteki DLL, które próbowały zostać załadowane z zapisalnego folderu Ścieżki Systemowej:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Brakujące DLL

Uruchamiając to na darmowej **wirtualnej maszynie Windows 11 (vmware)**, otrzymałem następujące wyniki:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku pliki .exe są bezużyteczne, więc zignoruj je, brakujące DLL pochodziły z:

| Usługa                         | Dll                | Wiersz poleceń                                                      |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Harmonogram zadań (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Usługa zasad diagnostycznych (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Po znalezieniu tego, natrafiłem na interesujący post na blogu, który również wyjaśnia, jak [**wykorzystać WptsExtensions.dll do eskalacji uprawnień**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). To właśnie **zamierzamy teraz zrobić**.

### Wykorzystanie

Aby **zwiększyć uprawnienia**, zamierzamy przejąć bibliotekę **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy tylko **wygenerować złośliwą bibliotekę DLL**.

Możesz [**spróbować użyć któregoś z tych przykładów**](./#creating-and-compiling-dlls). Możesz uruchamiać ładunki takie jak: uzyskać powłokę rev, dodać użytkownika, wykonać beacon...

{% hint style="warning" %}
Zauważ, że **nie wszystkie usługi są uruchamiane** z kontem **`NT AUTHORITY\SYSTEM`**, niektóre są również uruchamiane z kontem **`NT AUTHORITY\LOCAL SERVICE`**, które ma **mniej uprawnień**, i nie będziesz mógł utworzyć nowego użytkownika, nadużyć jego uprawnień.\
Jednak ten użytkownik ma uprawnienie **`seImpersonate`**, więc możesz użyć [**pakietu potato do eskalacji uprawnień**](../roguepotato-and-printspoofer.md). W tym przypadku powłoka rev jest lepszą opcją niż próba utworzenia użytkownika.
{% endhint %}

W chwili pisania usługa **Harmonogram zadań** jest uruchamiana z kontem **NT AUTHORITY\SYSTEM**.

Po **wygenerowaniu złośliwej biblioteki DLL** (_w moim przypadku użyłem powłoki rev x64 i uzyskałem powłokę, ale defender ją zabił, ponieważ pochodziła z msfvenom_), zapisz ją w zapisalnym folderze Ścieżki Systemowej pod nazwą **WptsExtensions.dll** i **zrestartuj** komputer (lub zrestartuj usługę lub wykonaj inne czynności, aby ponownie uruchomić dotkniętą usługę/program).

Gdy usługa zostanie ponownie uruchomiona, **biblioteka DLL powinna zostać załadowana i wykonana** (możesz **ponownie użyć** sztuczki z **procmonem**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).
