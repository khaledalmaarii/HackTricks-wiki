# 브라우저 아티팩트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 제로부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 브라우저 아티팩트 <a href="#id-3def" id="id-3def"></a>

브라우저 아티팩트에는 네비게이션 히스토리, 북마크, 캐시 데이터 등 웹 브라우저에 의해 저장된 다양한 유형의 데이터가 포함됩니다. 이러한 아티팩트는 운영 체제 내의 특정 폴더에 보관되며 브라우저마다 위치와 이름이 다르지만 일반적으로 유사한 데이터 유형을 저장합니다.

가장 일반적인 브라우저 아티팩트 요약은 다음과 같습니다:

* **네비게이션 히스토리**: 사용자가 웹 사이트를 방문한 내역을 추적하여 악성 사이트 방문을 식별하는 데 유용합니다.
* **자동완성 데이터**: 빈번한 검색을 기반으로 하는 제안으로, 네비게이션 히스토리와 결합되면 통찰을 제공합니다.
* **북마크**: 사용자가 빠르게 액세스하기 위해 저장한 사이트.
* **확장 프로그램 및 애드온**: 사용자가 설치한 브라우저 확장 프로그램 또는 애드온.
* **캐시**: 웹 콘텐츠(예: 이미지, JavaScript 파일)를 저장하여 웹 사이트 로딩 시간을 단축하는 데 유용하며 포렌식 분석에 가치가 있습니다.
* **로그인 정보**: 저장된 로그인 자격 증명.
* **파비콘**: 탭 및 북마크에 나타나는 웹 사이트와 관련된 아이콘으로, 사용자 방문에 대한 추가 정보로 유용합니다.
* **브라우저 세션**: 열린 브라우저 세션과 관련된 데이터.
* **다운로드**: 브라우저를 통해 다운로드한 파일의 기록.
* **양식 데이터**: 웹 양식에 입력된 정보로, 미래 자동 입력 제안을 위해 저장됩니다.
* **썸네일**: 웹 사이트의 미리 보기 이미지.
* **사용자 지정 사전.txt**: 사용자가 브라우저 사전에 추가한 단어.

## 파이어폭스

파이어폭스는 프로필 내에서 사용자 데이터를 구성하며, 운영 체제에 따라 특정 위치에 저장됩니다:

* **리눅스**: `~/.mozilla/firefox/`
* **맥OS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **윈도우**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

이러한 디렉토리 내에는 `profiles.ini` 파일이 있어 사용자 프로필을 나열합니다. 각 프로필의 데이터는 `profiles.ini`와 동일한 디렉토리에 위치한 `profiles.ini` 내의 `Path` 변수로 명명된 폴더에 저장됩니다. 프로필 폴더가 누락된 경우 삭제된 것일 수 있습니다.

각 프로필 폴더 내에서 여러 중요한 파일을 찾을 수 있습니다:

* **places.sqlite**: 히스토리, 북마크 및 다운로드를 저장합니다. Windows의 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)와 같은 도구를 사용하여 히스토리 데이터에 액세스할 수 있습니다.
* 특정 SQL 쿼리를 사용하여 히스토리 및 다운로드 정보를 추출합니다.
* **bookmarkbackups**: 북마크의 백업을 포함합니다.
* **formhistory.sqlite**: 웹 양식 데이터를 저장합니다.
* **handlers.json**: 프로토콜 핸들러를 관리합니다.
* **persdict.dat**: 사용자 지정 사전 단어.
* **addons.json** 및 **extensions.sqlite**: 설치된 애드온 및 확장 프로그램 정보.
* **cookies.sqlite**: 쿠키 저장소로, Windows에서는 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)를 사용하여 검사할 수 있습니다.
* **cache2/entries** 또는 **startupCache**: 캐시 데이터로, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html)와 같은 도구를 통해 액세스할 수 있습니다.
* **favicons.sqlite**: 파비콘을 저장합니다.
* **prefs.js**: 사용자 설정 및 환경 설정.
* **downloads.sqlite**: 이전 다운로드 데이터베이스로, 현재는 places.sqlite에 통합되어 있습니다.
* **thumbnails**: 웹 사이트 썸네일.
* **logins.json**: 암호화된 로그인 정보.
* **key4.db** 또는 **key3.db**: 민감한 정보 보호를 위한 암호화 키를 저장합니다.

또한, 브라우저의 안티 피싱 설정을 확인하려면 `prefs.js`에서 `browser.safebrowsing` 항목을 검색하여 안전한 브라우징 기능이 활성화되었는지 비활성화되었는지 확인할 수 있습니다.

마스터 암호를 복호화하려면 [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)를 사용할 수 있습니다. 다음 스크립트와 호출을 사용하여 브루트 포스할 암호 파일을 지정할 수 있습니다:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Google Chrome은 운영 체제에 따라 특정 위치에 사용자 프로필을 저장합니다:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

이러한 디렉토리 내에서 대부분의 사용자 데이터는 **Default/** 또는 **ChromeDefaultData/** 폴더에서 찾을 수 있습니다. 다음 파일에 중요한 데이터가 포함되어 있습니다:

* **History**: URL, 다운로드 및 검색 키워드를 포함합니다. Windows에서는 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html)를 사용하여 히스토리를 읽을 수 있습니다. "Transition Type" 열에는 사용자가 링크를 클릭하거나 URL을 입력하거나 양식을 제출하거나 페이지를 새로 고침하는 등 다양한 의미가 포함됩니다.
* **Cookies**: 쿠키를 저장합니다. 검사를 위해 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html)를 사용할 수 있습니다.
* **Cache**: 캐시된 데이터를 보유합니다. Windows 사용자는 [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html)를 활용하여 검사할 수 있습니다.
* **Bookmarks**: 사용자 북마크입니다.
* **Web Data**: 양식 기록을 포함합니다.
* **Favicons**: 웹 사이트의 아이콘을 저장합니다.
* **Login Data**: 사용자 이름 및 비밀번호와 같은 로그인 자격 증명을 포함합니다.
* **Current Session**/**Current Tabs**: 현재 브라우징 세션 및 열린 탭에 대한 데이터입니다.
* **Last Session**/**Last Tabs**: Chrome이 닫히기 전 마지막 세션 중 활성 상태인 사이트에 대한 정보입니다.
* **Extensions**: 브라우저 확장 프로그램 및 애드온을 위한 디렉토리입니다.
* **Thumbnails**: 웹 사이트 썸네일을 저장합니다.
* **Preferences**: 플러그인, 확장 프로그램, 팝업, 알림 등의 설정을 포함한 정보가 풍부한 파일입니다.
* **브라우저 내장 안티 피싱**: 안티 피싱 및 악성 코드 보호가 활성화되어 있는지 확인하려면 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`를 실행합니다. 출력에서 `{"enabled: true,"}`를 찾습니다.

## **SQLite DB 데이터 복구**

이전 섹션에서 관찰할 수 있듯이 Chrome과 Firefox는 데이터를 저장하기 위해 **SQLite** 데이터베이스를 사용합니다. 삭제된 항목을 복구할 수 있는 도구로 [**sqlparse**](https://github.com/padfoot999/sqlparse) 또는 [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)를 사용할 수 있습니다.

## **Internet Explorer 11**

Internet Explorer 11은 다양한 위치에 데이터 및 메타데이터를 관리하여 저장된 정보와 해당 세부 정보를 쉽게 액세스하고 관리할 수 있도록 지원합니다.

### 메타데이터 저장

Internet Explorer의 메타데이터는 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`에 저장됩니다 (VX는 V01, V16 또는 V24일 수 있음). 이와 함께 `V01.log` 파일은 `WebcacheVX.data`와 수정 시간 불일치를 보여줄 수 있으며, `esentutl /r V01 /d`를 사용하여 복구가 필요할 수 있습니다. 이 ESE 데이터베이스에 저장된 메타데이터는 photorec 및 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)와 같은 도구를 사용하여 복구하고 검사할 수 있습니다. **Containers** 테이블 내에서 각 데이터 세그먼트가 저장된 특정 테이블 또는 컨테이너를 식별할 수 있으며, 이는 Skype와 같은 다른 Microsoft 도구의 캐시 세부 정보를 포함합니다.

### 캐시 검사

[IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) 도구를 사용하여 캐시를 검사할 수 있으며, 캐시 데이터 추출 폴더 위치가 필요합니다. 캐시에 대한 메타데이터에는 파일 이름, 디렉토리, 액세스 횟수, URL 원본 및 캐시 생성, 액세스, 수정 및 만료 시간을 나타내는 타임스탬프가 포함됩니다.

### 쿠키 관리

쿠키는 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html)를 사용하여 탐색할 수 있으며, 메타데이터에는 이름, URL, 액세스 횟수 및 다양한 시간 관련 세부 정보가 포함됩니다. 영구 쿠키는 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`에 저장되며, 세션 쿠키는 메모리에 저장됩니다.

### 다운로드 세부 정보

다운로드 메타데이터는 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)를 통해 액세스할 수 있으며, 특정 컨테이너에는 URL, 파일 유형 및 다운로드 위치와 같은 데이터가 저장됩니다. 물리적 파일은 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`에서 찾을 수 있습니다.

### 브라우징 히스토리

브라우징 히스토리를 검토하려면 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)를 사용하고, 추출된 히스토리 파일의 위치와 Internet Explorer 구성을 필요로 합니다. 여기서 메타데이터에는 수정 및 액세스 시간과 액세스 횟수가 포함됩니다. 히스토리 파일은 `%userprofile%\Appdata\Local\Microsoft\Windows\History`에 있습니다.

### 입력된 URL

입력된 URL과 사용 시간은 레지스트리 내 `NTUSER.DAT`의 `Software\Microsoft\InternetExplorer\TypedURLs` 및 `Software\Microsoft\InternetExplorer\TypedURLsTime`에 저장되며, 사용자가 입력한 마지막 50개 URL과 마지막 입력 시간을 추적합니다.

## Microsoft Edge

Microsoft Edge는 사용자 데이터를 `%userprofile%\Appdata\Local\Packages`에 저장합니다. 다양한 데이터 유형의 경로는 다음과 같습니다:

* **프로필 경로**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **히스토리, 쿠키 및 다운로드**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **설정, 북마크 및 읽기 목록**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **캐시**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **최근 활성 세션**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 데이터는 `/Users/$User/Library/Safari`에 저장됩니다. 주요 파일은 다음과 같습니다:

* **History.db**: URL 및 방문 타임스탬프를 포함하는 `history_visits` 및 `history_items` 테이블이 포함되어 있습니다. 쿼리를 수행하려면 `sqlite3`를 사용합니다.
* **Downloads.plist**: 다운로드된 파일에 대한 정보입니다.
* **Bookmarks.plist**: 북마크된 URL을 저장합니다.
* **TopSites.plist**: 가장 자주 방문하는 사이트입니다.
* **Extensions.plist**: Safari 브라우저 확장 프로그램 목록입니다. 검색하려면 `plutil` 또는 `pluginkit`을 사용합니다.
* **UserNotificationPermissions.plist**: 푸시 알림을 허용하는 도메인입니다. 파싱하려면 `plutil`을 사용합니다.
* **LastSession.plist**: 마지막 세션의 탭입니다. 파싱하려면 `plutil`을 사용합니다.
* **브라우저 내장 안티 피싱**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`를 사용하여 활성화 여부를 확인합니다. 1로 응답하면 해당 기능이 활성화되어 있음을 나타냅니다.

## Opera

Opera 데이터는 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`에 저장되며, 히스토리 및 다운로드에 대한 Chrome의 형식을 공유합니다.

* **브라우저 내장 안티 피싱**: `fraud_protection_enabled`이 `true`로 설정되어 있는지 확인하여 검증합니다. `grep`를 사용합니다.

이러한 경로와 명령은 다른 웹 브라우저에 의해 저장된 브라우징 데이터에 액세스하고 이해하는 데 중요합니다.

## 참고 자료

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **책: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**로부터 제로에서 영웅까지 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:
* **HackTricks**에서 귀하의 **회사 광고를 보고** 싶거나 **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면 PR을 제출하여** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.
