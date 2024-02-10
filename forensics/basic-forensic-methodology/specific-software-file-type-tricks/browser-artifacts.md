# 브라우저 아티팩트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 브라우저 아티팩트 <a href="#id-3def" id="id-3def"></a>

브라우저 아티팩트에는 탐색 기록, 즐겨찾기 및 캐시 데이터와 같은 웹 브라우저에 의해 저장된 다양한 유형의 데이터가 포함됩니다. 이러한 아티팩트는 운영 체제 내의 특정 폴더에 보관되며, 브라우저마다 위치와 이름이 다르지만 일반적으로 유사한 데이터 유형을 저장합니다.

가장 일반적인 브라우저 아티팩트 요약은 다음과 같습니다:

- **탐색 기록**: 사용자가 웹 사이트를 방문한 기록으로, 악성 사이트 방문을 식별하는 데 유용합니다.
- **자동 완성 데이터**: 자주 검색한 내용을 기반으로 한 제안으로, 탐색 기록과 결합하여 통찰력을 제공합니다.
- **즐겨찾기**: 사용자가 빠르게 액세스하기 위해 저장한 사이트.
- **확장 프로그램 및 애드온**: 사용자가 설치한 브라우저 확장 프로그램 또는 애드온.
- **캐시**: 웹 콘텐츠(예: 이미지, JavaScript 파일)를 저장하여 웹 사이트 로딩 시간을 개선하는 데 유용한 포렌식 분석에 가치가 있습니다.
- **로그인**: 저장된 로그인 자격 증명.
- **파비콘**: 탭 및 즐겨찾기에 표시되는 웹 사이트와 관련된 아이콘으로, 사용자 방문에 대한 추가 정보로 유용합니다.
- **브라우저 세션**: 열린 브라우저 세션과 관련된 데이터.
- **다운로드**: 브라우저를 통해 다운로드한 파일의 기록.
- **양식 데이터**: 웹 양식에 입력한 정보로, 자동 완성 제안을 위해 저장됩니다.
- **썸네일**: 웹 사이트의 미리보기 이미지.
- **사용자 정의 사전.txt**: 사용자가 브라우저 사전에 추가한 단어.


## Firefox

Firefox는 프로필 내에서 사용자 데이터를 조직화하며, 운영 체제에 따라 특정 위치에 저장됩니다:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

이러한 디렉토리 내의 `profiles.ini` 파일은 사용자 프로필을 나열합니다. 각 프로필의 데이터는 `profiles.ini`와 동일한 디렉토리에 위치한 `profiles.ini` 내의 `Path` 변수로 지정된 폴더에 저장됩니다. 프로필 폴더가 없는 경우 삭제되었을 수 있습니다.

각 프로필 폴더 내에서 여러 중요한 파일을 찾을 수 있습니다:

- **places.sqlite**: 탐색 기록, 즐겨찾기 및 다운로드를 저장합니다. Windows에서 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)와 같은 도구를 사용하여 탐색 기록 데이터에 액세스할 수 있습니다.
- 특정 SQL 쿼리를 사용하여 탐색 기록 및 다운로드 정보를 추출할 수 있습니다.
- **bookmarkbackups**: 즐겨찾기의 백업을 포함합니다.
- **formhistory.sqlite**: 웹 양식 데이터를 저장합니다.
- **handlers.json**: 프로토콜 핸들러를 관리합니다.
- **persdict.dat**: 사용자 정의 사전 단어.
- **addons.json** 및 **extensions.sqlite**: 설치된 애드온 및 확장 프로그램에 대한 정보.
- **cookies.sqlite**: 쿠키 저장소로, Windows에서 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)를 사용하여 검사할 수 있습니다.
- **cache2/entries** 또는 **startupCache**: 캐시 데이터로, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)와 같은 도구를 통해 액세스할 수 있습니다.
- **favicons.sqlite**: 파비콘을 저장합니다.
- **prefs.js**: 사용자 설정 및 기본 설정.
- **downloads.sqlite**: 이전 다운로드 데이터베이스로, 현재는 places.sqlite에 통합되었습니다.
- **thumbnails**: 웹 사이트 썸네일.
- **logins.json**: 암호화된 로그인 정보.
- **key4.db** 또는 **key3.db**: 민감한 정보를 보호하기 위한 암호화 키를 저장합니다.

또한, `prefs.js`에서 `browser.safebrowsing` 항목을 검색하여 안전한 탐색 기능이 활성화되었는지 비활성화되었는지 확인할 수 있습니다.


마스터 암호를 복호화하려면 [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)를 사용할 수 있습니다.\
다음 스크립트와 호출을 사용하여 브루트 포스할 암호 파일을 지정할 수 있습니다:

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

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome은 운영 체제에 따라 사용자 프로필을 특정 위치에 저장합니다:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

이러한 디렉토리 내에서 대부분의 사용자 데이터는 **Default/** 또는 **ChromeDefaultData/** 폴더에 저장됩니다. 다음 파일에는 중요한 데이터가 저장됩니다:

- **History**: URL, 다운로드 및 검색 키워드가 포함되어 있습니다. Windows에서는 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)를 사용하여 히스토리를 읽을 수 있습니다. "Transition Type" 열에는 사용자가 링크를 클릭하거나 URL을 입력하거나 양식을 제출하거나 페이지를 새로 고침하는 등 다양한 의미가 있습니다.
- **Cookies**: 쿠키를 저장합니다. 검사를 위해 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)를 사용할 수 있습니다.
- **Cache**: 캐시된 데이터를 보유합니다. Windows 사용자는 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)를 활용하여 검사할 수 있습니다.
- **Bookmarks**: 사용자 북마크입니다.
- **Web Data**: 양식 기록이 포함되어 있습니다.
- **Favicons**: 웹 사이트 아이콘이 저장됩니다.
- **Login Data**: 사용자 이름과 비밀번호와 같은 로그인 자격 증명이 포함됩니다.
- **Current Session**/**Current Tabs**: 현재 브라우징 세션 및 열린 탭에 대한 데이터입니다.
- **Last Session**/**Last Tabs**: Chrome이 닫히기 전 마지막 세션에서 활성화된 사이트에 대한 정보입니다.
- **Extensions**: 브라우저 확장 프로그램과 애드온을 위한 디렉토리입니다.
- **Thumbnails**: 웹 사이트 썸네일이 저장됩니다.
- **Preferences**: 플러그인, 확장 프로그램, 팝업, 알림 등의 설정을 포함한 정보가 있는 파일입니다.
- **브라우저 내장 안티 피싱**: 안티 피싱 및 악성 코드 보호 기능이 활성화되어 있는지 확인하려면 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`를 실행합니다. 출력에서 `{"enabled: true,"}`를 찾습니다.


## **SQLite DB 데이터 복구**

이전 섹션에서 확인할 수 있듯이, Chrome과 Firefox는 데이터를 저장하기 위해 **SQLite** 데이터베이스를 사용합니다. [**sqlparse**](https://github.com/padfoot999/sqlparse) **또는** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) 도구를 사용하여 삭제된 항목을 복구할 수 있습니다.

## **Internet Explorer 11**

Internet Explorer 11은 저장된 정보와 해당 세부 정보를 쉽게 액세스하고 관리하기 위해 다양한 위치에 데이터 및 메타데이터를 관리합니다.

### 메타데이터 저장
Internet Explorer의 메타데이터는 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (VX는 V01, V16 또는 V24일 수 있음)에 저장됩니다. 이와 함께 `V01.log` 파일은 `WebcacheVX.data`와 수정 시간의 불일치를 보여줄 수 있으며, `esentutl /r V01 /d`를 사용하여 복구해야 할 수도 있습니다. 이 ESE 데이터베이스에 저장된 메타데이터는 photorec 및 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)와 같은 도구를 사용하여 복구하고 검사할 수 있습니다. **Containers** 테이블 내에서는 각 데이터 세그먼트가 저장된 특정 테이블 또는 컨테이너를 식별할 수 있으며, 이는 Skype와 같은 다른 Microsoft 도구에 대한 캐시 세부 정보를 포함합니다.

### 캐시 검사
[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 도구를 사용하여 캐시를 검사할 수 있으며, 캐시 데이터 추출 폴더 위치가 필요합니다. 캐시의 메타데이터에는 파일 이름, 디렉토리, 액세스 횟수, URL 원본 및 캐시 생성, 액세스, 수정 및 만료 시간을 나타내는 타임스탬프가 포함됩니다.

### 쿠키 관리
[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)를 사용하여 쿠키를 탐색할 수 있으며, 메타데이터에는 이름, URL, 액세스 횟수 및 다양한 시간 관련 세부 정보가 포함됩니다. 영구적인 쿠키는 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`에 저장되며, 세션 쿠키는 메모리에 저장됩니다.

### 다운로드 세부 정보
[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)를 통해 다운로드 메타데이터에 액세스할 수 있으며, 특정 컨테이너에는 URL, 파일 유형 및 다운로드 위치와 같은 데이터가 저장됩니다. 물리적인 파일은 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`에서 찾을 수 있습니다.

### 브라우징 기록
[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)를 사용하여 브라우징 기록을 검토할 수 있으며, 추출된 기록 파일의 위치와 Internet Explorer의 구성이 필요합니다. 여기서 메타데이터에는 수정 및 액세스 시간과 액세스 횟수가 포함됩니다. 기록 파일은 `%userprofile%\Appdata\Local\Microsoft\Windows\History`에 위치합니다.

### 입력된 URL
입력된 URL과 사용 시간은 레지스트리의 `NTUSER.DAT`에서 `Software\Microsoft\InternetExplorer\TypedURLs` 및 `Software\Microsoft\InternetExplorer\TypedURLsTime`에 저장되며, 사용자가 입력한 마지막 50개의 URL과 마지막 입력 시간을 추적합니다.


## Microsoft Edge

Microsoft Edge는 사용자 데이터를 `%userprofile%\Appdata\Local\Packages`에 저장합니다. 다양한 데이터 유형의 경로는 다음과 같습니다:

- **프로필 경로**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **히스토리, 쿠키 및 다운로드**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **설정, 북마크 및 읽기 목록**: `C
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**telegram 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* 여러분의 해킹 기술을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
