# KIOSKからの脱出

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングテクニックを共有してください。

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗聴マルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

## 物理デバイスのチェック

|   コンポーネント   | アクション                                                               |
| ------------- | -------------------------------------------------------------------- |
| 電源ボタン  | デバイスの電源を切って再度入れると、スタート画面が表示される可能性があります      |
| 電源ケーブル   | 電源が一時的に切断されたときにデバイスが再起動するかどうかを確認します   |
| USBポート     | より多くのショートカットを持つ物理キーボードを接続します                        |
| イーサネット      | ネットワークスキャンやスニッフィングにより、さらなる攻撃が可能になるかもしれません             |


## GUIアプリケーション内での可能なアクションをチェック

**一般的なダイアログ**は、**ファイルの保存**、**ファイルの開く**、フォントの選択、色の選択などのオプションです。ほとんどの場合、これらのオプションにアクセスできれば、**完全なエクスプローラ機能**を利用できます。

* 閉じる/閉じるとして保存
* 開く/開くとして
* 印刷
* エクスポート/インポート
* 検索
* スキャン

次のことをチェックすべきです：

* ファイルの変更または新規作成
* シンボリックリンクの作成
* 制限された領域へのアクセス
* 他のアプリの実行

### コマンドの実行

おそらく`開くとして`オプションを使用して、ある種のシェルを開いたり実行したりできるかもしれません。

#### Windows

例えば _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ ここでコマンドを実行するために使用できる他のバイナリを見つける: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ ここで詳細を確認: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### パス制限のバイパス

* **環境変数**: 特定のパスを指す多くの環境変数があります
* **その他のプロトコル**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **シンボリックリンク**
* **ショートカット**: CTRL+N (新しいセッションを開く), CTRL+R (コマンドを実行), CTRL+SHIFT+ESC (タスクマネージャ), Windows+E (エクスプローラを開く), CTRL-B, CTRL-I (お気に入り), CTRL-H (履歴), CTRL-L, CTRL-O (ファイル/開くダイアログ), CTRL-P (印刷ダイアログ), CTRL-S (名前を付けて保存)
* 隠し管理メニュー: CTRL-ALT-F8, CTRL-ESC-F9
* **シェルURI**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNCパス**: 共有フォルダに接続するパス。ローカルマシンのC$に接続してみてください ("\\\127.0.0.1\c$\Windows\System32")
* **その他のUNCパス:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### バイナリのダウンロード

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
レジストリエディタ: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### ブラウザからファイルシステムにアクセス

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |
### ショートカット

* スティッキーキー – SHIFTを5回押す
* マウスキー – SHIFT+ALT+NUMLOCK
* ハイコントラスト – SHIFT+ALT+PRINTSCN
* トグルキー – NUMLOCKを5秒間押し続ける
* フィルターキー – 右SHIFTを12秒間押し続ける
* WINDOWS+F1 – Windows検索
* WINDOWS+D – デスクトップを表示
* WINDOWS+E – Windowsエクスプローラーを起動
* WINDOWS+R – 実行
* WINDOWS+U – 利便性センター
* WINDOWS+F – 検索
* SHIFT+F10 – コンテキストメニュー
* CTRL+SHIFT+ESC – タスクマネージャー
* CTRL+ALT+DEL – 新しいWindowsバージョンのスプラッシュスクリーン
* F1 – ヘルプ F3 – 検索
* F6 – アドレスバー
* F11 – Internet Explorer内でのフルスクリーンの切り替え
* CTRL+H – Internet Explorerの履歴
* CTRL+T – Internet Explorer – 新しいタブ
* CTRL+N – Internet Explorer – 新しいページ
* CTRL+O – ファイルを開く
* CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

### スワイプ

* 左側から右側にスワイプしてすべての開いているウィンドウを表示し、KIOSKアプリを最小化してOS全体に直接アクセスします。
* 右側から左側にスワイプしてアクションセンターを開き、KIOSKアプリを最小化してOS全体に直接アクセスします。
* 上端からスワイプしてフルスクリーンモードで開いているアプリのタイトルバーを表示します。
* 下端からスワイプしてフルスクリーンアプリでタスクバーを表示します。

### Internet Explorerのトリック

#### 'Image Toolbar'

画像をクリックすると画像の左上に表示されるツールバーです。保存、印刷、メール送信、エクスプローラーで「マイピクチャー」を開くことができます。KioskはInternet Explorerを使用する必要があります。

#### シェルプロトコル

これらのURLを入力してエクスプローラービューを取得します：

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> コントロールパネル
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> マイコンピューター
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> マイネットワークプレイス
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### ファイル拡張子の表示

詳細は次のページを参照してください：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## ブラウザのトリック

iKatバージョンのバックアップ：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

JavaScriptを使用して共通のダイアログを作成し、ファイルエクスプローラーにアクセスします： `document.write('<input/type=file>')`\
出典：https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### ジェスチャーとボタン

* 4本（または5本）の指で上にスワイプ/ホームボタンを2回タップ：マルチタスクビューを表示してアプリを切り替える
* 4本または5本の指で片方向にスワイプ：次の/前のアプリに切り替える
* 5本の指で画面をつまむ/ホームボタンをタッチ/画面下部から上に素早く1本の指でスワイプ：ホームにアクセス
* 画面下部から1-2インチ上に1本の指でゆっくりスワイプ：ドックが表示されます
* 画面上部から1本の指で下にスワイプ：通知を表示します
* 画面の右上隅から1本の指で下にスワイプ：iPad Proのコントロールセンターを表示します
* 画面の左から1-2インチの1本の指でスワイプ：今日のビューを表示します
* 画面の中央から右または左に素早く1本の指でスワイプ：次の/前のアプリに切り替える
* 上部右隅のOn/**Off**/Sleepボタンを押し続ける + スライドを右まで移動する：電源を切る
* 上部右隅のOn/**Off**/Sleepボタンを押し続ける + ホームボタンを数秒押し続ける：強制的に電源を切る
* 上部右隅のOn/**Off**/Sleepボタンを押し続ける + ホームボタンを素早く押す：画面左下にポップアップするスクリーンショットを撮影します。両方のボタンを同時に非常に短く押すと、数秒間押し続けるかのようにハードパワーオフが実行されます。

### ショートカット

iPadキーボードまたはUSBキーボードアダプターを持っている必要があります。アプリケーションからの脱出に役立つショートカットのみがここに表示されます。

| キー | 名前         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### システムショートカット

これらのショートカットはiPadの視覚設定および音声設定に関連しています。

| ショートカット | アクション                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 画面を暗くする                                                                    |
| F2       | 画面を明るくする                                                                |
| F7       | 前の曲に戻る                                                                  |
| F8       | 再生/一時停止                                                                     |
| F9       | 次の曲にスキップ                                                                      |
| F10      | ミュート                                                                           |
| F11      | 音量を下げる                                                                |
| F12      | 音量を上げる                                                                |
| ⌘ Space  | 利用可能な言語のリストを表示します。選択するには、再度スペースバーをタップします。 |

#### iPadナビゲーション

| ショートカット                                           | アクション                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに移動                                              |
| ⌘⇧H (Command-Shift-H)                              | ホームに移動                                              |
| ⌘ (Space)                                          | スポットライトを開く                                          |
| ⌘⇥ (Command-Tab)                                   | 最後に使用した10個のアプリをリスト表示                                 |
| ⌘\~                                                | 最後のアプリに移動                                       |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（左下にホバーして保存または操作） |
| ⌘⇧4                                                | スクリーンショットを撮影してエディターで開く                    |
| ⌘を押して押し続ける                                   | アプリ用の利用可能なショートカットのリスト                 |
| ⌘⌥D (Command-Option/Alt-D)                         | ドックを表示                                      |
| ^⌥H (Control-Option-H)                             | ホームボタン                                             |
| ^⌥H H (Control-Option-H-H)                         | マルチタスクバーを表示                                      |
| ^⌥I (Control-Option-i)                             | アイテム選択                                             |
| Escape                                             | 戻るボタン                                             |
| → (右矢印)                                    | 次のアイテム                                               |
| ← (左矢印)                                     | 前のアイテム                                           |
| ↑↓ (上矢印、下矢印)                          | 選択したアイテムを同時にタップ                        |
| ⌥ ↓ (Option-下矢印)                            | 下にスクロール                                             |
| ⌥↑ (Option-上矢印)                               | 上にスクロール                                               |
| ⌥←または⌥→ (Option-左矢印またはOption-右矢印) | 左または右にスクロール                                    |
| ^⌥S (Control-Option-S)                             | VoiceOverスピーチのオン/オフ                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替える                              |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                         |
| ←+→、次にOption + ←またはOption+→                   | ドックを通じてナビゲート                                   |
#### Safariのショートカット

| ショートカット           | アクション                           |
| ----------------------- | ---------------------------------- |
| ⌘L (Command-L)          | ロケーションを開く                     |
| ⌘T                      | 新しいタブを開く                      |
| ⌘W                      | 現在のタブを閉じる                    |
| ⌘R                      | 現在のタブを更新                      |
| ⌘.                      | 現在のタブの読み込みを停止              |
| ^⇥                      | 次のタブに切り替え                     |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動                         |
| ⌘L                      | テキスト入力/URLフィールドを選択して変更 |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く（複数回使用可能） |
| ⌘\[                     | ブラウジング履歴で1ページ戻る            |
| ⌘]                      | ブラウジング履歴で1ページ進む            |
| ⌘⇧R                     | リーダーモードをアクティブにする          |

#### メールのショートカット

| ショートカット           | アクション                   |
| ----------------------- | ------------------------ |
| ⌘L                      | ロケーションを開く             |
| ⌘T                      | 新しいタブを開く              |
| ⌘W                      | 現在のタブを閉じる            |
| ⌘R                      | 現在のタブを更新              |
| ⌘.                      | 現在のタブの読み込みを停止       |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索         |

## 参考文献

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されていないかをチェックするための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする。
* **ハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>
{% endhint %}
