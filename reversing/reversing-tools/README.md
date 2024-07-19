{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}

# Wasm逆コンパイルとWatコンパイルガイド

**WebAssembly**の領域では、**逆コンパイル**と**コンパイル**のためのツールが開発者にとって不可欠です。このガイドでは、**Wasm (WebAssemblyバイナリ)**および**Wat (WebAssemblyテキスト)**ファイルを扱うためのオンラインリソースとソフトウェアを紹介します。

## オンラインツール

- WasmをWatに**逆コンパイル**するには、[Wabtのwasm2watデモ](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)が便利です。
- WatをWasmに**コンパイル**するには、[Wabtのwat2wasmデモ](https://webassembly.github.io/wabt/demo/wat2wasm/)が役立ちます。
- 別の逆コンパイルオプションは[web-wasmdec](https://wwwg.github.io/web-wasmdec/)で見つけることができます。

## ソフトウェアソリューション

- より堅牢なソリューションとして、[PNF SoftwareのJEB](https://www.pnfsoftware.com/jeb/demo)が広範な機能を提供します。
- オープンソースプロジェクト[wasmdec](https://github.com/wwwg/wasmdec)も逆コンパイルタスクに利用可能です。

# .Net逆コンパイルリソース

.Netアセンブリの逆コンパイルは、以下のツールを使用して実行できます。

- [ILSpy](https://github.com/icsharpcode/ILSpy)は、[Visual Studio Code用のプラグイン](https://github.com/icsharpcode/ilspy-vscode)も提供しており、クロスプラットフォームでの使用が可能です。
- **逆コンパイル**、**修正**、および**再コンパイル**を含むタスクには、[dnSpy](https://github.com/0xd4d/dnSpy/releases)が強く推奨されます。メソッドを**右クリック**して**Modify Method**を選択することで、コードの変更が可能です。
- [JetBrainsのdotPeek](https://www.jetbrains.com/es-es/decompiler/)も.Netアセンブリの逆コンパイルのための別の選択肢です。

## DNSpyによるデバッグとロギングの強化

### DNSpyロギング
DNSpyを使用してファイルに情報をログするには、以下の.Netコードスニペットを組み込みます。

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpyデバッグ
DNSpyを使用した効果的なデバッグのためには、デバッグのために**Assembly属性**を調整する一連の手順が推奨され、デバッグを妨げる可能性のある最適化が無効にされます。このプロセスには、`DebuggableAttribute`設定の変更、アセンブリの再コンパイル、および変更の保存が含まれます。

さらに、**IIS**によって実行される.Netアプリケーションをデバッグするには、`iisreset /noforce`を実行してIISを再起動します。デバッグのためにDNSpyをIISプロセスにアタッチするには、DNSpy内で**w3wp.exe**プロセスを選択し、デバッグセッションを開始するように指示します。

デバッグ中に読み込まれたモジュールの包括的なビューを得るためには、DNSpyの**Modules**ウィンドウにアクセスし、すべてのモジュールを開いてアセンブリをソートして、ナビゲーションとデバッグを容易にすることが推奨されます。

このガイドは、WebAssemblyと.Net逆コンパイルの本質を要約し、開発者がこれらのタスクを容易にナビゲートできる道筋を提供します。

## **Java逆コンパイラ**
Javaバイトコードを逆コンパイルするために、これらのツールが非常に役立ちます:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLLのデバッグ**
### IDAを使用
- **Rundll32**は、64ビットおよび32ビットバージョンの特定のパスからロードされます。
- **Windbg**がデバッガとして選択され、ライブラリのロード/アンロード時に一時停止するオプションが有効になります。
- 実行パラメータにはDLLパスと関数名が含まれます。この設定により、各DLLのロード時に実行が停止します。

### x64dbg/x32dbgを使用
- IDAと同様に、**rundll32**はコマンドラインの修正を加えてDLLと関数を指定してロードされます。
- DLLエントリでブレークするように設定が調整され、希望するDLLエントリポイントでブレークポイントを設定できます。

### 画像
- 実行停止ポイントと設定はスクリーンショットを通じて示されています。

## **ARM & MIPS**
- エミュレーションには、[arm_now](https://github.com/nongiach/arm_now)が便利なリソースです。

## **シェルコード**
### デバッグ技術
- **Blobrunner**と**jmp2it**は、メモリにシェルコードを割り当て、Idaまたはx64dbgでデバッグするためのツールです。
- Blobrunner [リリース](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [コンパイル版](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**はGUIベースのシェルコードエミュレーションと検査を提供し、ファイルとしてのシェルコード処理と直接シェルコード処理の違いを強調します。

### デオブフスケーションと分析
- **scdbg**はシェルコード関数とデオブフスケーション機能に関する洞察を提供します。
%%%bash
scdbg.exe -f shellcode # 基本情報
scdbg.exe -f shellcode -r # 分析レポート
scdbg.exe -f shellcode -i -r # インタラクティブフック
scdbg.exe -f shellcode -d # デコードされたシェルコードをダンプ
scdbg.exe -f shellcode /findsc # 開始オフセットを見つける
scdbg.exe -f shellcode /foff 0x0000004D # オフセットから実行
%%%

- シェルコードの逆アセンブルには**CyberChef**を使用: [CyberChefレシピ](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- すべての命令を`mov`に置き換えるオブフスケータです。
- 有用なリソースには[YouTubeの説明](https://www.youtube.com/watch?v=2VF_wPkiBJY)と[PDFスライド](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)があります。
- **demovfuscator**はmovfuscatorのオブフスケーションを逆転させる可能性があり、`libcapstone-dev`と`libz3-dev`の依存関係が必要で、[keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)をインストールする必要があります。

## **Delphi**
- Delphiバイナリには、[IDR](https://github.com/crypto2011/IDR)が推奨されます。

# コース

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(バイナリデオブフスケーション\)



{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
