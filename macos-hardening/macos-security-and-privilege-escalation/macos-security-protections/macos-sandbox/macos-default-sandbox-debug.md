# macOS 默认沙箱调试

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

在此页面中，您可以找到如何创建一个应用程序以从默认 macOS 沙箱内部启动任意命令：

1. 编译应用程序：

{% code title="main.m" %}
```objectivec
#include <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
while (true) {
char input[512];

printf("Enter command to run (or 'exit' to quit): ");
if (fgets(input, sizeof(input), stdin) == NULL) {
break;
}

// Remove newline character
size_t len = strlen(input);
if (len > 0 && input[len - 1] == '\n') {
input[len - 1] = '\0';
}

if (strcmp(input, "exit") == 0) {
break;
}

system(input);
}
}
return 0;
}
```
{% endcode %}

编译运行： `clang -framework Foundation -o SandboxedShellApp main.m`

2. 构建 `.app` 包
```bash
mkdir -p SandboxedShellApp.app/Contents/MacOS
mv SandboxedShellApp SandboxedShellApp.app/Contents/MacOS/

cat << EOF > SandboxedShellApp.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>com.example.SandboxedShellApp</string>
<key>CFBundleName</key>
<string>SandboxedShellApp</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleExecutable</key>
<string>SandboxedShellApp</string>
</dict>
</plist>
EOF
```
3. 定义权限

{% tabs %}
{% tab title="sandbox" %}
```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
EOF
```
{% endtab %}

{% tab title="沙箱 + 下载" %}
```bash
cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
<key>com.apple.security.files.downloads.read-write</key>
<true/>
</dict>
</plist>
EOF
```
{% endtab %}
{% endtabs %}

4. 签署应用程序（您需要在钥匙串中创建一个证书）
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# An d in case you need this in the future
codesign --remove-signature SandboxedShellApp.app
```
{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
