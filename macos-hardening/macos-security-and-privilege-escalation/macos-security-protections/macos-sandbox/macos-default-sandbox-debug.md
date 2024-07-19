# macOS Default Sandbox Debug

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

Σε αυτή τη σελίδα μπορείτε να βρείτε πώς να δημιουργήσετε μια εφαρμογή για να εκτελείτε αυθαίρετες εντολές από μέσα από το προεπιλεγμένο sandbox του macOS:

1. Συγκεντρώστε την εφαρμογή:

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

Συγκεντρώστε το εκτελώντας: `clang -framework Foundation -o SandboxedShellApp main.m`

2. Δημιουργήστε το πακέτο `.app`
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
3. Ορίστε τα δικαιώματα

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

{% tab title="sandbox + downloads" %}
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

4. Υπογράψτε την εφαρμογή (χρειάζεται να δημιουργήσετε ένα πιστοποιητικό στο keychain)
```bash
codesign --entitlements entitlements.plist -s "YourIdentity" SandboxedShellApp.app
./SandboxedShellApp.app/Contents/MacOS/SandboxedShellApp

# An d in case you need this in the future
codesign --remove-signature SandboxedShellApp.app
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
