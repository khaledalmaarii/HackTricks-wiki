<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> <strong>qaStaHvIS</strong> <strong>AWS hacking</strong> <strong>zero</strong> <strong>hero</strong> <strong>Learn</strong></summary>

<strong>HackTricks</strong> <strong>support</strong> <strong>ways</strong> <strong>Other</strong>:

* <strong>PDF</strong> <strong>HackTricks</strong> <strong>download</strong> <strong>or</strong> <strong>HackTricks</strong> <strong>in</strong> <strong>advertised</strong> <strong>company</strong> <strong>your</strong> <strong>see</strong> <strong>**SUBSCRIPTION PLANS**</strong> <strong>[**Check**](https://github.com/sponsors/carlospolop)</strong>!
* <strong>swag</strong> <strong>HackTricks</strong> <strong>&</strong> <strong>PEASS</strong> <strong>official</strong> <strong>Get</strong> <strong>[**the**](https://peass.creator-spring.com)</strong>
* <strong>NFTs</strong> <strong>[**exclusive**](https://opensea.io/collection/the-peass-family)</strong> <strong>collection</strong> <strong>our</strong> <strong>[**The PEASS Family**](https://opensea.io/collection/the-peass-family)</strong>
* <strong>**Twitter**</strong> <strong>us</strong> <strong>**follow**</strong> <strong>or</strong> <strong>**telegram group**</strong> <strong>[**the**](https://t.me/peass)</strong> <strong>**group**</strong> <strong>💬</strong> <strong>**Discord group**</strong> <strong>[**Join**](https://discord.gg/hRep4RUj7f)</strong> <strong>**the**</strong>
* <strong>repos</strong> <strong>github</strong> <strong>[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)</strong> <strong>[**HackTricks**](https://github.com/carlospolop/hacktricks)</strong> <strong>the</strong> <strong>PRs</strong> <strong>submitting</strong> <strong>by</strong> <strong>tricks</strong> <strong>hacking</strong> <strong>your</strong> <strong>Share</strong>

</details>


# ECB

(ECB) Electronic Code Book - symmetric encryption scheme which **replaces each block of the clear text** by the **block of ciphertext**. It is the **simplest** encryption scheme. The main idea is to **split** the clear text into **blocks of N bits** (depends on the size of the block of input data, encryption algorithm) and then to encrypt (decrypt) each block of clear text using the only key.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Using ECB has multiple security implications:

* **Blocks from encrypted message can be removed**
* **Blocks from encrypted message can be moved around**

# Detection of the vulnerability

Imagine you login into an application several times and you **always get the same cookie**. This is because the cookie of the application is **`<username>|<password>`**.\
Then, you generate to new users, both of them with the **same long password** and **almost** the **same** **username**.\
You find out that the **blocks of 8B** where the **info of both users** is the same are **equals**. Then, you imagine that this might be because **ECB is being used**.

Like in the following example. Observe how these** 2 decoded cookies** has several times the block **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
**ghItlhvam** **cookies** **username** **'a'** **ghaH** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'** **'a'
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
# Electronic Code Book (ECB)

## tlhIngan Hol Translation

ghItlhvam `\x23U\xE45K\xCB\x21\xC8` pattern vItlhutlh username `a` vItlhutlh.\
vaj, 8B block first remove 'ej valid cookie username `admin` jImej:

## HTML Translation

<p> We can see the pattern <code>\x23U\xE45K\xCB\x21\xC8</code> created previously with the username that contained only <code>a</code>.</p>
<p>Then, you can remove the first block of 8B and you will et a valid cookie for the username <code>admin</code>:</p>
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Qa'chuq boq

DaH jatlhpu' 'e' chenmoH 'e' `WHERE username='admin';` pagh 'e' `WHERE username='admin    ';` _(yI'el vItlhutlh)_

vaj, 'e' vItlhutlh 'e' `len(<username>) + len(<delimiter) % len(block)`. 'ej 'e' vItlhutlh 'e' `8B` block size, 'e' vItlhutlh vItlhutlh 'e' `username       `, 'ej 'e' delimiter `|` chunk `<username><delimiter>` vItlhutlh 2 blocks 'ej 8Bs.
vaj, 'e' vItlhutlh vItlhutlh 'e' username 'ej vItlhutlh, 'ej vItlhutlh, 'e' `admin   `

vaj, 'e' user cookie composed 3 blocks: 'e' first 2 blocks 'ej username + delimiter 'ej 'e' third block 'ej password (vItlhutlh username): `username       |admin   `

**vaj, 'e' first block replace last time 'ej 'e' impersonating user `admin`: `admin          |username`**

## References

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
