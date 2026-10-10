# Les mathématiques derrière cryptolab

[English](THEORY.md) · [Français](THEORY.fr.md)

Ce document explique *pourquoi* chaque primitive fonctionne et indique où l'idée se trouve dans le code. Notations : ⊕ est le XOR, ‖ la concaténation, `a mod n` le reste de la division, ≡ la congruence.

---

## 1. SHA-256 (`sha256.py`)

**Objectif.** Associer à un message de longueur quelconque 256 bits, de sorte que trouver deux messages de même empreinte (collision), ou un message pour une empreinte donnée (préimage), soit infaisable.

**Construction de Merkle-Damgård.**

1. *Bourrage :* ajouter un bit `1`, puis des bits `0` jusqu'à une longueur congrue à 448 modulo 512, puis la longueur d'origine sur 64 bits. Cette longueur fait que `abc` et `abc\x00` n'ont pas la même empreinte.
2. Découper en blocs de 512 bits. Conserver une valeur de chaînage de 256 bits (huit mots de 32 bits `a…h`), initialisée à H0.
3. Pour chaque bloc, étendre ses 16 mots en un **calendrier de messages** de 64 mots, en mélangeant les mots précédents par des rotations et des décalages (σ0, σ1).
4. Exécuter 64 **tours**. Chacun calcule deux valeurs temporaires à partir de `e`, `f`, `g`, `h`, d'une constante de tour et d'un mot du calendrier, et à partir de `a`, `b`, `c` :

   - `Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g)` : pour chaque bit, « si `e` alors `f` sinon `g` » ;
   - `Maj(a,b,c)` : le vote majoritaire de trois bits ;
   - `Σ0`, `Σ1` : XOR de trois rotations, qui répartit chaque bit d'entrée sur tout le mot.

   Puis les mots descendent d'une position et deux d'entre eux sont recalculés.
5. Ajouter le résultat à la valeur de chaînage (modulo 2³²). Cette addition finale rend la fonction de compression à sens unique.

**Pourquoi les constantes ne sont pas arbitraires.** K[i] est formé des 32 premiers bits de la partie fractionnaire de ∛pᵢ, et H0 de celle de √pᵢ, pour les premiers nombres premiers. Ce sont des « nombres sans manche » (*nothing-up-my-sleeve numbers*) : chacun peut les recalculer, donc les concepteurs n'ont pas pu y cacher une faiblesse. `sha256.py` les recalcule en arithmétique entière exacte (`isqrt`, et une itération de Newton pour la racine cubique).

**Extension de longueur.** L'empreinte *est* la dernière valeur de chaînage : un attaquant qui connaît `H(m)` et `len(m)` peut poursuivre le hachage et calculer `H(m ‖ bourrage ‖ x)` sans connaître `m`. C'est pourquoi `H(clé ‖ message)` est un MAC cassé, et pourquoi HMAC existe.

## 2. HMAC (`mac.py`)

`HMAC(K, m) = H( (K′ ⊕ opad) ‖ H( (K′ ⊕ ipad) ‖ m ) )`

`K′` est la clé complétée par des zéros à la taille de bloc de 64 octets (hachée d'abord si elle est plus longue) ; `ipad = 0x36…36`, `opad = 0x5c…5c`. Le hachage interne est enveloppé par un hachage externe, ce qui masque l'état interne et bloque l'extension de longueur. Des preuves de sécurité montrent que HMAC est une PRF sûre si la fonction de compression l'est.

## 3. AES (`aes.py`)

AES travaille sur une matrice 4×4 d'octets (l'*état*) pendant 10, 12 ou 14 tours (clés de 128, 192 ou 256 bits).

### 3.1 Le corps GF(2⁸)

Un octet est un polynôme de degré ≤ 7 à coefficients dans {0,1} : `0x57 = x⁶+x⁴+x²+x+1`.

- **L'addition** est le XOR.
- **La multiplication** est la multiplication de polynômes, réduite modulo le polynôme irréductible `x⁸+x⁴+x³+x+1` (`0x11B`). Multiplier par `x` est un décalage à gauche, combiné par XOR avec `0x1B` si un bit est sorti (`_xtime`).
- Le modulo étant irréductible, tout octet non nul possède un inverse.
- Les éléments non nuls forment un groupe cyclique d'ordre 255 dont `0x03` est un générateur. Donc tout `a ≠ 0` s'écrit `3ⁱ`, et `a · b = 3^(i+j mod 255)` : c'est ainsi que le code multiplie et inverse, avec des tables log/exp. FIPS 197 donne `0x57 · 0x83 = 0xC1`, que les tests vérifient.

### 3.2 SubBytes : la S-box

`S(a) = affine(a⁻¹)`, avec `0⁻¹ := 0`. L'inversion est la partie *non linéaire*. Elle a été choisie pour sa très bonne résistance aux cryptanalyses linéaire et différentielle. L'application affine `b ⊕ rotl(b,1) ⊕ rotl(b,2) ⊕ rotl(b,3) ⊕ rotl(b,4) ⊕ 0x63` supprime les points fixes et la structure algébrique de l'inversion pure. La table est *calculée* à l'import et vérifiée sur des valeurs connues (`S(0x00)=0x63`, `S(0x53)=0xED`).

### 3.3 ShiftRows et MixColumns

- **ShiftRows** fait tourner la ligne *r* de l'état de *r* octets vers la gauche : les octets d'une colonne se répartissent sur quatre colonnes.
- **MixColumns** multiplie chaque colonne, vue comme un vecteur sur GF(2⁸), par la matrice

  ```text
  | 02 03 01 01 |
  | 01 02 03 01 |
  | 01 01 02 03 |
  | 03 01 01 02 |
  ```

  Chaque octet de sortie dépend de quatre octets d'entrée. Ensemble, ShiftRows et MixColumns assurent la **diffusion** : après deux tours, chaque octet de l'état dépend de tous les octets d'entrée. La matrice de déchiffrement (`0E 0B 0D 09 …`) est l'inverse de celle-ci sur GF(2⁸).

### 3.4 Cadencement de clé

La clé est découpée en mots `w[0…Nk-1]` ; chaque mot suivant vaut `w[i] = w[i-Nk] ⊕ f(w[i-1])`, où `f` est l'identité, ou RotWord + SubWord + une constante de tour (tous les `Nk` mots), ou SubWord seul (AES-256, un mot sur quatre). Les constantes de tour sont les puissances successives de `x` dans GF(2⁸) : `01, 02, 04, 08, 10, 20, 40, 80, 1B, 36`.

### 3.5 Structure d'un tour

`AddRoundKey` → (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`) × (Nr−1) → `SubBytes`, `ShiftRows`, `AddRoundKey`. Le dernier tour n'a pas de MixColumns. Le déchiffrement applique les opérations inverses dans l'ordre inverse.

**Canaux auxiliaires.** Indexer une table de 256 entrées avec un octet secret prend un temps qui dépend de l'état du cache du processeur, ce qui a été exploité à distance (Bernstein, 2005). L'AES de production utilise des instructions matérielles (AES-NI) ou du code « bit-slicé ». Cette implémentation ne le fait pas.

## 4. Modes opératoires (`modes.py`)

Un chiffrement par blocs est une permutation de blocs de 16 octets. Pour chiffrer un message, il faut un *mode*.

- **ECB** (chiffrer chaque bloc indépendamment) n'est pas fourni : deux blocs clairs identiques donnent deux blocs chiffrés identiques, donc les motifs subsistent (le célèbre « pingouin ECB »).
- **CBC :** `Cᵢ = E(Pᵢ ⊕ Cᵢ₋₁)`, `C₀ = IV`. L'IV doit être imprévisible. Nécessite un bourrage (PKCS#7). Non authentifié, et des erreurs de bourrage signalées à un attaquant permettent des attaques par *oracle de bourrage* qui déchiffrent tout. D'où le message d'erreur unique dans `pkcs7_unpad`.
- **CTR :** `Cᵢ = Pᵢ ⊕ E(nonce ‖ compteurᵢ)`. Un chiffrement de flux construit à partir d'un chiffrement par blocs : pas de bourrage, parallélisable. Réutiliser une valeur de compteur révèle `P ⊕ P′` des deux messages. Toujours non authentifié : inverser un bit du chiffré inverse le même bit du clair.
- **GCM** = CTR + un MAC polynomial.
  - Soit `H = E(0¹²⁸)`. **GHASH** traite les blocs de 128 bits comme des éléments de GF(2¹²⁸) (modulo `x¹²⁸+x⁷+x²+x+1`, avec l'ordre de bits inversé du standard) et calcule `Y = (… ((A₁·H ⊕ A₂)·H ⊕ …) · H` sur les données associées, le chiffré et un dernier bloc contenant leurs longueurs. C'est l'évaluation d'un polynôme au point secret `H`.
  - Le **tag** vaut `E(J₀) ⊕ GHASH`, avec `J₀ = IV ‖ 0³¹1`. Le chiffrement utilise CTR à partir de `J₀ + 1`.
  - Deux tags valides sur des messages avec le même IV révèlent `H` (l'« attaque interdite »), après quoi n'importe qui peut forger des tags. **Ne jamais répéter un couple (clé, IV).** C'est pourquoi la CLI tire 96 bits aléatoires frais par fichier et dérive de toute façon une nouvelle clé à partir d'un sel frais.
  - Le déchiffrement vérifie d'abord le tag (comparaison en temps constant) et refuse de déchiffrer en cas d'écart.

## 5. RSA (`numtheory.py`, `rsa.py`)

### 5.1 Pourquoi ça fonctionne

Choisir deux grands nombres premiers `p`, `q` ; `n = pq`. Soit `λ = ppcm(p−1, q−1)`. Choisir `e` avec `pgcd(e, λ) = 1` (65537 ici) et calculer `d = e⁻¹ mod λ` avec l'algorithme d'Euclide étendu. La clé publique est `(n, e)`, la clé privée `d`.

Le chiffrement est `c = mᵉ mod n` ; le déchiffrement est `m = cᵈ mod n`. **Pourquoi on retrouve `m` :** `ed = 1 + kλ`, donc `mᵉᵈ = m · (m^λ)ᵏ`. D'après le petit théorème de Fermat, `m^(p−1) ≡ 1 (mod p)` si `p ∤ m`, et `λ` est un multiple de `p−1`, donc `mᵉᵈ ≡ m (mod p)`. (Si `p | m`, les deux côtés valent 0.) Il en va de même modulo `q`. Comme `p` et `q` sont premiers entre eux, le **théorème des restes chinois** donne `mᵉᵈ ≡ m (mod n)`.

**La sécurité** repose sur la difficulté de factoriser `n` (calculer `d` à partir de `(n, e)` est aussi difficile que factoriser). Le plus grand module RSA factorisé fait 829 bits (RSA-250, 2020), d'où le minimum actuel de 2048 bits ; un grand ordinateur quantique casserait RSA avec l'algorithme de Shor.

### 5.2 Nombres premiers : Miller-Rabin (`numtheory.py`)

Le test de Fermat (`aⁿ⁻¹ ≡ 1`) est trompé par les nombres de Carmichael comme 561. Miller-Rabin écrit `n − 1 = 2ˢd` et examine la suite `aᵈ, a²ᵈ, …, a^(2^(s−1) d)` : pour un nombre premier, elle commence à 1 ou atteint −1 (car les seules racines carrées de 1 modulo un premier sont ±1). Un nombre composé passe pour au plus 1/4 des bases ; 40 tours aléatoires donnent donc une erreur inférieure à 4⁻⁴⁰. Les candidats sont d'abord criblés avec les nombres premiers inférieurs à 1000. Les deux bits de poids fort sont forcés à 1 pour que `pq` ait exactement la taille demandée ; `p` et `q` sont rejetés s'ils sont trop proches (factorisation de Fermat).

### 5.3 Vitesse : le CRT (`_crt_private`)

Calculer `cᵈ mod n` directement coûte une exponentiation avec un module de 2048 bits. On la calcule plutôt modulo `p` et modulo `q` (nombres de moitié moins grands, avec des exposants réduits modulo `p−1` et `q−1`), puis on recombine : `m = m₂ + q · (q⁻¹(m₁ − m₂) mod p)`. Le coût d'une multiplication croît à peu près comme le carré de la taille : on gagne un facteur 4 environ.

### 5.4 Le RSA « textbook » est cassé

`c = mᵉ mod n` seul est :

- **déterministe :** le même message donne toujours le même chiffré, ce qui permet de confirmer des hypothèses ;
- **malléable :** `(m₁m₂)ᵉ = m₁ᵉ·m₂ᵉ`, donc un attaquant peut transformer un chiffré en chiffré de `2m` sans la clé ;
- **faible pour un petit `m` :** si `mᵉ < n`, il n'y a pas de réduction modulaire et `m` est simplement une racine `e`-ième entière.

### 5.5 OAEP (`oaep_encrypt`)

Un réseau de type Feistel à deux tours avec une graine aléatoire, utilisant la fonction de hachage comme générateur de masque (MGF1) :

```text
DB = H(label) ‖ 00…00 ‖ 01 ‖ M
DB_masqué    = DB   ⊕ MGF1(graine)
graine_masquée = graine ⊕ MGF1(DB_masqué)
EM = 00 ‖ graine_masquée ‖ DB_masqué          puis   c = EMᵉ mod n
```

La graine aléatoire rend le chiffrement probabiliste ; la redondance (`H(label)`, zéros, `01`) permet au déchiffreur de détecter toute modification. Le déchiffreur ne doit pas révéler *quel* contrôle a échoué : Manger (2001) a montré que distinguer « premier octet ≠ 0 » des autres erreurs permet de déchiffrer un message avec environ 1000 requêtes. Tous les échecs lèvent donc la même exception.

### 5.6 Signatures (`sign`, `verify`)

Une signature est une opération à *clé privée* sur un haché : `s = EM^d mod n`, avec `EM = 00 01 FF…FF 00 ‖ DigestInfo ‖ SHA-256(m)`. Pour vérifier, on calcule `sᵉ mod n` et on le compare à l'`EM` que l'on reconstruit soi-même, **sans** analyser le bourrage. Les analyseurs trop permissifs, qui s'arrêtent après le haché (en ignorant les octets restants), ont permis la falsification de Bleichenbacher en 2006 contre les petits `e`. RSA-PSS est le schéma moderne, randomisé et muni d'une preuve de sécurité ; PKCS#1 v1.5 est implémenté ici car il est déterministe, très répandu et facile à recouper avec OpenSSL.

### 5.7 Défenses de l'opération privée (`_private_op`)

- **Masquage (blinding) :** on déchiffre `c · rᵉ` pour un `r` aléatoire, puis on multiplie par `r⁻¹`. L'exponentiation ne voit jamais de donnée choisie par l'attaquant, ce qui déjoue les attaques temporelles (Kocher, 1996).
- **Contrôle de fautes :** une seule inversion de bit pendant le calcul CRT donne un résultat correct modulo `p` mais pas modulo `q` ; la sortie fautive révèle alors `pgcd(s′ᵉ − m, n) = p` (Boneh-DeMillo-Lipton, 1997). Nous rechiffrons le résultat et refusons de le publier s'il ne correspond pas.

## 6. Ce que ce projet ne fait volontairement pas

Arithmétique à temps constant, accélération matérielle, AES-GCM avec des IV de longueur quelconque, RSA-PSS, courbes elliptiques et hachage de mots de passe from scratch. Chacun est un bon projet suivant.

## Références

- NIST FIPS 197, *Advanced Encryption Standard* ; FIPS 180-4, *Secure Hash Standard*.
- NIST SP 800-38A (CBC, CTR) et SP 800-38D (GCM).
- RFC 2104 (HMAC), RFC 4231 (vecteurs de test HMAC-SHA-2), RFC 8017 (PKCS#1 v2.2).
- J. Daemen, V. Rijmen, *The Design of Rijndael*.
- D. Bleichenbacher, « Chosen ciphertext attacks against protocols based on RSA Encryption Standard PKCS #1 » (1998) ; J. Manger, « A chosen ciphertext attack on RSA OAEP » (2001).
