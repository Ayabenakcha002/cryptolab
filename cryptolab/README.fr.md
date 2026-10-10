# cryptolab

[English](README.md) · [Français](README.fr.md)

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances%20d'ex%C3%A9cution-aucune-brightgreen)
![Objectif](https://img.shields.io/badge/objectif-p%C3%A9dagogique-orange)

**cryptolab** est une implémentation « from scratch » des briques cryptographiques qui protègent la majeure partie d'internet, écrite en Python pur lisible, sans aucune dépendance d'exécution :

| Primitive | Standard | Ce qui est implémenté |
|---|---|---|
| **SHA-256** | FIPS 180-4 | hachage en flux ; constantes *dérivées* des racines de nombres premiers, pas copiées |
| **HMAC-SHA256** | RFC 2104 | authentification de messages par clé |
| **AES-128/192/256** | FIPS 197 | chiffrement par blocs ; S-box *calculée* à partir de l'arithmétique de GF(2⁸) |
| **CBC, CTR, GCM** | SP 800-38A/D | modes opératoires ; GCM offre le chiffrement authentifié |
| **RSA** | RFC 8017 | génération de clés (Miller-Rabin), chiffrement OAEP, signatures PKCS#1 v1.5, CRT + masquage + contrôle de fautes |

L'objectif est de **comprendre** la cryptographie en la construisant, puis de prouver que le résultat est correct en le comparant à des implémentations indépendantes.

> ⚠️ **Avertissement de sécurité.** Cette bibliothèque est **pédagogique**. Elle est lente, elle n'est pas à temps constant (les grands entiers Python et l'AES à tables fuient des informations de temps) et elle n'a pas été auditée. **Ne l'utilisez jamais pour protéger de vrais secrets.** Dans un vrai projet, utilisez une bibliothèque éprouvée comme [`cryptography`](https://cryptography.io) ou libsodium.

## Pourquoi on peut lui faire confiance

Écrire de la crypto est facile ; écrire de la crypto *correcte* ne l'est pas. Chaque primitive est vérifiée de trois manières :

1. **Vecteurs de test officiels :** FIPS 197 (annexes B et C), exemples NIST de SHA (dont le message d'un million de `a`), NIST SP 800-38A (CBC, CTR), cas de test GCM de McGrew et Viega, RFC 4231 (HMAC).
2. **Tests différentiels :** entrées aléatoires, toutes les tailles de clé, comparaison octet par octet avec `hashlib`, `hmac` et OpenSSL (via le paquet `cryptography`) : bloc AES, CBC, CTR, GCM, SHA-256 à chaque frontière de bourrage, HMAC pour chaque cas de longueur de clé.
3. **Interopérabilité :** les clés générées ici sont acceptées par OpenSSL ; nous déchiffrons les messages RSA-OAEP d'OpenSSL et vérifions ses signatures, et inversement. L'outil en ligne de commande `openssl` a aussi servi à contrôler un chiffré et une signature produits par ce code.

S'y ajoutent des tests de comportement pour les propriétés de sécurité : détection de modification en GCM, échecs OAEP indiscernables, rejet des signatures mal formées, détection de fautes, tailles de clé faibles refusées. **321 tests**, exécutés sur Python 3.9 à 3.13 par GitHub Actions.

## Installation

```bash
git clone https://github.com/<Ayabenakcha002>/cryptolab.git
cd cryptolab
python -m pip install -e ".[dev]"     # "dev" ajoute pytest et la bibliothèque de référence utilisée par les tests
```

Python 3.9+. La bibliothèque elle-même n'a besoin que de la bibliothèque standard.

## Utilisation comme bibliothèque

```python
from cryptolab import AES, gcm_encrypt, gcm_decrypt, InvalidTag, sha256, hmac_sha256
import os

# Hachage et MAC
print(sha256(b"abc").hex())
tag = hmac_sha256(b"cle secrete", b"message")

# Chiffrement authentifié : AES-256-GCM
key, nonce = os.urandom(32), os.urandom(12)      # un nonce ne doit JAMAIS se répéter avec une même clé
ciphertext, tag = gcm_encrypt(AES(key), nonce, b"attaque a l'aube", aad=b"en-tete")
assert gcm_decrypt(AES(key), nonce, ciphertext, tag, aad=b"en-tete") == b"attaque a l'aube"
try:
    gcm_decrypt(AES(key), nonce, ciphertext[:-1] + b"X", tag, aad=b"en-tete")
except InvalidTag:
    print("modification détectée")
```

```python
from cryptolab import generate_keypair, oaep_encrypt, oaep_decrypt, sign, verify

key = generate_keypair(2048)                      # environ une seconde
secret = oaep_encrypt(key.public, b"bonjour")     # randomisé : différent à chaque fois
assert oaep_decrypt(key, secret) == b"bonjour"

signature = sign(key, b"contrat v1")
assert verify(key.public, b"contrat v1", signature)
assert not verify(key.public, b"contrat v2", signature)
```

## Ligne de commande

```bash
cryptolab hash fichier.pdf                               # comme sha256sum
cryptolab encrypt notes.txt -o notes.enc                 # par mot de passe, AES-256-GCM
cryptolab decrypt notes.enc -o notes.txt

cryptolab rsa-keygen -b 2048 -o alice                    # écrit alice (privée, mode 600) et alice.pub
cryptolab rsa-encrypt -k alice.pub court.txt -o court.rsa
cryptolab rsa-decrypt -k alice court.rsa -o court.txt
cryptolab rsa-sign -k alice contrat.pdf -o contrat.sig
cryptolab rsa-verify -k alice.pub contrat.pdf contrat.sig     # code de sortie 0 = valide
```

Le format de fichier de `encrypt` est `magic | sel | nonce | chiffré | tag`, et l'en-tête est authentifié comme donnée associée GCM. Le mot de passe est transformé en clé par scrypt de la bibliothèque standard : la dérivation de clé n'est pas l'objet de ce projet, et un hachage de mot de passe en Python pur prendrait des minutes. Le mot de passe est saisi dans une invite masquée (jamais en argument de la ligne de commande, où il apparaîtrait dans l'historique du shell et la liste des processus).

## Choix de conception à connaître

- **Constantes dérivées.** Les 72 constantes de SHA-256 viennent des racines carrées/cubiques entières de nombres premiers ; la S-box d'AES de l'inverse dans GF(2⁸) suivi d'une application affine. Moins de nombres magiques, moins de fautes de frappe, et on voit *pourquoi* elles valent ce qu'elles valent.
- **Chiffrement authentifié d'abord.** GCM est le mode recommandé ; le tag est vérifié **avant** tout déchiffrement et comparé en temps constant. CBC et CTR sont fournis pour l'étude et accompagnés d'un avertissement.
- **RSA fait correctement.** OAEP plutôt que RSA « textbook » ; tous les échecs OAEP lèvent une erreur identique (contre l'attaque de Manger) ; la vérification de signature ré-encode et compare au lieu d'analyser le bourrage (contre les falsifications de type Bleichenbacher) ; les opérations privées utilisent le masquage (blinding) et un contrôle de fautes CRT ; les clés de moins de 1024 bits et les nombres premiers trop proches sont refusés.
- **Périmètre assumé.** Volontairement non implémentés : GCM avec des IV autres que 96 bits, RSA-PSS, courbes elliptiques, durcissement contre les canaux auxiliaires. Voir [`docs/THEORY.fr.md`](docs/THEORY.fr.md) pour les mathématiques de chaque primitive.

## Performances

Mesures sur une machine virtuelle dans le cloud (seuls les ordres de grandeur comptent). Le Python pur est environ **1000 fois plus lent** qu'OpenSSL : c'est un outil d'apprentissage.

| Opération | cryptolab | Référence |
|---|---|---|
| SHA-256 | environ 0,4 Mo/s | `hashlib` : des centaines de Mo/s |
| AES-256-GCM (chiffrer 1 Mo) | environ 4 s | OpenSSL avec AES-NI : quelques millisecondes |
| Génération d'une clé RSA-2048 | environ 1 s | |

## Structure du projet

```text
src/cryptolab/
├── sha256.py      SHA-256 avec constantes dérivées
├── mac.py         HMAC-SHA256
├── aes.py         arithmétique GF(2^8), S-box, cadencement de clé, chiffrement par blocs
├── modes.py       CBC, CTR, GCM (GHASH dans GF(2^128))
├── numtheory.py   Euclide étendu, inverse modulaire, Miller-Rabin, génération de premiers
├── rsa.py         clés, OAEP, signatures PKCS#1 v1.5
├── utils.py       PKCS#7, XOR, comparaison en temps constant
└── cli.py         la commande `cryptolab`
tests/             321 tests : vecteurs officiels, différentiels, interopérabilité, comportement
docs/THEORY.fr.md  les mathématiques derrière chaque primitive
```

## Tests

```bash
python -m pytest
```

## Pour aller plus loin

NIST FIPS 197 (AES) · FIPS 180-4 (SHS) · SP 800-38A et 38D (modes, GCM) · RFC 2104 (HMAC) · RFC 8017 (PKCS#1) · *Cryptography Engineering* (Ferguson, Schneier, Kohno) · *Serious Cryptography* (Aumasson).

## Licence

MIT. Voir [LICENSE](LICENSE).
