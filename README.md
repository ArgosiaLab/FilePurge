# FilePurge

Détecter les fichiers présents en plusieurs exemplaires, garder la version la plus récente et envoyer les autres copies à la Corbeille.

FilePurge compare le contenu des fichiers, octet par octet, grâce à une empreinte SHA-256. Le nom n'a aucune importance : `rapport.pdf` et `rapport (2).pdf` sont des doublons s'ils sont identiques, alors que 2 fichiers `photo.jpg` au contenu différent ne le sont pas.

## Fonctionnalités

- Recherche des copies identiques dans un ou plusieurs dossiers ou disques
- Conservation automatique de la copie la plus récente de chaque groupe
- Envoi des autres copies à la Corbeille, jamais de suppression définitive
- Plan complet affiché avant toute action, confirmation obligatoire
- Filtrage par type de fichier : images, PDF, vidéos, archives, documents, etc.
- Protection automatique des fichiers système, des logiciels, des jeux et des projets de code
- Journal de chaque session
- Fonctionnement sous Windows et sous Linux

## Exemple

```text
======================================================================
Plan de nettoyage
======================================================================
  Groupes de copies identiques    : 2
  Fichiers envoyes a la Corbeille : 3
  Espace recupere                 : 14.2 Mo

  Groupe 1 - 3 copies de 7.0 Mo
    GARDE      2026-05-12 18:40  /home/utilisateur/Images/vacances.jpg
    CORBEILLE  2026-03-02 09:15  /home/utilisateur/Bureau/vacances.jpg
    CORBEILLE  2026-01-20 14:02  /home/utilisateur/Telechargements/IMG_0042.jpg

  Groupe 2 - 2 copies de 154.0 Ko
    GARDE      2026-04-08 11:30  /home/utilisateur/Documents/cours.pdf
    CORBEILLE  2026-04-01 08:55  /home/utilisateur/Documents/cours (1).pdf
----------------------------------------------------------------------
  Saisir oui pour envoyer ces copies a la Corbeille,
  autre chose pour annuler.
```

## Prérequis

- Python 3.8 ou version supérieure
- Le module `send2trash`, listé dans `requirements.txt`

## Installation

Récupérer le dépôt :

```bash
git clone https://github.com/ArgosiaLab/FilePurge.git
```

```bash
cd FilePurge
```

### Sous Linux

Les distributions récentes refusent l'installation de modules dans le Python du système. Un environnement virtuel règle ce problème.

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

Variante sans environnement virtuel, sur Debian et Ubuntu :

```bash
sudo apt install python3-send2trash
```

### Sous Windows

```powershell
python -m venv .venv
```

```powershell
.venv\Scripts\activate
```

```powershell
pip install -r requirements.txt
```

## Utilisation

Sous Linux :

```bash
python3 FilePurge.py
```

Sous Windows :

```powershell
python FilePurge.py
```

Le programme se déroule en 3 étapes, puis présente le plan de nettoyage.

1. **Emplacements** : choisir les dossiers à analyser. Les dossiers personnels et les disques détectés sont proposés sous forme de liste numérotée. Il est possible de saisir des numéros (`1 2 4`) ou un chemin complet. Une ligne vide valide la sélection.
2. **Types de fichiers** : choisir les catégories à comparer (`1 6` pour les images et les PDF, `0` pour tout).
3. **Analyse** : FilePurge parcourt les emplacements et compare les fichiers.

Le plan liste chaque groupe de copies identiques, avec la date de chaque copie. Rien n'est déplacé tant que la réponse n'est pas exactement `oui`.

Lancer le programme en utilisateur normal. En administrateur ou en root, un avertissement s'affiche et une confirmation est demandée.

## Ce que FilePurge ne touche jamais

FilePurge reconnaît les éléments sensibles d'après leur emplacement et leur contenu, sans liste de logiciels à tenir à jour.

- **Dossiers système** de Windows et de Linux, jamais parcourus et refusés comme point de départ
- **Dossiers et fichiers cachés**, où la plupart des logiciels rangent leurs réglages, caches et extensions
- **Dossiers de logiciels et de jeux**, reconnus à la présence de bibliothèques ou de plusieurs programmes
- **Dossiers de données de logiciels**, reconnus à une majorité de fichiers de réglages
- **Projets de code**, reconnus à un dépôt Git ou à un fichier de projet
- **Dossiers de dépendances** et environnements de développement
- **Programmes, bibliothèques, raccourcis, fichiers de réglages et sauvegardes**, jamais proposés à la suppression
- **Liens symboliques, jonctions et liens physiques**, pour ne jamais confondre un fichier avec lui-même
- **Fichiers synchronisés à la demande** sous Windows, pour éviter un téléchargement massif
- **Fichiers vides**, souvent utilisés comme marqueurs par les logiciels

Chaque fichier est aussi revérifié juste avant son envoi à la Corbeille : une copie modifiée, déplacée ou supprimée après l'analyse n'est jamais touchée.

Le fonctionnement détaillé est décrit dans [docs/FONCTIONNEMENT.md](docs/FONCTIONNEMENT.md).

## Fichiers générés

| Fichier | Contenu |
|---------|---------|
| `filepurge_journal.txt` | Compte rendu de chaque session : fichiers déplacés, dossiers ignorés, erreurs |
| `filepurge_plan.txt` | Plan complet, créé quand il compte plus de 30 groupes |

Ces fichiers sont écrits à côté du script, ou dans le dossier personnel si le dossier du script est en lecture seule.

## Récupérer un fichier

Chaque copie déplacée se trouve dans la Corbeille du système. La restaurer depuis la Corbeille la remet à son emplacement d'origine. Le journal indique le chemin exact de chaque copie déplacée.

## Tests

Les tests créent une arborescence piégée dans un dossier temporaire et vérifient chaque protection. Aucun fichier personnel n'est touché, et la Corbeille réelle n'est pas utilisée.

```bash
python3 -m unittest discover -s tests -v
```

## Structure du projet

```text
FilePurge.py          programme complet
requirements.txt      dépendances
docs/                 documentation détaillée
tests/                tests automatisés
```

## Contribuer

Ouvrir une issue pour signaler un problème ou proposer une amélioration, puis proposer une pull request. Toute modification doit garder les tests au vert.

## Licence

Projet distribué sous licence MIT. Le texte complet se trouve dans le fichier [LICENSE](LICENSE).
