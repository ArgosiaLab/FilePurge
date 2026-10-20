# Fonctionnement de FilePurge

Ce document explique comment FilePurge décide qu'un fichier est un doublon, ce qu'il protège, et comment le code est organisé.

## Principe général

FilePurge cherche des fichiers dont le contenu est strictement identique. Dans chaque groupe de copies identiques, il garde la copie dont la date de modification est la plus récente, et propose d'envoyer les autres à la Corbeille.

Un groupe de 4 copies identiques donne donc 1 fichier conservé et 3 fichiers déplacés. Après le nettoyage, il ne reste qu'un seul exemplaire de chaque contenu dans les emplacements analysés.

## Détection des doublons

Comparer chaque fichier avec tous les autres serait beaucoup trop lent sur un disque entier. FilePurge procède par éliminations successives, de la plus rapide à la plus coûteuse.

| Étape | Critère | Rôle |
|-------|---------|------|
| 1 | Taille | 2 fichiers de tailles différentes ne peuvent pas être identiques. Un fichier dont la taille est unique est écarté sans être lu. |
| 2 | Identité physique | Un même fichier atteint par 2 chemins (lien physique, emplacements imbriqués) n'est compté qu'une fois. |
| 3 | Empreinte du début | SHA-256 des 64 premiers Ko. Écarte vite les fichiers de même taille mais différents. |
| 4 | Empreinte complète | SHA-256 du fichier entier, seulement pour les fichiers encore candidats. |

Une empreinte SHA-256 est une suite de 64 caractères calculée à partir du contenu. Changer un seul octet du fichier change complètement l'empreinte. Fabriquer 2 fichiers différents avec la même empreinte SHA-256 est aujourd'hui hors de portée.

L'étape 2 est essentielle : sans elle, un fichier vu 2 fois par 2 chemins différents passerait pour un doublon de lui-même, et la seule copie existante pourrait être envoyée à la Corbeille.

## Choix de la copie conservée

Les copies d'un groupe sont triées par date de modification, de la plus récente à la plus ancienne. En cas d'égalité parfaite, le tri se fait sur le chemin, pour que le résultat soit toujours le même d'une exécution à l'autre.

Les groupes sont ensuite présentés du plus grand gain de place au plus petit.

## Protections

### Zones jamais parcourues

- Arborescences système de Linux : `/usr`, `/etc`, `/var`, `/boot`, `/proc`, `/sys`, `/tmp`, etc. Les disques montés sous `/run/media` restent accessibles.
- Dossiers système de Windows : `Windows`, `Program Files`, `ProgramData`, `AppData`, la Corbeille, etc.
- Emplacements standard des sauvegardes de jeux sous Windows.
- Dossiers de dépendances et d'environnements de développement.

Ces zones sont aussi refusées si elles sont saisies comme point de départ.

### Dossiers reconnus d'après leur contenu

Plutôt que de tenir une liste de logiciels, FilePurge examine ce que contient chaque dossier.

| Signal | Classement |
|--------|------------|
| Une bibliothèque (`.dll`, `.so`, `.dylib`, `.sys`) ou au moins 2 programmes | Logiciel ou jeu |
| Un sous-dossier comme `bin`, `lib` ou `content` contenant des binaires | Logiciel ou jeu |
| Des fichiers de réglages, avec une majorité de fichiers techniques | Données de logiciel |
| Un dépôt Git ou un fichier de projet (`package.json`, `Makefile`, etc.) | Projet de code |

Un dossier ainsi reconnu est ignoré avec tout son contenu. Le journal liste chaque dossier ignoré et la raison.

2 garde-fous évitent les excès :

- un programme isolé ne déclenche rien, ce qui laisse le dossier Téléchargements analysable même s'il contient un installeur ;
- un fichier de réglages isolé au milieu de documents personnels ne bloque pas le dossier.

Les emplacements choisis au départ sont toujours ouverts : la détection s'applique seulement à leurs sous-dossiers.

### Éléments ignorés un par un

- Dossiers et fichiers cachés : nom commençant par un point, ou attribut caché ou système sous Windows.
- Liens symboliques et jonctions : jamais suivis.
- Fichiers spéciaux de Linux (tubes, sockets, périphériques) : leur lecture pourrait bloquer le programme.
- Fichiers vides.
- Fichiers synchronisés à la demande sous Windows.
- Programmes, bibliothèques, raccourcis, scripts système, fichiers de réglages, bases de données et sauvegardes, d'après leur extension.

### Vérification avant suppression

Entre l'analyse et la confirmation, du temps passe. Juste avant chaque envoi à la Corbeille, FilePurge vérifie que :

- la copie conservée existe toujours, avec la même taille et la même date ;
- la copie à déplacer existe toujours, avec la même taille et la même date.

Si l'une de ces conditions n'est pas remplie, la copie est laissée en place et l'événement est noté dans le journal.

### Affichage et journal

Un nom de fichier peut contenir des caractères invisibles : codes qui modifient l'affichage du terminal, retours à la ligne, inversion du sens d'écriture capable de déguiser une extension. Ces caractères sont remplacés par `?` avant tout affichage et toute écriture dans le journal.

Le journal est écrit même si le programme est interrompu en cours de suppression, pour que chaque déplacement laisse une trace.

## Organisation du code

Le programme tient dans un seul fichier, découpé en sections.

| Section | Contenu |
|---------|---------|
| Paramètres | Tailles de lecture, nom des fichiers générés |
| Protections | Listes des zones, extensions et signaux protégés |
| Catégories | Types de fichiers proposés à l'étape 2 |
| Utilitaires | Fonctions de contrôle : zone protégée, fichier caché, extension, détection de logiciel |
| Empreintes | `calculer_empreinte` : SHA-256 par blocs de 1 Mo |
| Parcours | `scanner_emplacement` : parcours d'un emplacement et collecte des fichiers éligibles |
| Déduplication | `trouver_doublons` et `determiner_plan_suppression` |
| Affichage | Présentation du plan |
| Suppression | `executer_suppression` : vérification puis envoi à la Corbeille |
| Journal | Écriture du compte rendu de session |
| Détection des emplacements | Dossiers personnels et disques proposés à l'étape 1 |
| Interface | Saisies et menus |
| Programme principal | `main` : enchaînement des étapes |

### Fonctions principales

**`scanner_emplacement(racine, filtre, erreurs, dossiers_ignores)`**
Parcourt un emplacement sans récursion, à l'aide d'une pile, et retourne la liste des fichiers éligibles sous la forme `(chemin, taille, date_de_modification)`.

**`trouver_doublons(liste_fichiers, erreurs)`**
Applique les 4 étapes de détection et retourne les groupes de fichiers identiques.

**`determiner_plan_suppression(doublons)`**
Choisit la copie conservée de chaque groupe et retourne le plan, trié par gain de place.

**`executer_suppression(plan, journal, erreurs)`**
Revérifie chaque fichier puis l'envoie à la Corbeille. Retourne le nombre de fichiers déplacés, ignorés et en échec.

**`dossier_logiciel(dossier, entrees)`**
Retourne la raison pour laquelle un dossier doit être ignoré (`logiciel`, `donnees de logiciel`, `projet de code`), ou `None`.

## Compatibilité

- **Linux** : chemins classiques, dossiers personnels lus depuis `~/.config/user-dirs.dirs` quand ce fichier existe, disques détectés sous `/media`, `/run/media` et `/mnt`.
- **Windows** : lettres de lecteurs détectées automatiquement, chemins longs de plus de 260 caractères pris en charge, attributs caché, système et nuage respectés.

## Limites connues

- Les fichiers ignorés par sécurité ne sont jamais comparés. Un doublon rangé dans un dossier de logiciel reste donc en place.
- Un fichier ouvert et verrouillé par un autre programme peut refuser d'aller à la Corbeille. L'échec est signalé dans le journal.
- Sur un disque sans Corbeille (certains supports réseau ou amovibles), l'envoi à la Corbeille peut échouer. Le fichier reste alors en place.
