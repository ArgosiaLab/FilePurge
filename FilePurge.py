#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FilePurge - Detection et suppression des fichiers en double.

Fonctionnement
  1. Parcours des emplacements choisis : dossiers personnels, disques,
     ou chemins saisis a la main.
  2. Regroupement des fichiers par taille, puis comparaison par empreinte
     SHA-256 : d'abord sur le debut du fichier, puis sur le fichier entier.
  3. Dans chaque groupe de copies identiques, la version la plus recente
     est conservee. Les autres copies sont envoyees a la Corbeille :
     aucun fichier n'est supprime definitivement.

Protections
  - Dossiers systeme de Windows et de Linux jamais parcourus.
  - Dossiers et fichiers caches ignores (configuration, caches, extensions
    de logiciels).
  - Dossiers de logiciels, de jeux et de projets de code reconnus d'apres
    leur contenu, puis ignores en entier.
  - Executables, bibliotheques, fichiers de configuration et sauvegardes
    jamais proposes a la suppression.
  - Liens symboliques, jonctions, liens physiques et fichiers synchronises
    a la demande ignores.
  - Fichiers vides ignores.
  - Verification de chaque fichier juste avant son envoi a la Corbeille.

Utilisation
  pip install send2trash
  python3 FilePurge.py        (Linux)
  python FilePurge.py         (Windows)

Un plan complet est affiche avant toute action, et rien n'est deplace
sans confirmation explicite. Un journal de chaque session est ecrit a cote
du script, ou dans le dossier personnel si ce dossier est en lecture seule.

Compatibilite : Python 3.8 ou plus recent, Windows et Linux.
"""

import os
import re
import sys
import stat
import string
import hashlib
import datetime
import unicodedata
import collections

try:
    import send2trash
except ImportError:
    print("Erreur : le module 'send2trash' est absent.")
    print("Installation : pip install send2trash")
    sys.exit(1)

# Un nom de fichier exotique ne doit jamais faire planter l'affichage.
for _flux in (sys.stdout, sys.stderr):
    try:
        _flux.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass


# ---------------------------------------------------------------------------
# PARAMETRES
# ---------------------------------------------------------------------------

EST_WINDOWS = sys.platform == "win32"
DOSSIER_PERSO = os.path.expanduser("~")

TAILLE_BLOC = 1024 * 1024                 # lecture par blocs de 1 Mo
TAILLE_EMPREINTE_PARTIELLE = 64 * 1024    # premier tri sur les 64 premiers Ko
MAX_GROUPES_AFFICHES = 30                 # au-dela, plan complet dans un fichier

NOM_JOURNAL = "filepurge_journal.txt"
NOM_PLAN = "filepurge_plan.txt"


# ---------------------------------------------------------------------------
# PROTECTIONS
# ---------------------------------------------------------------------------

# Noms de dossiers jamais parcourus, ou qu'ils se trouvent
# (comparaison exacte, sans tenir compte des majuscules).
NOMS_DOSSIERS_PROTEGES = {
    # Systeme Windows
    "windows", "program files", "program files (x86)", "programdata",
    "appdata", "application data", "windowsapps", "$recycle.bin",
    "system volume information", "recovery", "perflogs", "msocache",
    "config.msi", "$windows.~bt", "$windows.~ws", "$winreagent",
    # Emplacements standard des sauvegardes de jeux sous Windows
    "saved games", "my games",
    # Dependances et environnements de developpement
    "node_modules", "bower_components", "site-packages", "dist-packages",
    "__pycache__", "venv", "vendor", "libraries",
}

# Arborescences systeme de Linux, jamais parcourues.
CHEMINS_SYSTEME_LINUX = (
    "/bin", "/boot", "/dev", "/efi", "/etc", "/lib", "/lib32", "/lib64",
    "/libx32", "/lost+found", "/opt", "/proc", "/root", "/run", "/sbin",
    "/snap", "/srv", "/sys", "/tmp", "/usr", "/var",
)
# Exception : les disques externes sont montes sous /run/media.
EXCEPTIONS_SYSTEME_LINUX = ("/run/media",)

# Dossiers personnels geres par un gestionnaire de paquets.
CHEMINS_PERSO_PROTEGES = (os.path.join(DOSSIER_PERSO, "snap"),)

# Extensions jamais proposees a la suppression.
EXTENSIONS_PROTEGEES = {
    # Programmes, bibliotheques, pilotes, installeurs, scripts systeme
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".com",
    ".msi", ".msix", ".appx", ".bat", ".cmd", ".ps1", ".vbs",
    ".so", ".ko", ".dylib", ".appimage", ".deb", ".rpm",
    # Raccourcis
    ".lnk", ".desktop",
    # Configuration et donnees internes de logiciels
    ".ini", ".cfg", ".conf", ".config", ".cnf", ".toml", ".yaml", ".yml",
    ".plist", ".reg", ".inf", ".dat", ".db", ".sqlite", ".sqlite3",
    ".ldb", ".lock",
    # Sauvegardes de jeux et de logiciels
    ".sav", ".save",
}

# Bibliotheques Linux versionnees (exemple : libexemple.so.6).
MOTIF_BIBLIOTHEQUE_VERSIONNEE = re.compile(r"\.so(\.\d+)+$")

# Signature d'un dossier de logiciel ou de jeu.
EXTENSIONS_BIBLIOTHEQUES = (".dll", ".sys", ".so", ".dylib")
EXTENSIONS_EXECUTABLES = (".exe", ".appimage")

# Fichiers de reglages typiques d'un dossier de donnees de logiciel.
EXTENSIONS_MARQUEURS_CONFIG = {
    ".ini", ".cfg", ".conf", ".cnf", ".plist", ".sav", ".save",
}

# Sous-dossiers ou les logiciels rangent souvent leurs binaires : un dossier
# dont l'un de ces sous-dossiers contient un programme est un logiciel.
SOUS_DOSSIERS_BINAIRES = {
    "bin", "bin32", "bin64", "binaries", "lib", "lib32", "lib64",
    "x64", "x86", "win32", "win64", "content", "engine", "redist",
    "_commonredist",
}

# Presence de l'un de ces noms : dossier de projet de code.
MARQUEURS_PROJET = {
    ".git", ".svn", ".hg", "package.json", "pyproject.toml", "setup.py",
    "requirements.txt", "cargo.toml", "go.mod", "pom.xml", "build.gradle",
    "cmakelists.txt", "makefile", "composer.json", "gemfile",
}

# Attributs de fichiers Windows.
ATTRIBUT_CACHE = 0x2
ATTRIBUT_SYSTEME = 0x4
ATTRIBUT_POINT_ANALYSE = 0x400          # jonctions, liens, fichiers nuage
ATTRIBUT_HORS_LIGNE = 0x1000
ATTRIBUT_RAPPEL_OUVERTURE = 0x40000
ATTRIBUT_RAPPEL_LECTURE = 0x400000
ATTRIBUTS_NUAGE = (ATTRIBUT_HORS_LIGNE | ATTRIBUT_RAPPEL_OUVERTURE
                   | ATTRIBUT_RAPPEL_LECTURE)


# ---------------------------------------------------------------------------
# CATEGORIES DE FICHIERS
# ---------------------------------------------------------------------------

CATEGORIES = {
    1:  ("Images",          {".jpg", ".jpeg", ".png", ".gif", ".bmp",
                             ".tiff", ".webp", ".heic", ".svg"}),
    2:  ("Archives",        {".zip", ".tar", ".gz", ".bz2", ".xz",
                             ".rar", ".7z"}),
    3:  ("Documents texte", {".doc", ".docx", ".odt", ".rtf", ".txt",
                             ".md"}),
    4:  ("Tableurs",        {".xls", ".xlsx", ".ods", ".csv"}),
    5:  ("Presentations",   {".ppt", ".pptx", ".odp"}),
    6:  ("PDF",             {".pdf"}),
    7:  ("Code",            {".py", ".js", ".ts", ".html", ".css", ".php",
                             ".c", ".h", ".cpp", ".cs", ".java", ".sql",
                             ".sh"}),
    8:  ("Videos",          {".mp4", ".avi", ".mkv", ".mov", ".wmv",
                             ".flv", ".mpeg", ".mpg", ".webm"}),
    9:  ("Audio",           {".mp3", ".wav", ".flac", ".aac", ".ogg",
                             ".opus", ".m4a", ".wma"}),
    10: ("Tout le reste",   None),   # extensions absentes des listes
    0:  ("Tout",            None),   # toutes les extensions
}

TOUTES_EXT_CONNUES = set()
for _num, (_, _exts) in CATEGORIES.items():
    if _exts:
        TOUTES_EXT_CONNUES.update(_exts)


# ---------------------------------------------------------------------------
# UTILITAIRES
# ---------------------------------------------------------------------------

def texte_sur(texte):
    """
    Neutralise les caracteres invisibles ou de controle d'un nom de fichier
    avant affichage ou journalisation : sequences de terminal, retours a la
    ligne, inversion du sens d'ecriture, octets non decodables.
    """
    return "".join(
        "?" if unicodedata.category(c)[0] == "C" else c for c in texte
    )


def taille_lisible(octets):
    """Convertit un nombre d'octets en texte lisible."""
    for unite, seuil in (("Go", 1024 ** 3), ("Mo", 1024 ** 2), ("Ko", 1024)):
        if octets >= seuil:
            return "{:.1f} {}".format(octets / seuil, unite)
    return "{} o".format(octets)


def date_lisible(mtime_ns):
    """Convertit une date de modification en texte lisible."""
    try:
        return datetime.datetime.fromtimestamp(
            mtime_ns / 1e9).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "date inconnue   "


def chemin_acces(chemin):
    """
    Sous Windows, retourne le chemin au format etendu pour depasser la
    limite de 260 caracteres. Sans ce format, les fichiers aux chemins
    longs sont illisibles et leurs doublons ne sont jamais traites.
    """
    if not EST_WINDOWS:
        return chemin
    absolu = os.path.abspath(chemin)
    if absolu.startswith("\\\\?\\"):
        return absolu
    if absolu.startswith("\\\\"):                  # partage reseau
        return "\\\\?\\UNC\\" + absolu[2:]
    return "\\\\?\\" + absolu


def attributs(info):
    """Attributs Windows d'un fichier (0 sous Linux)."""
    return getattr(info, "st_file_attributes", 0)


def est_cache(nom, info):
    """Element cache : nom commencant par un point, ou attribut Windows."""
    return (nom.startswith(".")
            or bool(attributs(info) & (ATTRIBUT_CACHE | ATTRIBUT_SYSTEME)))


def est_sous_chemin(chemin, parent):
    """True si chemin est egal a parent ou situe a l'interieur."""
    c = os.path.normcase(os.path.normpath(chemin))
    p = os.path.normcase(os.path.normpath(parent))
    if c == p:
        return True
    return c.startswith(p.rstrip(os.sep) + os.sep)


def chemin_systeme_linux(chemin):
    """True si le chemin appartient a une arborescence systeme de Linux."""
    if EST_WINDOWS:
        return False
    for exception in EXCEPTIONS_SYSTEME_LINUX:
        if est_sous_chemin(chemin, exception):
            return False
    return any(est_sous_chemin(chemin, s) for s in CHEMINS_SYSTEME_LINUX)


def dossier_protege(chemin, nom):
    """True si le dossier ne doit jamais etre parcouru."""
    if nom.lower() in NOMS_DOSSIERS_PROTEGES:
        return True
    if chemin_systeme_linux(chemin):
        return True
    return any(est_sous_chemin(chemin, p) for p in CHEMINS_PERSO_PROTEGES)


def racine_protegee(chemin):
    """True si un emplacement choisi se trouve dans une zone protegee."""
    if chemin_systeme_linux(chemin):
        return True
    if any(est_sous_chemin(chemin, p) for p in CHEMINS_PERSO_PROTEGES):
        return True
    morceaux = os.path.normpath(chemin).split(os.sep)
    return any(m.lower() in NOMS_DOSSIERS_PROTEGES for m in morceaux if m)


def extension_protegee(nom):
    """True si le fichier ne doit jamais etre propose a la suppression."""
    bas = nom.lower()
    if os.path.splitext(bas)[1] in EXTENSIONS_PROTEGEES:
        return True
    return bool(MOTIF_BIBLIOTHEQUE_VERSIONNEE.search(bas))


def extension_acceptee(nom, filtre):
    """True si le fichier correspond aux categories choisies."""
    extensions_cibles, tout_mode, tout_reste_mode = filtre
    if tout_mode:
        return True
    ext = os.path.splitext(nom.lower())[1]
    if ext in extensions_cibles:
        return True
    return tout_reste_mode and ext not in TOUTES_EXT_CONNUES


def contient_binaires(noms):
    """True si une liste de noms contient une bibliotheque ou 2 executables."""
    nb_executables = 0
    for nom in noms:
        bas = nom.lower()
        if (bas.endswith(EXTENSIONS_BIBLIOTHEQUES)
                or MOTIF_BIBLIOTHEQUE_VERSIONNEE.search(bas)):
            return True
        if bas.endswith(EXTENSIONS_EXECUTABLES):
            nb_executables += 1
            if nb_executables >= 2:
                return True
    return False


def dossier_logiciel(dossier, entrees):
    """
    Reconnait un dossier de logiciel, de jeu ou de projet de code d'apres son
    contenu, sans connaitre son nom. Retourne la raison, ou None.
    Un installeur isole (un seul executable) ne declenche rien.
    """
    noms = [e.name for e in entrees]

    if {n.lower() for n in noms} & MARQUEURS_PROJET:
        return "projet de code"

    if contient_binaires(noms):
        return "logiciel"

    # Fichiers de reglages : le dossier n'est classe comme donnees de logiciel
    # que si les fichiers techniques y sont majoritaires. Un fichier de
    # reglages isole au milieu de documents personnels ne bloque rien.
    nb_config = 0
    nb_techniques = 0
    nb_personnels = 0
    for entree in entrees:
        try:
            info = entree.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or est_cache(entree.name, info):
            continue
        ext = os.path.splitext(entree.name.lower())[1]
        if ext in TOUTES_EXT_CONNUES:
            nb_personnels += 1
        else:
            nb_techniques += 1
            if ext in EXTENSIONS_MARQUEURS_CONFIG:
                nb_config += 1
    if nb_config and nb_techniques > nb_personnels:
        return "donnees de logiciel"

    for entree in entrees:
        if entree.name.lower() not in SOUS_DOSSIERS_BINAIRES:
            continue
        try:
            if not entree.is_dir(follow_symlinks=False):
                continue
            with os.scandir(chemin_acces(
                    os.path.join(dossier, entree.name))) as contenu:
                if contient_binaires(e.name for e in contenu):
                    return "logiciel"
        except OSError:
            continue

    return None


# ---------------------------------------------------------------------------
# EMPREINTES
# ---------------------------------------------------------------------------

def calculer_empreinte(chemin, limite=None):
    """
    Empreinte SHA-256 d'un fichier, lu par blocs. Avec limite, seuls les
    premiers octets sont lus. Retourne None si la lecture echoue.
    """
    hacheur = hashlib.sha256()
    lus = 0
    try:
        with open(chemin_acces(chemin), "rb") as f:
            while True:
                a_lire = TAILLE_BLOC
                if limite is not None:
                    a_lire = min(a_lire, limite - lus)
                    if a_lire <= 0:
                        break
                bloc = f.read(a_lire)
                if not bloc:
                    break
                hacheur.update(bloc)
                lus += len(bloc)
    except OSError:
        return None
    return hacheur.hexdigest()


# ---------------------------------------------------------------------------
# PARCOURS
# ---------------------------------------------------------------------------

def scanner_emplacement(racine, filtre, erreurs, dossiers_ignores):
    """
    Parcourt un emplacement et collecte les fichiers eligibles.
    Retourne une liste de tuples (chemin, taille, date_modif_ns).

    La detection de logiciels ne s'applique pas a la racine elle-meme :
    un emplacement choisi explicitement est toujours ouvert.
    """
    fichiers_trouves = []
    pile = [(racine, True)]

    while pile:
        dossier, est_racine = pile.pop()
        try:
            with os.scandir(chemin_acces(dossier)) as contenu:
                entrees = list(contenu)
        except OSError as e:
            erreurs.append("Dossier illisible : {} ({})".format(
                texte_sur(dossier), texte_sur(e.strerror or str(e))))
            continue

        if not est_racine:
            raison = dossier_logiciel(dossier, entrees)
            if raison:
                dossiers_ignores.append((dossier, raison))
                continue

        for entree in entrees:
            chemin = os.path.join(dossier, entree.name)
            try:
                info = entree.stat(follow_symlinks=False)
            except OSError as e:
                erreurs.append("Lecture impossible : {} ({})".format(
                    texte_sur(chemin), texte_sur(e.strerror or str(e))))
                continue

            # Liens symboliques et jonctions : jamais suivis, jamais traites.
            if stat.S_ISLNK(info.st_mode) or (
                    attributs(info) & ATTRIBUT_POINT_ANALYSE):
                continue
            if est_cache(entree.name, info):
                continue

            if stat.S_ISDIR(info.st_mode):
                if not dossier_protege(chemin, entree.name):
                    pile.append((chemin, False))
                continue

            # Uniquement les fichiers ordinaires : un tube ou un peripherique
            # bloquerait la lecture indefiniment.
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_size == 0:
                continue
            if attributs(info) & ATTRIBUTS_NUAGE:
                continue
            if extension_protegee(entree.name):
                continue
            if not extension_acceptee(entree.name, filtre):
                continue

            fichiers_trouves.append((chemin, info.st_size, info.st_mtime_ns))

    return fichiers_trouves


# ---------------------------------------------------------------------------
# DEDUPLICATION
# ---------------------------------------------------------------------------

def afficher_progression(libelle, idx, total):
    """Ligne de progression reecrite sur place."""
    if idx % 200 == 0 or idx == total:
        print("  {} : {}/{}".format(libelle, idx, total), end="\r")
        if idx == total:
            print()


def regrouper(fichiers, cle, libelle, erreurs):
    """
    Regroupe des fichiers selon une fonction cle et ne garde que les groupes
    d'au moins 2 elements. Une cle None ecarte le fichier.
    """
    groupes = collections.defaultdict(list)
    total = len(fichiers)
    for idx, fichier in enumerate(fichiers, 1):
        afficher_progression(libelle, idx, total)
        valeur = cle(fichier)
        if valeur is None:
            erreurs.append("Lecture impossible : {}".format(
                texte_sur(fichier[0])))
            continue
        groupes[valeur].append(fichier)
    return [g for g in groupes.values() if len(g) >= 2]


def trouver_doublons(liste_fichiers, erreurs):
    """
    Retourne la liste des groupes de fichiers strictement identiques.
    Etapes : taille, identite physique, debut du fichier, fichier entier.
    """
    # 1. Taille : deux fichiers de tailles differentes ne sont jamais
    #    identiques.
    par_taille = collections.defaultdict(list)
    for fichier in liste_fichiers:
        par_taille[fichier[1]].append(fichier)
    candidats = [f for g in par_taille.values() if len(g) >= 2 for f in g]

    # 2. Identite physique : un meme fichier atteint par 2 chemins (lien
    #    physique, emplacements imbriques) n'est pas un doublon. Sans ce
    #    controle, la seule copie existante serait supprimee. Les valeurs
    #    sont relues a la source pour servir de reference avant suppression.
    vus = set()
    uniques = []
    for chemin, _, _ in candidats:
        try:
            info = os.stat(chemin_acces(chemin), follow_symlinks=False)
        except OSError:
            erreurs.append("Lecture impossible : {}".format(texte_sur(chemin)))
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        identite = (info.st_dev, info.st_ino)
        if info.st_ino and identite in vus:
            continue
        vus.add(identite)
        uniques.append((chemin, info.st_size, info.st_mtime_ns))

    par_taille = collections.defaultdict(list)
    for fichier in uniques:
        par_taille[fichier[1]].append(fichier)
    candidats = [f for g in par_taille.values() if len(g) >= 2 for f in g]
    print("  {} fichier(s) partagent leur taille avec un autre.".format(
        len(candidats)))
    if not candidats:
        return []

    # 3. Empreinte du debut du fichier : elimine vite les faux candidats.
    groupes = regrouper(
        candidats,
        lambda f: (f[1], calculer_empreinte(f[0], TAILLE_EMPREINTE_PARTIELLE)),
        "Comparaison rapide",
        erreurs,
    )
    groupes = [[f for f in g] for g in groupes]

    # 4. Empreinte complete, inutile si le fichier tient dans le debut lu.
    resultat = []
    a_verifier = []
    for groupe in groupes:
        if groupe[0][1] <= TAILLE_EMPREINTE_PARTIELLE:
            resultat.append(groupe)
        else:
            a_verifier.extend(groupe)

    if a_verifier:
        resultat.extend(regrouper(
            a_verifier,
            lambda f: (f[1], calculer_empreinte(f[0])),
            "Comparaison complete",
            erreurs,
        ))

    return resultat


def determiner_plan_suppression(doublons):
    """
    Pour chaque groupe, conserve le fichier le plus recent et marque les
    autres pour la Corbeille. Groupes tries par espace recupere decroissant.
    """
    plan = []
    for fichiers in doublons:
        tries = sorted(fichiers, key=lambda f: (-f[2], f[0]))
        plan.append({"conserver": tries[0], "supprimer": tries[1:]})
    plan.sort(key=lambda g: -sum(f[1] for f in g["supprimer"]))
    return plan


# ---------------------------------------------------------------------------
# AFFICHAGE
# ---------------------------------------------------------------------------

def titre(texte):
    """Titre de section."""
    print()
    print("=" * 70)
    print(texte)
    print("=" * 70)


def lignes_plan(plan, limite=None):
    """Lignes de texte decrivant le plan, groupe par groupe."""
    lignes = []
    for i, groupe in enumerate(plan[:limite], 1):
        chemin, taille, mtime = groupe["conserver"]
        lignes.append("")
        lignes.append("Groupe {} - {} copies de {}".format(
            i, len(groupe["supprimer"]) + 1, taille_lisible(taille)))
        lignes.append("  GARDE      {}  {}".format(
            date_lisible(mtime), texte_sur(chemin)))
        for c, _, m in groupe["supprimer"]:
            lignes.append("  CORBEILLE  {}  {}".format(
                date_lisible(m), texte_sur(c)))
    return lignes


def afficher_plan(plan):
    """Affiche le plan de nettoyage avant confirmation."""
    nb_fichiers = sum(len(g["supprimer"]) for g in plan)
    espace = sum(f[1] for g in plan for f in g["supprimer"])

    print("  Groupes de copies identiques    : {}".format(len(plan)))
    print("  Fichiers envoyes a la Corbeille : {}".format(nb_fichiers))
    print("  Espace recupere                 : {}".format(
        taille_lisible(espace)))

    for ligne in lignes_plan(plan, MAX_GROUPES_AFFICHES):
        print("  " + ligne if ligne else "")

    if len(plan) > MAX_GROUPES_AFFICHES:
        chemin_plan = ecrire_fichier(NOM_PLAN, lignes_plan(plan), "w")
        print()
        print("  {} autre(s) groupe(s) non affiche(s).".format(
            len(plan) - MAX_GROUPES_AFFICHES))
        if chemin_plan:
            print("  Plan complet : {}".format(texte_sur(chemin_plan)))
    print("-" * 70)


# ---------------------------------------------------------------------------
# SUPPRESSION
# ---------------------------------------------------------------------------

def fichier_inchange(chemin, taille, mtime_ns):
    """True si le fichier existe encore, tel qu'il etait lors de l'analyse."""
    try:
        info = os.stat(chemin_acces(chemin), follow_symlinks=False)
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode)
            and info.st_size == taille
            and info.st_mtime_ns == mtime_ns)


def executer_suppression(plan, journal, erreurs):
    """
    Envoie les copies a la Corbeille. Avant chaque envoi, le fichier conserve
    et la copie sont reverifies : un fichier modifie, deplace ou disparu
    depuis l'analyse n'est jamais touche.
    """
    nb_ok = 0
    nb_ignores = 0
    nb_erreurs = 0

    for groupe in plan:
        conserve = groupe["conserver"]
        if not fichier_inchange(*conserve):
            nb_ignores += len(groupe["supprimer"])
            erreurs.append("Groupe ignore, fichier conserve modifie ou "
                           "absent : {}".format(texte_sur(conserve[0])))
            continue

        for chemin, taille, mtime in groupe["supprimer"]:
            if not fichier_inchange(chemin, taille, mtime):
                nb_ignores += 1
                erreurs.append("Ignore, modifie depuis l'analyse : {}".format(
                    texte_sur(chemin)))
                continue
            try:
                send2trash.send2trash(chemin)
            except Exception as e:                      # send2trash varie
                nb_erreurs += 1
                erreurs.append("Echec Corbeille : {} ({})".format(
                    texte_sur(chemin), texte_sur(str(e))))
                continue
            nb_ok += 1
            ligne = "CORBEILLE  {}  ({})".format(
                texte_sur(chemin), taille_lisible(taille))
            journal.append(ligne)
            print("  " + ligne)

    print()
    print("  Envoyes a la Corbeille : {}".format(nb_ok))
    print("  Ignores par securite   : {}".format(nb_ignores))
    print("  Echecs                 : {}".format(nb_erreurs))
    return nb_ok, nb_ignores, nb_erreurs


# ---------------------------------------------------------------------------
# JOURNAL
# ---------------------------------------------------------------------------

def dossier_ecriture():
    """Dossier du script s'il est accessible en ecriture, sinon dossier perso."""
    dossier = os.path.dirname(os.path.abspath(__file__))
    return dossier if os.access(dossier, os.W_OK) else DOSSIER_PERSO


def ecrire_fichier(nom, lignes, mode):
    """Ecrit des lignes dans un fichier du dossier d'ecriture."""
    chemin = os.path.join(dossier_ecriture(), nom)
    try:
        with open(chemin, mode, encoding="utf-8", errors="replace") as f:
            for ligne in lignes:
                f.write(ligne + "\n")
        return chemin
    except OSError as e:
        print("  Ecriture impossible : {} ({})".format(
            texte_sur(chemin), texte_sur(e.strerror or str(e))))
        return None


def ecrire_journal(emplacements, journal, erreurs, dossiers_ignores):
    """Ajoute le compte rendu de la session au journal."""
    lignes = [
        "",
        "=" * 70,
        "Session du {}".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "Systeme : {}".format("Windows" if EST_WINDOWS else "Linux"),
        "Emplacements : {}".format(
            " | ".join(texte_sur(e) for e in emplacements)),
        "-" * 70,
    ]
    if journal:
        lignes.append("Fichiers envoyes a la Corbeille :")
        lignes.extend("  " + l for l in journal)
    else:
        lignes.append("Aucun fichier envoye a la Corbeille.")
    if dossiers_ignores:
        lignes.append("")
        lignes.append("Dossiers ignores par securite :")
        lignes.extend("  [{}] {}".format(r, texte_sur(d))
                      for d, r in dossiers_ignores)
    if erreurs:
        lignes.append("")
        lignes.append("Erreurs et elements ignores :")
        lignes.extend("  " + e for e in erreurs)
    lignes.append("=" * 70)

    chemin = ecrire_fichier(NOM_JOURNAL, lignes, "a")
    if chemin:
        print("\n  Journal : {}".format(texte_sur(chemin)))


# ---------------------------------------------------------------------------
# DETECTION DES EMPLACEMENTS
# ---------------------------------------------------------------------------

# Cle XDG, libelle, noms de dossier habituels (anglais puis francais).
DOSSIERS_STANDARD = (
    ("DESKTOP",   "Bureau",          ("Desktop", "Bureau")),
    ("DOCUMENTS", "Documents",       ("Documents",)),
    ("DOWNLOAD",  "Telechargements", ("Downloads", "Téléchargements",
                                      "Telechargements")),
    ("PICTURES",  "Images",          ("Pictures", "Images")),
    ("VIDEOS",    "Videos",          ("Videos", "Vidéos")),
    ("MUSIC",     "Musique",         ("Music", "Musique")),
)


def dossiers_xdg():
    """Lit les dossiers personnels declares sous Linux (user-dirs.dirs)."""
    resultat = {}
    fichier = os.path.join(DOSSIER_PERSO, ".config", "user-dirs.dirs")
    try:
        with open(fichier, encoding="utf-8") as f:
            for ligne in f:
                m = re.match(r'\s*XDG_([A-Z]+)_DIR\s*=\s*"(.*)"\s*$', ligne)
                if m:
                    resultat[m.group(1)] = m.group(2).replace(
                        "$HOME", DOSSIER_PERSO)
    except OSError:
        pass
    return resultat


def dossiers_personnels():
    """Liste (libelle, chemin) des dossiers personnels existants."""
    xdg = {} if EST_WINDOWS else dossiers_xdg()
    resultat = []
    for cle, libelle, noms in DOSSIERS_STANDARD:
        candidats = ([xdg[cle]] if cle in xdg else []) + [
            os.path.join(DOSSIER_PERSO, n) for n in noms]
        for chemin in candidats:
            if (os.path.isdir(chemin)
                    and not est_sous_chemin(DOSSIER_PERSO, chemin)):
                resultat.append((libelle, chemin))
                break
    return resultat


def disques():
    """Liste (libelle, chemin) des disques ou partitions accessibles."""
    resultat = []
    if EST_WINDOWS:
        try:
            import ctypes
            masque = ctypes.windll.kernel32.GetLogicalDrives()
        except (ImportError, AttributeError, OSError):
            masque = None
        for i, lettre in enumerate(string.ascii_uppercase):
            racine = "{}:\\".format(lettre)
            present = (masque >> i) & 1 if masque is not None else True
            if present and os.path.isdir(racine):
                resultat.append(("Disque {}:".format(lettre), racine))
        return resultat

    utilisateur = os.environ.get("USER") or os.path.basename(DOSSIER_PERSO)
    vus = set()
    for base in ("/media/" + utilisateur, "/run/media/" + utilisateur,
                 "/media", "/mnt"):
        try:
            with os.scandir(base) as contenu:
                for e in contenu:
                    if (e.is_dir(follow_symlinks=False)
                            and os.path.ismount(e.path)
                            and e.path not in vus):
                        vus.add(e.path)
                        resultat.append(("Disque", e.path))
        except OSError:
            continue
    return resultat


# ---------------------------------------------------------------------------
# INTERFACE
# ---------------------------------------------------------------------------

def demander(invite="> "):
    """Saisie clavier ; fin propre si l'entree est fermee."""
    try:
        return input(invite).strip()
    except EOFError:
        print("\n  Entree fermee, arret du programme.")
        sys.exit(1)


def droits_eleves():
    """True si le programme tourne en administrateur ou en root."""
    if EST_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (ImportError, AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def valider_emplacement(saisie):
    """Retourne (chemin_reel, None) ou (None, motif_du_refus)."""
    chemin = os.path.expanduser(saisie.strip().strip('"').strip("'"))
    if not chemin:
        return None, "chemin vide"
    chemin = os.path.abspath(chemin)
    if not os.path.isdir(chemin):
        return None, "dossier introuvable"
    reel = os.path.realpath(chemin)
    if racine_protegee(reel):
        return None, "zone systeme ou logiciel protegee"
    return reel, None


def choisir_emplacements():
    """Selection des emplacements a analyser."""
    titre("Etape 1/3 - Emplacements a analyser")
    proposes = dossiers_personnels() + disques()
    largeur = max([len(l) for l, _ in proposes] + [10])
    for i, (libelle, chemin) in enumerate(proposes, 1):
        print("  [{:>2}] {:<{}}  {}".format(
            i, libelle, largeur, texte_sur(chemin)))
    if not proposes:
        print("  Aucun dossier personnel ni disque detecte automatiquement.")
    print()
    print("  Saisie : numeros separes par des espaces, ou chemin complet")
    print("  d'un dossier. Entree vide pour valider la selection.")
    print("  Exemple : 1 2 5")

    choisis = []

    def ajouter(chemin_brut):
        chemin, refus = valider_emplacement(chemin_brut)
        if refus:
            print("  Refuse ({}) : {}".format(refus, texte_sur(chemin_brut)))
            return
        if any(est_sous_chemin(chemin, c) for c in choisis):
            print("  Deja couvert : {}".format(texte_sur(chemin)))
            return
        # Un nouvel emplacement englobe peut-etre des choix precedents.
        choisis[:] = [c for c in choisis if not est_sous_chemin(c, chemin)]
        choisis.append(chemin)
        print("  Ajoute : {}".format(texte_sur(chemin)))

    while True:
        saisie = demander()
        if not saisie:
            if choisis:
                return choisis
            print("  Aucun emplacement selectionne.")
            continue
        morceaux = saisie.split()
        if all(m.isdigit() for m in morceaux):
            for m in morceaux:
                n = int(m)
                if 1 <= n <= len(proposes):
                    ajouter(proposes[n - 1][1])
                else:
                    print("  Numero inconnu : {}".format(n))
        else:
            ajouter(saisie)


def choisir_categories():
    """Selection des categories de fichiers. Retourne le filtre."""
    titre("Etape 2/3 - Types de fichiers")
    ordre = sorted(k for k in CATEGORIES if k != 0) + [0]
    for num in ordre:
        nom, exts = CATEGORIES[num]
        if exts:
            detail = " ".join(sorted(exts))
        elif num == 10:
            detail = "extensions absentes des listes ci-dessus"
        else:
            detail = "toutes les extensions"
        print("  [{:>2}] {:<16} {}".format(num, nom, detail))
    print()
    print("  Saisie : numeros separes par des espaces. Exemple : 1 6")

    while True:
        morceaux = demander().split()
        if not morceaux:
            print("  Aucune categorie selectionnee.")
            continue
        if not all(m.isdigit() and int(m) in CATEGORIES for m in morceaux):
            print("  Saisie invalide, numeros attendus parmi la liste.")
            continue
        choisis = {int(m) for m in morceaux}
        break

    tout_mode = 0 in choisis
    tout_reste_mode = 10 in choisis
    extensions_cibles = set()
    for num in choisis:
        exts = CATEGORIES[num][1]
        if exts:
            extensions_cibles.update(exts)
    return extensions_cibles, tout_mode, tout_reste_mode


# ---------------------------------------------------------------------------
# PROGRAMME PRINCIPAL
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("FilePurge - Nettoyage des fichiers en double")
    print("Les copies partent a la Corbeille, rien n'est supprime definitivement.")
    print("=" * 70)

    if droits_eleves():
        print()
        print("  Attention : lancement avec les droits administrateur.")
        print("  Un lancement en utilisateur normal est fortement recommande.")
        print("  Saisir oui pour continuer malgre tout.")
        if demander().lower() != "oui":
            return

    emplacements = choisir_emplacements()
    filtre = choisir_categories()

    erreurs = []
    dossiers_ignores = []
    journal = []

    try:
        titre("Etape 3/3 - Analyse")
        tous_fichiers = []
        for racine in emplacements:
            print("  Parcours : {}".format(texte_sur(racine)))
            trouves = scanner_emplacement(racine, filtre, erreurs,
                                          dossiers_ignores)
            print("    {} fichier(s) retenu(s)".format(len(trouves)))
            tous_fichiers.extend(trouves)

        print()
        print("  Total : {} fichier(s) a comparer.".format(len(tous_fichiers)))
        if dossiers_ignores:
            print("  {} dossier(s) de logiciel ou de projet ignore(s) "
                  "(detail dans le journal).".format(len(dossiers_ignores)))
        if not tous_fichiers:
            print("  Aucun fichier a comparer.")
            return

        doublons = trouver_doublons(tous_fichiers, erreurs)
        if not doublons:
            print("  Aucun doublon detecte.")
            return

        plan = determiner_plan_suppression(doublons)
        titre("Plan de nettoyage")
        afficher_plan(plan)

        print("  Saisir oui pour envoyer ces copies a la Corbeille,")
        print("  autre chose pour annuler.")
        if demander().lower() == "oui":
            print()
            executer_suppression(plan, journal, erreurs)
        else:
            print("  Annule, aucun fichier n'a ete deplace.")
    finally:
        # Ecrit meme en cas d'interruption : aucune action ne reste sans trace.
        ecrire_journal(emplacements, journal, erreurs, dossiers_ignores)

    print("\n  Termine.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interruption (Ctrl+C), arret du programme.")
        sys.exit(130)
