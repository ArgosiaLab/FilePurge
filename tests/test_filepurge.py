"""
Tests automatises de FilePurge.

Chaque test construit une arborescence dans un dossier temporaire, lance
l'analyse puis la suppression, et verifie le resultat. L'envoi a la Corbeille
est remplace par un deplacement vers un dossier de test : la Corbeille reelle
n'est jamais utilisee.

Lancement depuis la racine du depot :
    python3 -m unittest discover -s tests -v
"""

import os
import sys
import time
import shutil
import tempfile
import unittest
from unittest import mock

RACINE_DEPOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RACINE_DEPOT)

import FilePurge as fp  # noqa: E402

CONTENU = b"contenu identique " * 5000      # plus de 64 Ko : empreinte complete
PETIT = b"petit contenu identique"           # moins de 64 Ko
FILTRE_TOUT = (set(), True, False)


def dossier_temporaire():
    """
    Cree un dossier de test hors des zones protegees : le dossier temporaire
    du systeme est lui-meme protege sous Linux.
    """
    for parent in (os.path.dirname(os.path.abspath(__file__)),
                   os.path.expanduser("~")):
        if not fp.racine_protegee(parent) and os.access(parent, os.W_OK):
            return tempfile.mkdtemp(prefix="filepurge_test_", dir=parent)
    raise unittest.SkipTest("aucun dossier de test disponible")


class BaseTest(unittest.TestCase):

    def setUp(self):
        self.dossier = dossier_temporaire()
        self.racine = os.path.join(self.dossier, "analyse")
        self.corbeille = os.path.join(self.dossier, "corbeille")
        os.makedirs(self.racine)
        os.makedirs(self.corbeille)

        def fausse_corbeille(chemin):
            destination = os.path.join(
                self.corbeille, "{}_{}".format(
                    len(os.listdir(self.corbeille)), os.path.basename(chemin)))
            shutil.move(chemin, destination)

        correctif = mock.patch.object(fp.send2trash, "send2trash",
                                      side_effect=fausse_corbeille)
        correctif.start()
        self.addCleanup(correctif.stop)

        # Affichage du programme coupe pendant les tests.
        silence = mock.patch.object(fp, "print", create=True)
        silence.start()
        self.addCleanup(silence.stop)
        self.addCleanup(shutil.rmtree, self.dossier, ignore_errors=True)

    def ecrire(self, relatif, donnees, age=0):
        chemin = os.path.join(self.racine, relatif)
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        with open(chemin, "wb") as f:
            f.write(donnees)
        t = time.time() - age
        os.utime(chemin, (t, t))
        return chemin

    def existe(self, relatif):
        return os.path.lexists(os.path.join(self.racine, relatif))

    def analyser(self, filtre=FILTRE_TOUT):
        self.erreurs, self.ignores = [], []
        fichiers = fp.scanner_emplacement(self.racine, filtre, self.erreurs,
                                          self.ignores)
        groupes = fp.trouver_doublons(fichiers, self.erreurs)
        return fp.determiner_plan_suppression(groupes)

    def nettoyer(self, filtre=FILTRE_TOUT):
        plan = self.analyser(filtre)
        self.journal = []
        resultat = fp.executer_suppression(plan, self.journal, self.erreurs)
        return plan, resultat


class TestDeduplication(BaseTest):

    def test_garde_la_copie_la_plus_recente(self):
        self.ecrire("a/copie1.pdf", CONTENU, age=300)
        self.ecrire("b/copie2.pdf", CONTENU, age=200)
        self.ecrire("c/copie3.pdf", CONTENU, age=100)
        self.ecrire("d/recente.pdf", CONTENU, age=10)
        _, (nb_ok, _, _) = self.nettoyer()
        self.assertEqual(nb_ok, 3)
        self.assertTrue(self.existe("d/recente.pdf"))
        for p in ("a/copie1.pdf", "b/copie2.pdf", "c/copie3.pdf"):
            self.assertFalse(self.existe(p), p)

    def test_le_nom_ne_compte_pas(self):
        self.ecrire("rapport.pdf", CONTENU, age=100)
        self.ecrire("autre_nom.pdf", CONTENU, age=10)
        plan = self.analyser()
        self.assertEqual(len(plan), 1)

    def test_petits_fichiers(self):
        self.ecrire("note1.txt", PETIT, age=100)
        self.ecrire("note2.txt", PETIT, age=10)
        self.nettoyer()
        self.assertFalse(self.existe("note1.txt"))
        self.assertTrue(self.existe("note2.txt"))

    def test_meme_debut_fin_differente(self):
        self.ecrire("a.pdf", CONTENU)
        self.ecrire("b.pdf", CONTENU[:-1] + b"Z")
        self.assertEqual(self.analyser(), [])

    def test_meme_taille_debut_different(self):
        self.ecrire("a.pdf", CONTENU)
        self.ecrire("b.pdf", b"Z" + CONTENU[1:])
        self.assertEqual(self.analyser(), [])

    def test_fichiers_vides_ignores(self):
        self.ecrire("vide1.txt", b"")
        self.ecrire("vide2.txt", b"")
        self.assertEqual(self.analyser(), [])

    def test_filtre_par_categorie(self):
        self.ecrire("a.pdf", CONTENU, age=100)
        self.ecrire("b.pdf", CONTENU, age=10)
        self.ecrire("a.jpg", PETIT, age=100)
        self.ecrire("b.jpg", PETIT, age=10)
        extensions_pdf = set(fp.CATEGORIES[6][1])
        plan = self.analyser((extensions_pdf, False, False))
        self.assertEqual(len(plan), 1)
        self.assertTrue(plan[0]["conserver"][0].endswith("b.pdf"))


class TestProtections(BaseTest):

    def test_dossier_cache(self):
        self.ecrire("visible.pdf", CONTENU)
        self.ecrire(".cache_logiciel/copie.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])

    def test_dossier_logiciel_bibliotheque(self):
        self.ecrire("visible.pdf", CONTENU)
        self.ecrire("Logiciel/moteur.dll", b"binaire")
        self.ecrire("Logiciel/donnees/copie.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])
        self.assertIn("logiciel", [r for _, r in self.ignores])

    def test_dossier_logiciel_sous_dossier_bin(self):
        self.ecrire("visible.pdf", CONTENU)
        self.ecrire("Logiciel/bin/libmoteur.so.6", b"binaire")
        self.ecrire("Logiciel/donnees/copie.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])

    def test_installeur_isole_ne_bloque_pas(self):
        self.ecrire("Telechargements/installeur.exe", b"binaire")
        self.ecrire("Telechargements/a.pdf", CONTENU, age=100)
        self.ecrire("Telechargements/b.pdf", CONTENU, age=10)
        self.assertEqual(len(self.analyser()), 1)

    def test_donnees_de_logiciel(self):
        self.ecrire("visible.pdf", CONTENU)
        self.ecrire("Sauvegardes/reglages.cfg", b"reglage")
        self.ecrire("Sauvegardes/profil/copie.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])

    def test_reglage_isole_ne_bloque_pas(self):
        self.ecrire("Documents/reglages.ini", b"reglage")
        self.ecrire("Documents/a.pdf", CONTENU, age=100)
        self.ecrire("Documents/b.pdf", CONTENU, age=10)
        self.assertEqual(len(self.analyser()), 1)

    def test_projet_de_code(self):
        self.ecrire("visible.pdf", CONTENU)
        self.ecrire("projet/.git/HEAD", b"ref")
        self.ecrire("projet/copie.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])

    def test_dossier_de_dependances(self):
        self.ecrire("visible.pdf", CONTENU)
        self.ecrire("site/node_modules/paquet/copie.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])

    def test_extension_protegee(self):
        self.ecrire("a.ini", PETIT)
        self.ecrire("b.ini", PETIT)
        self.assertEqual(self.analyser(), [])

    @unittest.skipIf(fp.EST_WINDOWS, "liens symboliques reserves aux administrateurs")
    def test_lien_symbolique(self):
        cible = self.ecrire("original.pdf", CONTENU)
        os.symlink(cible, os.path.join(self.racine, "lien.pdf"))
        os.symlink(self.racine, os.path.join(self.racine, "lien_dossier"))
        self.assertEqual(self.analyser(), [])

    def test_lien_physique(self):
        cible = self.ecrire("original.pdf", CONTENU)
        try:
            os.link(cible, os.path.join(self.racine, "lien.pdf"))
        except OSError:
            self.skipTest("liens physiques non pris en charge")
        self.nettoyer()
        self.assertTrue(self.existe("original.pdf") or self.existe("lien.pdf"))

    @unittest.skipIf(fp.EST_WINDOWS, "tubes nommes propres a Linux")
    def test_tube_nomme(self):
        os.mkfifo(os.path.join(self.racine, "tube.pdf"))
        self.ecrire("a.pdf", CONTENU)
        self.assertEqual(self.analyser(), [])

    def test_fichier_modifie_apres_analyse(self):
        self.ecrire("ancienne.pdf", CONTENU, age=100)
        self.ecrire("recente.pdf", CONTENU, age=10)
        plan = self.analyser()
        with open(os.path.join(self.racine, "ancienne.pdf"), "ab") as f:
            f.write(b"modification")
        nb_ok, nb_ignores, _ = fp.executer_suppression(plan, [], self.erreurs)
        self.assertEqual((nb_ok, nb_ignores), (0, 1))
        self.assertTrue(self.existe("ancienne.pdf"))

    def test_copie_conservee_disparue(self):
        self.ecrire("ancienne.pdf", CONTENU, age=100)
        self.ecrire("recente.pdf", CONTENU, age=10)
        plan = self.analyser()
        os.remove(os.path.join(self.racine, "recente.pdf"))
        nb_ok, _, _ = fp.executer_suppression(plan, [], self.erreurs)
        self.assertEqual(nb_ok, 0)
        self.assertTrue(self.existe("ancienne.pdf"))


class TestControles(unittest.TestCase):

    @unittest.skipIf(fp.EST_WINDOWS, "chemins systeme propres a Linux")
    def test_zones_systeme_linux_refusees(self):
        for chemin in ("/usr", "/etc", "/tmp", "/var/log"):
            self.assertTrue(fp.racine_protegee(chemin), chemin)
        self.assertFalse(fp.chemin_systeme_linux("/run/media/disque"))

    def test_dossiers_systeme_windows_reconnus(self):
        for nom in ("Windows", "Program Files", "AppData", "$Recycle.Bin"):
            self.assertTrue(fp.dossier_protege(nom, nom), nom)

    def test_noms_pieges_neutralises(self):
        nom = "photo\x1b[31m\n\u202egpj.exe"
        propre = fp.texte_sur(nom)
        for caractere in ("\x1b", "\n", "\u202e"):
            self.assertNotIn(caractere, propre)

    def test_bibliotheque_versionnee_protegee(self):
        self.assertTrue(fp.extension_protegee("libexemple.so.6"))
        self.assertFalse(fp.extension_protegee("photo.jpg"))


if __name__ == "__main__":
    unittest.main()
