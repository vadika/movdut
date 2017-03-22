import unittest
from mkmvdut import main as mainfile


# import main as mainfile


class TestMokumCheck(unittest.TestCase):
    def test_user_exists(self):
        self.assertTrue(mainfile.mokum_check('vadikas'))

    def test_user_not_exist(self):
        self.assertFalse(mainfile.mokum_check('vdavdvadada'))

    def test_user_blocked(self):
        self.assertFalse(mainfile.mokum_check('liquidgold'))


if __name__ == '__main__':
    unittest.main()
