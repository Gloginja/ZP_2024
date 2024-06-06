import sys

from PyQt5 import QtWidgets

from PGP import PGP
from dialog import Ui_Dialog
from gui import Ui_MainWindow
from user import User, users


def generateNewKeyPair(main_ui: Ui_MainWindow, dialog_ui: Ui_Dialog, pgp_prot: PGP):
    name = dialog_ui.nameInput.text()
    email = dialog_ui.emailInput.text()
    password = dialog_ui.passwordInput.text()
    if name != '' and email != '' and password != '':
        users.append(User(email, password, name))
        pgp_prot.keyRingManager.generateNewPairRSA(1024 if dialog_ui.keySize1024RadioButton.isChecked() else 2048,
                                                   email,
                                                   password)
        main_ui.sentToCombo.addItem(email)
        main_ui.sendFromCombo.addItem(email)


def configure(main_ui: Ui_MainWindow, dialog_ui: Ui_Dialog, pgp_prot: PGP):
    main_ui.generateKeyButton.clicked.connect(dialog_ui.dialog.show)
    dialog_ui.buttonBox.accepted.connect(lambda: generateNewKeyPair(main_ui, dialog_ui, pgp_prot))


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    PGPSimulator = QtWidgets.QMainWindow()
    InputDialog = QtWidgets.QDialog()
    InputDialog.setModal(True)
    dialogUI = Ui_Dialog()
    dialogUI.setupUi(InputDialog)
    mainUI = Ui_MainWindow()
    mainUI.setupUi(PGPSimulator)
    pgp = PGP()
    PGPSimulator.show()
    configure(mainUI, dialogUI, pgp)
    sys.exit(app.exec_())
