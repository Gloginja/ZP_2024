import os
import sys

from PyQt5 import QtWidgets

from PGP import PGP
from dialog import Ui_Dialog
from gui import Ui_MainWindow
from user import User, users, getUserDataByEmail


def displayPrivateKeyList(main_ui: Ui_MainWindow, pgp_prot: PGP):
    main_ui.privateKeysList.clear()
    userPrivate = main_ui.sendFromCombo.currentText()
    for key in pgp_prot.keyRingManager.getAllPrivateKeysByUserID(userPrivate):
        main_ui.privateKeysList.addItem(str(key['keyID']))


def displayPublicKeysList(main_ui: Ui_MainWindow, pgp_prot: PGP):
    main_ui.publicKeyList.clear()
    userPublic = main_ui.sentToCombo.currentText()
    for key in pgp_prot.keyRingManager.getAllPublicKeysByUserID(userPublic):
        main_ui.publicKeyList.addItem(str(key['keyID']))


def send(main_ui: Ui_MainWindow, pgp_prot: PGP):
    privateKey = main_ui.privateKeysList.currentItem()
    publicKey = main_ui.publicKeyList.currentItem()
    if publicKey is not None or privateKey is not None:
        filePath, ext = QtWidgets.QFileDialog.getSaveFileName(caption='Save message: ', directory=os.getcwd(),
                                                              filter='JSON (*.json)')
        PU = pgp_prot.keyRingManager.getPU(int(publicKey.text())) if publicKey is not None else None
        PR = pgp_prot.keyRingManager.getPR(int(privateKey.text())) if privateKey is not None else None #ovde treba dopuniti
        sym_algo = 2 if main_ui.aesRadioButton.isChecked() else 1
        pgp_prot.send(filePath, PR, PU, main_ui.compressCheckbox.isChecked(), sym_algo,
                      main_ui.textEdit.toPlainText())
    else:
        pass


def generateNewKeyPair(main_ui: Ui_MainWindow, dialog_ui: Ui_Dialog, pgp_prot: PGP):
    name = dialog_ui.nameInput.text()
    email = dialog_ui.emailInput.text()
    password = dialog_ui.passwordInput.text()
    dialog_ui.nameInput.clear()
    dialog_ui.emailInput.clear()
    dialog_ui.passwordInput.clear()
    if name != '' and email != '' and password != '':
        if getUserDataByEmail(email) is None:
            users.append(User(email, password, name))
            main_ui.sentToCombo.addItem(email)
            main_ui.sendFromCombo.addItem(email)
        pgp_prot.keyRingManager.generateNewPairRSA(
            1024 if dialog_ui.keySize1024RadioButton.isChecked() else 2048,
            email,
            password)
        main_ui.sendFromCombo.setCurrentText(email)
        displayPrivateKeyList(main_ui, pgp_prot)
        displayPublicKeysList(main_ui, pgp_prot)


def configure(main_ui: Ui_MainWindow, dialog_ui: Ui_Dialog, pgp_prot: PGP):
    main_ui.generateKeyButton.clicked.connect(dialog_ui.dialog.show)
    dialog_ui.buttonBox.accepted.connect(lambda: generateNewKeyPair(main_ui, dialog_ui, pgp_prot))
    main_ui.sendFromCombo.currentIndexChanged.connect(lambda: displayPrivateKeyList(main_ui, pgp_prot))
    main_ui.sentToCombo.currentIndexChanged.connect(lambda: displayPublicKeysList(main_ui, pgp_prot))
    main_ui.sendMessageButton.clicked.connect(lambda: send(main_ui, pgp_prot))


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
