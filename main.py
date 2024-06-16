import datetime
import json
import os
import sys

from Cryptodome.PublicKey.RSA import RsaKey
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox

from PGP import PGP
from dialog import Ui_Dialog
from gui import Ui_MainWindow
from password import Ui_Dialog_Password
from user import User, users, getUserDataByEmail
from keyRing.keyRingManager import saveKey


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


def sendWithPR(passwordDialog: Ui_Dialog_Password, pgp_prot: PGP, filePath: str, PU: RsaKey | None, isCompressed: bool,
               sym_algo: int, message: str, keyID: int):
    password = passwordDialog.passwordInput.text()
    passwordDialog.passwordInput.clear()
    PR = pgp_prot.keyRingManager.getPR(keyID, password)
    if PR is None:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Incorrect password for selected private key!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Error")
        msg.exec_()
        return
    pgp_prot.send(filePath, PR, PU, isCompressed, sym_algo, message)


def receiveWithPR(passwordDialog: Ui_Dialog_Password, main_ui: Ui_MainWindow, pgp_prot: PGP, message_data: dict):
    password = passwordDialog.passwordInput.text()
    message = pgp_prot.receive(message_data, pgp_prot.keyRingManager, password)
    main_ui.textEdit.setText(message['data'] + '\n' + 'Sent ' + datetime.datetime.isoformat(message['timestamp']))


def send(main_ui: Ui_MainWindow, pgp_prot: PGP):
    privateKey = main_ui.privateKeysList.currentItem()
    publicKey = main_ui.publicKeyList.currentItem()
    if publicKey is not None or privateKey is not None:
        filePath, ext = QtWidgets.QFileDialog.getSaveFileName(caption='Save message: ', directory=os.getcwd(),
                                                              filter='JSON (*.json)')
        if filePath == '':
            return
        PU = pgp_prot.keyRingManager.getPU(int(publicKey.text())) if publicKey is not None else None
        if privateKey is not None:
            inputPasswordDialog = QtWidgets.QDialog()
            inputPasswordDialog.setModal(True)
            passwordDialog = Ui_Dialog_Password()
            passwordDialog.setupUi(inputPasswordDialog)
            passwordDialog.buttonBox.accepted.connect(lambda: sendWithPR(passwordDialog,
                                                                         pgp_prot,
                                                                         filePath,
                                                                         PU,
                                                                         main_ui.compressCheckbox.isChecked(),
                                                                         2 if main_ui.aesRadioButton.isChecked() else 1,
                                                                         main_ui.textEdit.toPlainText(),
                                                                         int(privateKey.text())))
            passwordDialog.keyid.setText(f"Key ID {privateKey.text()}")
            passwordDialog.user.setText(f"for user {main_ui.sendFromCombo.currentText()}")
            passwordDialog.Dialog.show()

        else:
            sym_algo = 2 if main_ui.aesRadioButton.isChecked() else 1
            pgp_prot.send(filePath, None, PU, main_ui.compressCheckbox.isChecked(), sym_algo,
                          main_ui.textEdit.toPlainText())
    else:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Please select private key or public key or both!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Info")
        msg.exec_()


def receive(main_ui: Ui_MainWindow, pgp_prot: PGP):
    filePath, ext = QtWidgets.QFileDialog.getOpenFileName(caption='Open message: ', directory=os.getcwd(),
                                                          filter='JSON (*.json)')
    if filePath == '':
        return
    with open(filePath, 'r') as f:
        message_data = json.load(f)

        if 'recipientKeyID' in message_data.keys():
            inputPasswordDialog = QtWidgets.QDialog()
            inputPasswordDialog.setModal(True)
            passwordDialog = Ui_Dialog_Password()
            passwordDialog.setupUi(inputPasswordDialog)
            key_data = None
            for k in pgp_prot.keyRingManager.privateKeyRing.keyRing:
                if k['keyID'] == message_data['recipientKeyID']:
                    key_data = k
                    break
            if key_data is None:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Critical)
                msg.setText("Recipient key not found!")
                # msg.setInformativeText('More information')
                msg.setWindowTitle("Key error")
                msg.exec_()
                return
            passwordDialog.keyid.setText(f"Key ID {key_data['keyID']}")
            passwordDialog.user.setText(f"for user {key_data['userID']}")
            passwordDialog.buttonBox.accepted.connect(
                lambda: receiveWithPR(passwordDialog, main_ui, pgp_prot, message_data))
            passwordDialog.Dialog.show()
        else:
            message = pgp_prot.receive(message_data, pgp_prot.keyRingManager)
            main_ui.textEdit.setText(
                message['data'] + '\n' + 'Sent ' + datetime.datetime.isoformat(message['timestamp']))


def checkPasswordAndSaveKey(pgp_prot: PGP, passwordDialog: Ui_Dialog_Password, filePath: str, key_data: dict):
    key = pgp_prot.keyRingManager.privateKeyRing.getPR(key_data['keyID'], passwordDialog.passwordInput.text())
    if key is None:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Password is incorrect for selected private key!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Critical")
        msg.exec_()
        return
    else:
        saveKey(filePath, key_data['userID'], key, passwordDialog.passwordInput.text())

def exportKey(main_ui: Ui_MainWindow, pgp_prot: PGP):
    privateKeyID = main_ui.privateKeysList.currentItem()
    publicKeyID = main_ui.publicKeyList.currentItem()
    if privateKeyID is None and publicKeyID is None:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Please select a private or public key to export!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Error")
        msg.exec_()
        return
    filePath, ext = QtWidgets.QFileDialog.getSaveFileName(caption='Export key: ', directory=os.getcwd(),
                                                          filter='PEM (*.pem)')
    if filePath == '':
        return
    if privateKeyID is not None:
        key_data = None
        for k in pgp_prot.keyRingManager.privateKeyRing.keyRing:
            if k['keyID'] == int(privateKeyID.text()):
                key_data = k
                break
        inputPasswordDialog = QtWidgets.QDialog()
        inputPasswordDialog.setModal(True)
        passwordDialog = Ui_Dialog_Password()
        passwordDialog.setupUi(inputPasswordDialog)
        passwordDialog.keyid.setText(f"Key ID {key_data['keyID']}")
        passwordDialog.user.setText(f"for user {key_data['userID']}")
        passwordDialog.buttonBox.accepted.connect(
            lambda: checkPasswordAndSaveKey(pgp_prot, passwordDialog, filePath, key_data))
        passwordDialog.Dialog.show()
    else:
        key_data = None
        for k in pgp_prot.keyRingManager.publicKeyRing.keyRing:
            if k['keyID'] == int(publicKeyID.text()):
                key_data = k
                break
        saveKey(filePath, key_data['userID'], key_data['PU'])


def importAndDisplayKey(filePath: str, main_ui: Ui_MainWindow, pgp_prot: PGP, passwordDialog: Ui_Dialog_Password):
    keyID = pgp_prot.keyRingManager.importKey_s(filePath, main_ui.sendFromCombo.currentText(),
                                                passwordDialog.passwordInput.text())
    if keyID is None:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Password is incorrect for private key import!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Critical")
        msg.exec_()
        return
    if keyID == -1:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Key with ID already present!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Critical")
        msg.exec_()
        return
    main_ui.privateKeysList.addItem(str(keyID))
    if main_ui.sentToCombo.currentText() == main_ui.sendFromCombo.currentText():
        main_ui.publicKeyList.addItem(str(keyID))


def importKey(main_ui: Ui_MainWindow, pgp_prot: PGP):
    if len(users) == 0:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("No users to import keys!")
        # msg.setInformativeText('More information')
        msg.setWindowTitle("Error")
        msg.exec_()
        return
    else:
        filePath, ext = QtWidgets.QFileDialog.getOpenFileName(caption='Import key: ', directory=os.getcwd(),
                                                              filter='PEM (*.pem)')
        try:
            main_ui.publicKeyList.addItem(
                str(pgp_prot.keyRingManager.importKey_s(filePath, main_ui.sentToCombo.currentText())))
        except ValueError:
            inputPasswordDialog = QtWidgets.QDialog()
            inputPasswordDialog.setModal(True)
            passwordDialog = Ui_Dialog_Password()
            passwordDialog.setupUi(inputPasswordDialog)
            passwordDialog.keyid.setText(f"Key for user {main_ui.sendFromCombo.currentText()}")
            passwordDialog.user.setText(f"Input password for private key import:")
            passwordDialog.buttonBox.accepted.connect(
                lambda: importAndDisplayKey(filePath, main_ui, pgp_prot, passwordDialog))
            passwordDialog.Dialog.show()


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
    main_ui.receiveMessageButton.clicked.connect(lambda: receive(main_ui, pgp_prot))
    main_ui.exportKeyButton.clicked.connect(lambda: exportKey(main_ui, pgp_prot))
    main_ui.importKeyButton.clicked.connect(lambda: importKey(main_ui, pgp_prot))


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
