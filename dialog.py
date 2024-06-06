from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        self.dialog = Dialog
        self.dialog.setObjectName("Dialog")
        self.dialog.resize(409, 244)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(30, 200, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.nameLabel = QtWidgets.QLabel(Dialog)
        self.nameLabel.setGeometry(QtCore.QRect(60, 20, 55, 16))
        self.nameLabel.setObjectName("nameLabel")
        self.nameInput = QtWidgets.QLineEdit(Dialog)
        self.nameInput.setGeometry(QtCore.QRect(130, 20, 191, 22))
        self.nameInput.setObjectName("nameInput")
        self.emailLabel = QtWidgets.QLabel(Dialog)
        self.emailLabel.setGeometry(QtCore.QRect(60, 60, 55, 16))
        self.emailLabel.setObjectName("emailLabel")
        self.emailInput = QtWidgets.QLineEdit(Dialog)
        self.emailInput.setGeometry(QtCore.QRect(130, 60, 191, 22))
        self.emailInput.setObjectName("emailInput")
        self.passwordLabel = QtWidgets.QLabel(Dialog)
        self.passwordLabel.setGeometry(QtCore.QRect(60, 100, 61, 16))
        self.passwordLabel.setObjectName("passwordLabel")
        self.passwordInput = QtWidgets.QLineEdit(Dialog)
        self.passwordInput.setGeometry(QtCore.QRect(130, 100, 191, 22))
        self.passwordInput.setEchoMode(QtWidgets.QLineEdit.Password)
        self.passwordInput.setObjectName("passwordInput")
        self.label_4 = QtWidgets.QLabel(Dialog)
        self.label_4.setGeometry(QtCore.QRect(60, 150, 81, 16))
        self.label_4.setObjectName("label_4")
        self.keySize1024RadioButton = QtWidgets.QRadioButton(Dialog)
        self.keySize1024RadioButton.setGeometry(QtCore.QRect(150, 150, 95, 20))
        self.keySize1024RadioButton.setObjectName("keySize1024RadioButton")
        self.keySize1024RadioButton.setChecked(True)
        self.keySize2048RadioButton = QtWidgets.QRadioButton(Dialog)
        self.keySize2048RadioButton.setGeometry(QtCore.QRect(230, 150, 95, 20))
        self.keySize2048RadioButton.setObjectName("keySize2048RadioButton")

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept) # type: ignore
        self.buttonBox.rejected.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "RSA key generation"))
        self.nameLabel.setText(_translate("Dialog", "Name:"))
        self.emailLabel.setText(_translate("Dialog", "E-mail:"))
        self.passwordLabel.setText(_translate("Dialog", "Password:"))
        self.label_4.setText(_translate("Dialog", "RSA key size:"))
        self.keySize1024RadioButton.setText(_translate("Dialog", "1024"))
        self.keySize2048RadioButton.setText(_translate("Dialog", "2048"))