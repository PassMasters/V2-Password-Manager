import sys
from PyQt6.QtWidgets import QApplication, QWizard, QLineEdit
from PyQt6.uic import loadUi
import winreg
import requests
import jwt
class MyWizardApp(QWizard):
    def __init__(self):
        super().__init__()
        loadUi("setup.ui", self)  # Replace with the actual path to your .ui file
        self.currentIdChanged.connect(self.on_page_changed)

    def on_page_changed(self, page_id):
        if page_id == 1:  # Adjust the page ID based on your actual setup
            # Access the Line Edit widget on Page 1 and print its text
            Username = self.findChild(QLineEdit, "Username").text()
            API = self.findChild(QLineEdit, "apikey").text()
            url = "https://passmasters.vercel.app/api/tokenrequest"
            data = {"key": API}
            response = requests.post(url, data=data)
            print("POST request successful!")
            print("Response:", response.text)
            json_data = response.json()
            print(json_data)
            token_value = json_data["token"]
            print(token_value)
            decoded_token = jwt.decode(token_value, algorithms=["HS256"], key=b'OIDFJIODSFJIODSFJIU(WFHOISDF903248uweriy87345ureiyrtb965258752475201258525475sduri6838ejmfiuvmknmeujdjedjdjjdjdjdjd)')
            serial_claim = decoded_token.get("serial")
            for claim, value in decoded_token.items():
                registry_key_path = r"Software\PassMasters\Secure"
                try:
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key_path)
                    winreg.SetValueEx(key, claim, 0, winreg.REG_SZ, str(value))
                    print(f"Claim '{claim}' saved to the Windows Registry.")
                except PermissionError:
                    print(f"Permission error when accessing '{claim}' in the Windows Registry.")
                finally:
                    if key:
                        winreg.CloseKey(key)
            try:
                registry_key_path = r"Software\PassMasters"
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key_path)
                winreg.SetValueEx(key, "APISetupComplete", 0, winreg.REG_BINARY, b'\x01')
            except PermissionError:
                    print("Setup Failure")
            data = {"key": API, "username": Username, 'Serial': serial_claim, 'Perm1': "Read All TOTP Secrets", 'Perm2': "Store Account Data"}
            url = "https://passmasters.vercel.app/api/request"
            response = requests.post(url, data=data)
            json_data = response.json()
            code = json_data["code"]
            print(code)
            line_edit_code = self.findChild(QLineEdit, "Code")
            
            if line_edit_code:
                # The Line Edit widget is found, you can set its text
                new_code_value = code  # Replace with the value you want to set
                line_edit_code.setText(new_code_value)
                print("Value changed in Line Edit 'code' on Page 2 before display.")
            else:
                print("Line Edit 'code' not found on Page 2.")
            
                
if __name__ == "__main__":
    app = QApplication(sys.argv)
    wizard_app = MyWizardApp()
    wizard_app.show()
    sys.exit(app.exec())