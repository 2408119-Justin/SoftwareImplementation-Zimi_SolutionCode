import hashlib
import secrets

#GLOBAL VARIABLES
#maximum number of users allowed in the system
MAX_USERS = 1000

#Stores registered user records
users = []

#Number of registered users
userCount = 0

#ID assigned to the next new user
nextUserID = 1
currentUserID = 0
FRAUD_THRESHOLD = 5_000_000

def FindEmail(email):
    email = email.strip().lower() #normalize the email for comparison

    for i in range(userCount):
        if users[i]['email'] == email:
            return i

    return -1

def FindUser(id):
    #Check each registered user to see if the ID matches
    for i in range(userCount):
        if users[i]["user_id"] == id: 
            return i #Return the user's position in the list

    return -1 #Return -1 if the user is not found

def ActiveUser(id, role):
    #Find the user position
    u = FindUser(id)

    #Check this before accessing users[u]
    if u == -1:
        return False

    #Both conditions must be true
    return users[u]["status"] == "ACTIVE" and users[u]["role"] == role 

def Authorized(role):
    #Check whether the logged-in user is active and has this role
    return ActiveUser(currentUserID, role)

def Logout():
    global currentUserID

    #Clear the session without deleting any accounts
    currentUserID = 0

def Login():
    global currentUserID

    #Clear any previous login session
    Logout()

    email = READ_REQUIRED("Email: ").lower()
    password = READ_REQUIRED("Password: ")  

    #Find the account linked to this email
    u = FindEmail(email)

    if u == -1:
        print("Email not registered")
        return

    #Check the entered password against the stored hash
    if not VerifyPassword(password, users[u]["password_hash"]):
        print("Incorrect password")
        return

    #Only active accounts can login
    if users[u]["status"] != "ACTIVE":
        print("Account is disabled or blocked. Please contact support.")
        return False

    #Save the permanent user ID for the current session
    currentUserID = users[u]["user_id"]

    print(f"Welcome, {users[u]['fullname']}! You are logged in as a {users[u]['role']}.")
    return True

def READ_REQUIRED(prompt):
    while True:
        #Ask the user for input and strip whitespace
        value = input(prompt).strip()

        if value != "":
            return value #send back the value if it's not empty

        print("This field is required. Please enter a value.")

def READ_CHOICE(options):
    while True:
        try:
            #Convert the entered text into a whole number
            choice = int(input("Enter your choice: "))

            #check whether the number is allowed
            if choice in options:
                return choice #send back the number if it's valid

            print ("Please choose one of: ", options)

        except ValueError:
            print("Please enter a whole number.")

def HashPassword(password):
    #Create random data so identical passwords get different hashes
    salt = secrets.token_bytes(16) #generate a random 16-byte salt

    #Use a passowrd-hashing algorithm
    password_hash = hashlib.scrypt(
        password.encode('utf-8'), #convert password to bytes
        salt = salt, #add the random salt
        n = 16384, #CPU/memory cost factor
        r = 8, #block size factor
        p = 1 #parallelization factor
    )

    #Store the salt and hash together as text
    return salt.hex() + ":" + password_hash.hex()

def VerifyPassword(password, stored_hash):
    #Separate the saved salt and password hash
    salt_text, hash_text = stored_hash.split(":") #salt_text -  is the hexadecimal representation of the salt, hash_text - is the hexadecimal representation of the password hash
                                                #salt is used to add randomness to the password hashing process, making it more secure against attacks like rainbow table attacks. 
                                                #The hash is the result of applying the hashing algorithm to the password combined with the salt.

    #convert the saved hexadecimal text back into bytes
    salt = bytes.fromhex(salt_text) #fromhex() converts hexadecimal string to bytes
    saved_hash = bytes.fromhex(hash_text)

    #Hash the entered password using the same salt and parameters
    entered_hash = hashlib.scrypt(
        password.encode('utf-8'), #convert password to bytes
        salt = salt, #use the saved salt
        n = 16384, #CPU/memory cost factor
        r = 8, #block size factor
        p = 1 #parallelization factor
    )

    #Return True if the hashes match, otherwise False
    return secrets.compare_digest(entered_hash, saved_hash) #compare_digest() is used to compare the two hashes 
                                                            #in a way that is resistant to timing attacks. It returns True if 
                                                            #the hashes match and False otherwise.

#REGISTRATION OF ZIMI SOLUTIONS CODE
def registration():
    global userCount, nextUserID
    PASSENGER = "PASSENGER"
    DRIVER = "DRIVER"
    ACTIVE = "ACTIVE"

    if userCount >= MAX_USERS:
        print("User storage full")
        return

    fullname = READ_REQUIRED("Fullname: ")
    email = READ_REQUIRED("Email: ").lower()
    phoneNum = READ_REQUIRED("Phone: ")
    password = READ_REQUIRED("Password: ")

    if FindEmail(email) != -1:
        print("Email already registered")
        return

    print("1 Passenger | 2 Driver")
    choice = READ_CHOICE({1, 2})

    if choice == 1:
        role = PASSENGER
    else:
        role = DRIVER

    new_user = {
        "user_id": nextUserID,
        "fullname": fullname,
        "email": email,
        "phoneNum": phoneNum,
        "password_hash": HashPassword(password),
        "role": role,
        "status": ACTIVE,
        "balance": 0
    }

    users.append(new_user) #add the new user to the list of users
    print(f"Registered. Your user ID is {nextUserID}.")

    userCount += 1
    nextUserID += 1

#registration() #Lets you test registering the same email again
#Login()
#print("Logged-in user ID:", currentUserID)
#Logout()
#print("After logout:", currentUserID)
def BootstrapAdmin():
    global userCount, nextUserID

    print("\n--- Initializing Admin Account ---")

    name = READ_REQUIRED("Initial admin name: ")
    email = READ_REQUIRED("Initial admin email: ").lower()
    phoneNum = READ_REQUIRED("Initial admin phone: ")
    password = READ_REQUIRED("Set admin password: ")

    #Use the same dictionary fields as registration()
    admin = {
        "user_id": nextUserID,
        "fullname": name,
        "email": email,
        "phoneNum": phoneNum,
        "password_hash": HashPassword(password),
        "role": "ADMIN",
        "status": "ACTIVE",
        "balance": 0
    }

    #Save the administor and advance the counters
    users.append(admin)
    userCount += 1
    nextUserID += 1

    print("Administor account created.")

#BootstrapAdmin() #Call this function to create the initial admin account when the program starts

#if Login():
##    print("Administrator access:", Authorized("ADMIN"))

#Logout()

def READ_OPTIONAL(prompt):
    return input(prompt).strip() #return the entered text, even if it's empty

def EditProfileFields(u):
    name = READ_OPTIONAL("New name, blank to keep current: ")
    phone = READ_OPTIONAL("New phone, blank to keep current: ")

    #Only replace fields when a new value was entered
    if name != "":
        users[u]["fullname"] = name

    if phone != "":
        users[u]["phoneNum"] = phone

def UpdateProfile():
    u = FindUser(currentUserID)

    if u == -1:
        print("Please log in")
        return

    if users[u]["status"] != "ACTIVE":
        Logout()
        return

    EditProfileFields(u)

    password = READ_OPTIONAL("New password, blank to keep current: ")

    if password != "":
        users[u]["password_hash"] = HashPassword(password)

    print("Profile updated.")

def SetUserStatus(newStatus):
    if not Authorized("ADMIN"):
        print("Access denied")
        return

    if users[u]["status"] == "BLOCKED" and newStatus == "DISABLED":
        print("User is already blocked")
        return

    id = READ_ID("User ID:")
    u = FindUser(id)

    if u == -1:
        print("User not found")
        return

    if users[u]["role"] == ("ADMIN"):
        print("Administrator accounts cannot be disabled or blocked here")
        return

    if users[u]["status"] == ("BLOCKED") and newStatus == ("DISABLED"):
        print("User is already blocked")
        return

    if users[u]["status"] == newStatus:
        print("Status already set")
        return

    if not CONFIRM("Confirm status change? 1 Yes 2 No"):
        return

    users[u]["status"] = newStatus
    print("User status changed to ", newStatus)

def MonitorTransactions():
    if not Authorized("ADMIN"):
        print("Access denied")
        return

    print("1 View All | 2 Find Transaction | 3 Back")
    choice = READ_CHOICE({1,2,3})

    match choice:
        case 1:
            if transactionCount == 0:
                print("No transactions")
                return

            for i in range(transactionCount):
                print(transactions[i])

        case 2:
            transaction_id = READ_ID("Transaction ID:")
            t = FindTransaction(transaction_id)

            if t == -1:
                print("Transaction not found")
                return

            print(transactions[t])

        case 3:
            return

def DetectFraud(): 
    if not Authorized("ADMIN"):
        print("Access denied")
        return

    found = False

    for i in range(transactionCount):
        transactions[i]["flagged"] == transactions[i]["amount"] > FRAUD_THRESHOLD

        if transactions[i]["flagged"]:
            print(transactions[i])
            found = True

        if found:
            print("Transactions flagged for administrator review")
        else:
            print("No transactions exceed the configured threshold")

        

def ManageUsers():
    if not Authorized("ADMIN"):
        print ("Access denied")
        return

    print("1 View Users | 2 Update User | 3 Disbale User | 4 Back")
    choice = READ_CHOICE({1, 2, 3, 4})

    match choice:
        case 1:
            for i in range(userCount):
                print (users[i]["user_id"], users[i]["fullname"], users[i]["email"], users[i]["role"], users[i]["status"])
        case 2:
            id = READ_ID("User ID to update: ")
            u = FindUser(id)

            if u == -1:
                print("User not found")
                return

            EditProfileFields(u)
            print("User updated")        
        case 3:
            SetUserStatus("DISABLED")
        case 4:
            return

def AdminServices():
    while Authorized("ADMIN"):
        print("1 Manage Users | 2 Monitor Transactions | 3 Detect Fraud")
        print("4 Block User | 5 Logout | 6 Update Own Profile")

        choice = READ_CHOICE({1, 2, 3, 4, 5, 6})

        match choice:
            case 1:
                ManageUsers()
            case 2:
                MonitorTransactions()
            case 3:
                DetectFraud()
            case 4:
                SetUserStatus("BLOCKED")
            case 5:
                Logout()
                return
            case 6:
                UpdateProfile()

    Logout() 

