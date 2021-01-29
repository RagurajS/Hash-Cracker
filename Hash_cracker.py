import hashlib

print("\nThis tool will find the correct password from given Hash. This tool has different attacks such as Brute-force attack, Dictionary attack, combo of Brute-force & Dictionary attack. Keep strong dictionary (dict.txt) in same folder.\nBrute-force uses 0 to 1 million combinations. if you select no '3' these 0 - 1 million combo will be added at the last of each word dictionary has, And remember you enter the correct input. It detects many Hash types but reverses only MD5, SHA1, SHA2-256, SHA2.384, SHA2-512 at present. \n\t *** Created by Ragu ***, \n\t\t\tVersion 3\n\n")

type = input("Enter '1' to go with 'Brute-force only', '2' for 'dictionary attack only', 3 for 'combination of brute-force & dictionary attack': ")

given_hash = input("Gimme the Hash to attack: ")
#given_hash = "F3899973D90D9EBB3A03ABC143B293CD33CFD688CB949AE1FBA61ACAB0D3D6220948AB3C35E00AF9D9497484B666D7FEA9D7673E2FC6AE463936C7B797FB3AF0"

algorithm = 0
if (len(given_hash)==4):
  print("\nThis may be CRC-16 Hashing Algorithm. This is not supported yet!")
if (len(given_hash)==8):
  print("\nThis may be CRC-32 Hashing Algorithm. This is not supported yet!")
if (len(given_hash)==32):
    algorithm = '1'
elif (len(given_hash) == 40):
    algorithm = '2'
elif (len(given_hash)==64):
  algorithm = '3'
elif (len(given_hash) == 96):
    algorithm = '5'
elif (len(given_hash)==128):
    algorithm = '4'
elif (len(given_hash) == 60 and given_hash[:2] == "$1" or given_hash[:2] == "$2"):
  print("\nSeems this is BCrypt Hashing Algorithm. This is not supported yet!")
elif (len(given_hash) == 34 and given_hash[:2] == "$1"):
  print("\nSeems this is MD5-Crypt Hashing Algorithm. This is not supported yet!")
elif (len(given_hash) == 56):
  print("\nSeems this is Keccak-224 Hashing Algorithm. This is not supported yet!")
else:
  print("\nCouldn't find the Hash type you have entered, Either it's not valid or not in our database., Anyhow check capital/small letters and any spaces found.")
  exit(0)

if(algorithm == '0'):
    pass

if(algorithm == '1'):
    if (type == '1'):
        a = range(1000001)
        for b in a:

            b = str(b)
            print(b)
            get_hash = hashlib.md5(b.encode())
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tMD5 hash type detected.")
                print("\tMATCH FOUND - ", b)
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '2'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            line = line.strip().encode()
            print("Currently Matching on: ", line.strip())
            get_hash = hashlib.md5(line)
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tMD5 hash type detected.")
                print("\tMATCH FOUND - ", line.decode().strip())
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '3'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            a = range(1000001)
            for b in a:
                linee = line.strip() + str(b)
                lineee = linee.encode()
                print("Currently Matching on: ", linee)
                get_hash = hashlib.md5(lineee)
                hashed = get_hash.hexdigest()
                print(hashed)
                print(given_hash)
                if (hashed == given_hash):
                    print("\n\tMD5 hash type detected.")
                    print("\tMATCH FOUND - ", line.strip()+str(b))
                    exit(0)
                    # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
                else:
                    print("Still working on it, Kinda tricky...\n")

    else:
        print("Wrong selction. Enter 1 or 2 or 3 only!")

if (algorithm == '2'):
    if (type == '1'):
        a = range(1000001)
        for b in a:

            b = str(b)
            print(b)
            get_hash = hashlib.sha1(b.encode())
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA1 hash type detected.")
                print("\tMATCH FOUND - ", b)
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '2'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            line = line.strip().encode()
            print("Currently Matching on: ", line.strip())
            get_hash = hashlib.sha1(line)
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA1 hash type detected.")
                print("\tMATCH FOUND - ", line.decode().strip())
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '3'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            a = range(1000001)
            for b in a:
                linee = line.strip() + str(b)
                lineee = linee.encode()
                print("Currently Matching on: ", linee)
                get_hash = hashlib.sha1(lineee)
                hashed = get_hash.hexdigest()
                print(hashed)
                print(given_hash)
                if (hashed == given_hash):
                    print("\n\tSHA1 hash type detected.")
                    print("\tMATCH FOUND - ", line.strip() + str(b))
                    exit(0)
                    # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
                else:
                    print("Still working on it, Kinda tricky...\n")

    else:
        print("Wrong selction. Enter 1 or 2 or 3 only!")

if (algorithm == '3'):
    if (type == '1'):
        a = range(1000001)
        for b in a:

            b = str(b)
            print(b)
            get_hash = hashlib.sha256(b.encode())
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA2-256 hash type detected.")
                print("\tMATCH FOUND - ", b)
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '2'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            line = line.strip().encode()
            print("Currently Matching on: ", line.strip())
            get_hash = hashlib.sha256(line)
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA2-256 hash type detected.")
                print("\tMATCH FOUND - ", line.decode().strip())
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '3'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            a = range(1000001)
            for b in a:
                linee = line.strip() + str(b)
                lineee = linee.encode()
                print("Currently Matching on: ", linee)
                get_hash = hashlib.sha256(lineee)
                hashed = get_hash.hexdigest()
                print(hashed)
                print(given_hash)
                if (hashed == given_hash):
                    print("\n\tSHA2-256 hash type detected.")
                    print("\tMATCH FOUND - ", line.strip() + str(b))
                    exit(0)
                    # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
                else:
                    print("Still working on it, Kinda tricky...\n")

    else:
        print("Wrong selction. Enter 1 or 2 or 3 only!")

if (algorithm == '4'):
    if (type == '1'):
        a = range(1000001)
        for b in a:

            b = str(b)
            print(b)
            get_hash = hashlib.sha512(b.encode())
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA2-512 hash type detected.")
                print("\tMATCH FOUND - ", b)
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '2'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            line = line.strip().encode()
            print("Currently Matching on: ", line.strip())
            get_hash = hashlib.sha512(line)
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA2-512 hash type detected.")
                print("\tMATCH FOUND - ", line.decode().strip())
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '3'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            a = range(1000001)
            for b in a:
                linee = line.strip() + str(b)
                lineee = linee.encode()
                print("Currently Matching on: ", linee)
                get_hash = hashlib.sha512(lineee)
                hashed = get_hash.hexdigest()
                print(hashed)
                print(given_hash)
                if (hashed == given_hash):
                    print("\n\tSHA2-512 hash type detected.")
                    print("\tMATCH FOUND - ", line.strip() + str(b))
                    exit(0)
                    # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
                else:
                    print("Still working on it, Kinda tricky...\n")

    else:
        print("Wrong selction. Enter 1 or 2 or 3 only!")


if (algorithm == '5'):
    if (type == '1'):
        a = range(1000001)
        for b in a:

            b = str(b)
            print(b)
            get_hash = hashlib.sha384(b.encode())
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA2-384 hash type detected.")
                print("\tMATCH FOUND - ", b)
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '2'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            line = line.strip().encode()
            print("Currently Matching on: ", line.strip())
            get_hash = hashlib.sha384(line)
            hashed = get_hash.hexdigest()
            print(hashed)
            print(given_hash)
            if (hashed == given_hash):
                print("\n\tSHA2-512 hash type detected.")
                print("\tMATCH FOUND - ", line.decode().strip())
                exit(0)
                # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
            else:
                print("Still working on it, Kinda tricky...\n")

    elif (type == '3'):
        pwd = open("dict.txt", 'r')
        lines = pwd.readlines()

        for line in lines:

            a = range(1000001)
            for b in a:
                linee = line.strip() + str(b)
                lineee = linee.encode()
                print("Currently Matching on: ", linee)
                get_hash = hashlib.sha384(lineee)
                hashed = get_hash.hexdigest()
                print(hashed)
                print(given_hash)
                if (hashed == given_hash):
                    print("\n\tSHA2-512 hash type detected.")
                    print("\tMATCH FOUND - ", line.strip() + str(b))
                    exit(0)
                    # Break or Continue not gonna work on manin lines loop, it's going even after found the match!
                else:
                    print("Still working on it, Kinda tricky...\n")

    else:
        print("Wrong selction. Enter 1 or 2 or 3 only!")

