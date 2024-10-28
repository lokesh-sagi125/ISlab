def hashing(s):
    hashval=5381
    for char in s:
        hashval=(hashval*33)+ord(char)
        
    hashval=hashval & 0xFFFFFFFF
    return hashval

msg="Ayush"
print(hashing(msg))