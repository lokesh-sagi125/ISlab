
def encrypt(text,key):
    encrypted = ''
    for i in range(len(text)):
        pt = int(text[i])
        k = int(key[i])
        encrypted[i] = ((pt-97)+(k-97))%26
        print(chr(encrypted[i]+97),end=' ')


def decrypt():
    encrypted = ''
    for i in range(len(text)):
        pt = int(text[i])
        k = int(key[i])
        encrypted[i] = ((pt-97)-(k-97))%26
        print(chr(encrypted[i]+97),end=' ')



while(1):
    text = input('enter text :')
    text1 = text.replace(' ','')
    text2 = list(text1)
    key = input('enter key:')
    if (len(text)!=len(key)):
        key1 = key
        while(len(key1)<len(text)):
            key1 += key
    key2 = list(key1)
    print('\n')
    y = input('e or d :')
    if (y =='e'):
        encrypt(text2,key2)
        
    elif(y=='d'):
        decrypt(text2,key2)