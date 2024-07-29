

def encrypt():
    
    pt1 = input('enter plain text:')
    key1 = input('key for add crypt:')
    key = int(key1)
    pt = pt1.lower()
    x= pt.split()
    for i in x:
        for j in i:
          
            j1 = ord(j)
            k = (j1-97+key)%26 
            final = k+97
            print(chr(final),end=' ')
        


def decrypt():
    pt1 = input('enter cypher text:')
    key1 = input('key :')
    key = int(key1)
    pt = pt1.lower()
    x= pt.split()
    for i in x:
        for j in i:
           
            j1 = ord(j)
            k = (j1-97-key)%26 
            final = k+97
            print(chr(final),end=' ')
           
while(1):
    y = input('\n e or d:')

    if(y == 'e') :
        encrypt()

    elif(y == 'd'):
        decrypt()

    else:
        print('incorrect option')

