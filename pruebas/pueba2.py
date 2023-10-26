import pandas as pd
from cryptography.fernet import Fernet
data_frame3 = pd.read_excel("./Claves_privadas.xlsx")
nickname = "Arlong"

for index, row in data_frame3.iterrows():
    nickname_base = row['Nickname']
    if nickname == nickname_base:
        privada = row['Privadas']

print(nickname_base)
key_simetrica = Fernet.generate_key()
print(len(key_simetrica))