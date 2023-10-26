import os
import re
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import pandas as pd
import PySimpleGUI as sg

data_frame2 = pd.read_excel("./Coordenadas.xlsx")
coordenadas_encriptadas = 1
nickname = "Usopp"
receptor = "Arlong"
for index, row in data_frame2.iterrows():
    receptor_base = row['Nickname']
    if receptor == receptor_base:
        print("entra")
        data_frame2.at[index, 'Coordenadas'] = coordenadas_encriptadas
        data_frame2.to_excel('./Coordenadas.xlsx', index=False)