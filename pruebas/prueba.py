import os
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pandas as pd
import PySimpleGUI as sg

sg.theme('DarkRed')


EXCEL_FILE = './datos_cripto.xlsx'
data_frame = pd.read_excel(EXCEL_FILE)

"""for index, row in data_frame.iterrows():
    salt = os.urandom(16)
    contraseña = row['Contraseña']
    contraseña_bytes = contraseña.encode('utf-8')
    data_frame.at[index, 'Salt'] = salt
    data_frame.to_excel('./datos_cripto.xlsx', index=False)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        )
    key = kdf.derive(contraseña_bytes)
    data_frame.at[index, 'Key'] = key
    data_frame.to_excel('./datos_cripto.xlsx', index=False)"""
    
layout = [

    [sg.Text('Por favor rellene con sus datos:')],
    [sg.Text('Nickname', size=(15, 1)), sg.InputText(key='Nickname')],
    [sg.Text('Contraseña', size=(15, 1)), sg.InputText(key='Contraseña', password_char='•')],
    [sg.Submit('Aceptar'), sg.Exit('Salir')]
]

window = sg.Window('App Cripto', layout)

def clear_input():
    for key in values:
        window[key]('')
    return None

while True:
    event, values = window.read()   
    if event == sg.WIN_CLOSED or event == 'Salir':
        break
    if event == 'Aceptar':
        nickname = values['Nickname']
        contraseña = values['Contraseña']

        #si los campos están vacíos lanzamos error
        if not nickname or not contraseña:
            sg.popup_error('Tienes que completar todos los campos')        
        else:

            exito = False
            #recorremos el excel y vemos si hay alguna coincidencia de usuarios y contraseñas en la base de datos
            for index, row in data_frame.iterrows():
                if row['Nickname'] == nickname:
                    print('yee')
                
                else:
                    print(row['Nickname'])
            
                                

window.close()