import os
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pandas as pd
import PySimpleGUI as sg


#color de la ventana
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

#cada lista representa una fila en la pantalla de la app
layout = [

    [sg.Text('Por favor rellene con sus datos:')],
    [sg.Text('Nickname', size=(15, 1)), sg.InputText(key='Nickname')],
    [sg.Text('Contraseña', size=(15, 1)), sg.InputText(key='Contraseña', password_char='•')],
    [sg.Submit('Aceptar'), sg.Exit('Salir')]
]

window = sg.Window('App Cripto', layout)

#función para vaciar el input
def clear_input():
    for key in values:
        window[key]('')
    return None
        
while True:
    event, values = window.read()   
    if event == sg.WIN_CLOSED or event == 'Salir':
        break

    #al hacer click en aceptar se guarda el usuario y la contraseña en variables
    if event == 'Aceptar':
        nickname = values['Nickname']
        contraseña = values['Contraseña']
        #es necesario convertir la contraseña en bytes para poder derivar la key
        contraseña_bytes = contraseña.encode('utf-8')

        #si los campos están vacíos lanzamos error
        if not nickname or not contraseña:
            sg.popup_error('Tienes que completar todos los campos')        
        else:
            
            #variable booleana para determinar si se ha encontrado el usuario y si la contraseña es correcta
            exito = False
            #recorremos el excel y vemos si hay alguna coincidencia de usuarios y contraseñas en la base de datos
            for index, row in data_frame.iterrows():
                salt = row['Salt']
                key = ast.literal_eval(row['Key'])
                kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=ast.literal_eval(salt),
                iterations=480000,
                )
                key2 = kdf.derive(contraseña_bytes)
                
                #si coinciden
                if row['Nickname'] == nickname and key == key2:               
                    exito = True
                    #se sale del for
                    break

            if exito:
                sg.popup('Autenticado con éxito')
                """print(row['Nickname'])
                print(nickname)
                print(repr(salt))
                print(repr(ast.literal_eval(salt)))
                print(key)
                print(key2)
                print(contraseña)"""

                #cerramos la ventana de autenticado
                window.close()
                
                #abrir una nueva ventana para enviar o recibir
                layout_main_ventana = [
                    [sg.Text('Enviar coordenadas')],
                ]
                
                window_main = sg.Window('Selección de Coordenadas', layout_main_ventana)
                
                while True:
                    event_main, values_main = window_main.read()                 
                    if event_main == sg.WIN_CLOSED:
                        window_main.close()
                        break

            #si no coinciden
            if not exito:
                sg.popup_error('Tus datos no coinciden con la base')
                """print(row['Nickname'])
                print(nickname)
                print(repr(salt))
                print(repr(ast.literal_eval(salt)))
                print(key)
                print(key2)
                print(contraseña)"""
                clear_input()
                break

window.close()