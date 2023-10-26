import os
import re
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import pandas as pd
import PySimpleGUI as sg


#color de la ventana
sg.theme('DarkRed')


EXCEL_FILE = './datos_cripto.xlsx'
data_frame = pd.read_excel(EXCEL_FILE)
data_frame2 = pd.read_excel("./Coordenadas.xlsx")
data_frame3 = pd.read_excel("./Claves_privadas.xlsx")

#CODIGO PARA ENCRIPTAR LAS CONTRASEÑAS
"""for index, row in data_frame.iterrows():
    salt = os.urandom(16)
    contraseña = row['Contraseña']
    contraseña_bytes = contraseña.encode('utf-8')
    data_frame.at[index, 'Salt'] = salt
    data_frame.to_excel('./datos_cripto.xlsx', index=False)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(contraseña_bytes)
    data_frame.at[index, 'Key'] = key
    data_frame.to_excel('./datos_cripto.xlsx', index=False)"""

#CODIGO PARA GENERAR LAS CLAVES PRIVADAS DE CADA USUARIO 
"""for index, row in data_frame3.iterrows():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    pem.splitlines()[0]
    data_frame3.at[index, 'Privadas'] = pem
    data_frame3.to_excel('./Claves_privadas.xlsx', index=False)"""

#CODIGO PARA OBTENER LA CALVE PÚBLICA DE CADA USUARIO Y GUARDARLA EN LA BASE DE DATOS
"""for index, row in data_frame.iterrows():
    nickname1 = row['Nickname']
    for index, row in data_frame3.iterrows():
        nickname2 = row['Nickname']
        privada = row['Privadas']
        privada_pem = serialization.load_pem_private_key(ast.literal_eval(privada), password=None)
        if nickname1 == nickname2:
            public_key = privada_pem.public_key()
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pem_public.splitlines()[0]
            data_frame.at[index, 'Key_public'] = pem_public  
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

def validar_coordenadas(coordenadas):
    rgx = r'^-?([0-9]|[1-8][0-9]|90)(\.\d{1,6})?,\s?-?((0|1[0-7][0-9]|[0-9]{1,2})|180)(\.\d{1,6})?$'
    if re.match(rgx, coordenadas):
        return True
    else:
        return False

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
                kdf = Scrypt(
                    salt=ast.literal_eval(salt),
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                )              
                key2 = kdf.derive(contraseña_bytes)
                
                #si coinciden
                if row['Nickname'] == nickname and key == key2:               
                    exito = True
                    #se sale del for
                    break
            if exito:
                sg.popup('Autenticado con éxito')

                #cerramos la ventana de autenticado
                window.close()
                
                #abrir una nueva ventana para enviar o recibir
                layout_main_ventana = [
                    [sg.Text('¿Deseas enviar o recibir coordenadas?')],
                    [sg.Submit('Enviar'), sg.Submit('Recibir')]
                ]
                
                window_main = sg.Window('Selección de Coordenadas', layout_main_ventana)
                
                while True:
                    event_main, values_main = window_main.read()                 
                    if event_main == sg.WIN_CLOSED:
                        window_main.close()
                        break

                    if event_main == 'Enviar':
                        window_main.close()

                        layout_enviar = [
                            [sg.Text('¿A quién quieres enviar tus coordenadas?')],
                            [sg.Text('Receptor', size=(15, 1)), sg.InputText(key='Receptor')],
                            [sg.Text('Coordenadas', size=(15, 1)), sg.InputText(key='Coordenadas')],
                            [sg.Submit('Aceptar'), sg.Exit('Cancelar')]
                        ]

                        window_enviar = sg.Window('Enviar coordenadas', layout_enviar)
                        
                        while True:
                            event_enviar, values_enviar = window_enviar.read()
                            if event_enviar == sg.WIN_CLOSED or event_enviar == 'Cancelar':
                                window_enviar.close()
                                break

                            elif event_enviar == 'Aceptar':
                                receptor = values_enviar['Receptor']
                                coordenadas = values_enviar['Coordenadas']
                                coordenadas_bytes = coordenadas.encode('utf-8')
                                if not receptor or not coordenadas:
                                    sg.popup_error('Tienes que completar todos los campos')        
                                else:

                                    comp = False
                                    for index, row in data_frame.iterrows():
                                        receptor_base = row['Nickname']
                                        if nickname == receptor:
                                            break
                                        elif receptor_base == receptor:
                                            comp = True
                                    
                                    if comp == False:
                                        sg.popup_error('Receptor no válido')
                                    
                                    else:
                                        if validar_coordenadas(coordenadas) == False:
                                            sg.popup_error('Coordenada no válida')
                                        else:                                         
                                            key_simetrica = Fernet.generate_key()
                                            f = Fernet(key_simetrica)
                                            coordenadas_encriptadas = f.encrypt(coordenadas_bytes)

                                            for index, row in data_frame.iterrows():
                                                receptor_base = row['Nickname']
                                                if receptor == receptor_base:
                                                    key_public = row['Key_public']
                                                    key_public_pem = serialization.load_pem_public_key(ast.literal_eval(key_public))

                                            for index, row in data_frame2.iterrows():
                                                receptor_base = row['Nickname']
                                                if receptor == receptor_base:
                                                    data_frame2.at[index, 'Coordenadas'] = coordenadas_encriptadas
                                                    data_frame2.to_excel('./Coordenadas.xlsx', index=False)
                                                    key_simetrica_cifrada = key_public_pem.encrypt(
                                                        key_simetrica,
                                                        padding.OAEP(
                                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None
                                                            )
                                                        )
                                                    data_frame2.at[index, 'Key_symmetric'] = key_simetrica_cifrada  
                                                    data_frame2.to_excel('./Coordenadas.xlsx', index=False)
                                            sg.popup('Coordenadas enviadas con éxito')
                                            window_enviar.close()

                    elif(event_main == 'Recibir'):
                        window_main.close()

                        for index, row in data_frame2.iterrows():
                            nickname_base = row['Nickname']
                            if nickname == nickname_base:
                                key_simetrica_cifrada = row['Key_symmetric']
                                coordenadas_cifradas = row['Coordenadas']
                        
                        if pd.isna(coordenadas_cifradas):
                            sg.popup("Todavía no se te han enviado coordenadas")
                        else:
                            for index, row in data_frame3.iterrows():
                                nickname_base = row['Nickname']
                                if nickname == nickname_base:
                                    privada = row['Privadas']

                            coordenadas_cifradas_bytes = ast.literal_eval(coordenadas_cifradas)
                            key_simetrica_cifrada_bytes = ast.literal_eval(key_simetrica_cifrada)
                            privada_pem = serialization.load_pem_private_key(ast.literal_eval(privada), password=None)
                            
                            key_simetrica_descifrada = privada_pem.decrypt(
                                        key_simetrica_cifrada_bytes,
                                        padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                        )
                                    )
                            f =  Fernet(key_simetrica_descifrada)
                            coordenada_descifrada = f.decrypt(coordenadas_cifradas_bytes)
                            coordenadas_str = str(coordenada_descifrada)
                            cadena_str = coordenadas_str[2:-1]
                            
                            layout_recibir = [
                                [sg.Text('Tus coordenadas son:' + cadena_str)],
                                [sg.Submit('Aceptar'), sg.Exit('Cancelar')]
                            ]

                            window_recibir = sg.Window('Recibir coordenadas', layout_recibir)

                            while True:
                                event_recibir, values_recibir = window_recibir.read()
                                if event_recibir == sg.WIN_CLOSED or event_recibir == 'Cancelar' or event_recibir == 'Aceptar':
                                    window_recibir.close()
                                    break

            #si no coinciden
            if not exito:
                sg.popup_error('Tus datos no coinciden con la base')
                clear_input()               

window.close()