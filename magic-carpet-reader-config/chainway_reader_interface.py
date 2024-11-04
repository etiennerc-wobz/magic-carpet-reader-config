import serial
import binascii
import time
import yaml
import os
from enum import Enum
import struct
import threading

class ChainwayReaderInterface:
    class Commands(Enum):
        SET_POWER = b'\x10'
        SET_POWER_RESPONSE = b'\x11'
        GET_POWER = b'\x12'
        GET_POWER_RESPONSE = b'\x13'
        SET_REGION = b'\x2c'
        SET_REGION_RESPONSE = b'\x2d'
        GET_REGION = b'\x2e'
        GET_REGION_RESPONSE = b'\x2f'
        START_INVENTORY = b'\x82'
        START_INVENTORY_RESPONSE = b'\x83'
        STOP_INVENTORY = b'\x8c'
        STOP_INVENTORY_RESPONSE = b'\x8d'
        RESET_SOFTWARE = b'\x68'
        RESET_SOFTWARE_RESPONSE = b'\x69'

    class Regions(Enum):
        CHINA1 = b'\x01'
        CHINA2 = b'\x02'
        EUROPE = b'\x04'
        USA = b'\x08'
        KOREA = b'\x16'
        JAPAN = b'\x32'

    class RFIDTag:
        def __init__(self,epc,rssi):
            self.epc = epc
            self.rssi = rssi
            self.counter = 1

        def update(self, rssi):
            self.rssi = rssi
            self.counter += 1

    def __init__(self):
        module_dir = os.path.dirname(__file__)
        with open(os.path.join(module_dir,'config/reader_config.yaml')) as yaml_file:
            try :
                config = yaml.safe_load(yaml_file)
            except yaml.YAMLError as exc:
                print(exc)
        self.serial_port_name = config['serial_port_name']
        self.serial_port_baud_rate = config['serial_port_baud_rate']

        self.serialPort = serial.Serial(
            port=self.serial_port_name,
            baudrate=self.serial_port_baud_rate,
            stopbits=serial.STOPBITS_ONE,
            timeout = 1
        )

        # Create a byte array to store incoming data
        self.serialPortBuffer = bytearray()

        self.frame_header = b'\xc8\x8c'
        self.frame_tail = b'\r\n'

        self.inventory_loop_enable = False
        self.inventory_loop_thread = 0

        self.inventory_list = []

        self.rssi_filter_value = -100

        time.sleep(0.5)
        self.serialPort.reset_input_buffer()
        time.sleep(0.5)
        self.serialPort.reset_output_buffer()


    def close(self):
        """Ferme la connexion série."""
        if self.serialPort.is_open:
            self.serialPort.close()

    def calculate_bcc(self, frame_without_bcc):
        """
        Calcule le BCC (XOR de tous les octets de la frame sauf l'en-tête et la queue).
        :param frame_without_bcc: Frame sans le BCC.
        :return: Byte BCC calculé.
        """
        bcc = 0x00
        for byte in frame_without_bcc:
            bcc ^= byte
        return struct.pack('B', bcc)

    def build_frame(self, command: Commands, data: bytes = b''):
        """
        Construit une frame à envoyer au lecteur RFID avec le bon format.
        :param command: Commande à envoyer (type Commands).
        :param data: Données supplémentaires à envoyer (si nécessaire).
        :return: Frame complète prête à être envoyée sous forme de byte array.
        """
        # Calcul de la longueur totale de la frame
        frame_length = 2 + 2 + 1 + len(data) + 1 + 2  # Header (2) + Length (2) + CMD (1) + Data (n) + BCC (1) + Tail (2)
        length_bytes = struct.pack('>H', frame_length)  # Encodage en big-endian (2 octets)

        # Construction de la frame sans BCC
        frame_without_bcc = self.frame_header + length_bytes + command.value + data

        # Calcul du BCC (XOR de tous les octets sauf en-tête et queue)
        bcc = self.calculate_bcc(frame_without_bcc[2:])  # Exclure les 2 octets de l'en-tête

        # Ajout du BCC et de la queue à la frame
        complete_frame = frame_without_bcc + bcc + self.frame_tail
        return complete_frame
    
    def send_command(self, command: Commands, data: bytes = b''):
        """
        Envoie une commande au lecteur RFID via le port série.
        :param command: Commande à envoyer (type Commands).
        :param data: Données supplémentaires à envoyer (si nécessaire).
        """
        frame = self.build_frame(command, data)
        self.serialPort.write(frame)
        print(f"Commande envoyée : {binascii.hexlify(frame)}")
        time.sleep(0.1)
        response = self.read_data()
        if response != None : 
            print(f"Données reçues : cmd : {response['command']}, result : {response['decoded_data']}")
        return response

    def read_data(self):
        """
        Lit les données reçues sur le port série, et renvoie une frame décodée.
        :return: La réponse du lecteur RFID sous forme de byte array.
        """
        if self.serialPort.in_waiting > 0:
            raw_data = self.serialPort.read(self.serialPort.in_waiting)
            print(f"Données reçues brutes : {binascii.hexlify(raw_data)}")
            return self.decode_frame(raw_data)
        else:
            return None
        
    def decode_frame(self, frame: bytes):
        """
        Décode une frame reçue du lecteur RFID.
        :param frame: Byte array contenant la frame reçue.
        :return: Dictionnaire avec le contenu de la frame décodée.
        """
        if frame.startswith(self.frame_header) and frame.endswith(self.frame_tail):
            frame_length = struct.unpack('>H', frame[2:4])[0]  # Extraction de la longueur
            command_byte = frame[4:5]  # Extraction de la commande
            data = frame[5:-3]  # Extraction des données (sans BCC et tail)
            bcc_received = frame[-3]  # Extraction du BCC reçu

            # Vérification du BCC
            calculated_bcc = self.calculate_bcc(frame[2:-3])
            if calculated_bcc != struct.pack('B', bcc_received):
                print("BCC incorrect, les données peuvent être corrompues")
                return None

            try:
                # Convertir le byte de commande en énumération
                command = self.Commands(command_byte)
            except ValueError:
                print(f"Commande inconnue: {command_byte}")
                return None

            # Décodage des données en fonction de la commande
            decoded_data = self.decode_data_by_command(command, data)

            return {
                'command': command,
                'decoded_data': decoded_data
            }
        else:
            print("Frame non valide")
            return None
        
    def decode_data_by_command(self, command: Commands, data: bytes):
        """
        Décode les données en fonction de la commande reçue en utilisant un dictionnaire de correspondance (type switch-case).
        :param command: La commande reçue (énumération).
        :param data: Les données brutes associées à la commande.
        :return: Un dictionnaire avec les données décodées spécifiques à la commande.
        """

         # Dictionnaire de fonctions pour simuler le comportement switch-case
        command_decoder = {
            self.Commands.SET_POWER_RESPONSE: self.decode_simple_response,
            self.Commands.GET_POWER_RESPONSE: self.decode_get_power_response,
            self.Commands.SET_REGION_RESPONSE: self.decode_simple_response,
            self.Commands.GET_REGION_RESPONSE: self.decode_get_region_response,
            self.Commands.RESET_SOFTWARE_RESPONSE: self.decode_simple_response,
        }

        # Obtenez la fonction de décodage pour la commande ou renvoyez une fonction de défaut si non trouvée
        decode_function = command_decoder.get(command, self.default_decode)
        
        # Appeler la fonction de décodage appropriée
        return decode_function(data)

    def decode_simple_response(self, data: bytes):
        """
        Décodage de commande simple.
        :param data: Données brutes associées à la commande.
        :return: Un dictionnaire contenant les informations décodées.
        """
        status = data[0]  # success_flag
        if status == 0x01:
            return {'status': 'success'}
        elif status == 0x00:
            return {'status': 'failure'}
        else:
            return {'status': 'unknown', 'value': status}
        
    def decode_get_power_response(self, data: bytes):
        """
        Décodage de la commande GET_POWER_RESPONSE.
        :param data: Données brutes associées à la commande.
        :return: Un dictionnaire contenant les informations décodées.
        """
        status = data[0]
        antenna = data[1:2]
        read_power = struct.unpack('>H', data[2:4])[0] / 100  # Puissance de lecture (2 bytes)
        write_power = struct.unpack('>H', data[4:6])[0] / 100  # Puissance d'écriture (2 bytes)
        return {
            'status': status,
            'antenna': antenna,
            'read_power': read_power,
            'write_power': write_power
        }

    def decode_get_region_response(self, data: bytes):
        """
        Décodage de la commande GET_REGION_RESPONSE.
        :param data: Données brutes associées à la commande.
        :return: Un dictionnaire contenant les informations décodées.
        """
        status = data[0]
        area_byte = data[1:2]
        try:
            # Convertir le byte de la zone géographique en énumération
            area = self.Areas(area_byte)
        except ValueError:
            print(f"Commande inconnue: {area_byte}")
            return None

        return {
            'status': status,
            'area': area
        }

    def default_decode(self, data: bytes):
        """
        Fonction par défaut pour décoder les données non reconnues.
        :param data: Données brutes associées à une commande inconnue.
        :return: Un dictionnaire contenant les données brutes.
        """
        return {'raw_data': data}

    def get_power(self):
        """
        Fonction pour récupérer le niveau de puissance actuel.
        """
        result = self.send_command(self.Commands.GET_POWER)
        return result


    def set_power(self, read_power_dbm: float, write_power_dbm: float):
        """
        Fonction pour définir la puissance de l'antenne du lecteur RFID.

        Les puissances de lecture et d'écriture sont fournies en dBm. Elles sont
        multipliées par 100 et ensuite converties en hexadécimal.

        :param read_power_dbm: Niveau de puissance de lecture en dBm (ex: 30.0).
        :param write_power_dbm: Niveau de puissance d'écriture en dBm (ex: 27.5).
        """
        # Conversion en entier (dBm * 100)
        read_power = int(read_power_dbm * 100)
        write_power = int(write_power_dbm * 100)
        # Validation des puissances : doivent être entre 0 et 65535 après conversion
        if 0 <= read_power <= 65535 and 0 <= write_power <= 65535:
            status = 0x00

            # Data: 1 byte pour l'antenne (toujours 0x01), 2 bytes pour read_power, 2 bytes pour write_power
            antenna = 0x01
            read_power_msb = (read_power >> 8) & 0xFF  # MSB de la puissance de lecture
            read_power_lsb = read_power & 0xFF         # LSB de la puissance de lecture
            write_power_msb = (write_power >> 8) & 0xFF  # MSB de la puissance d'écriture
            write_power_lsb = write_power & 0xFF         # LSB de la puissance d'écriture

            # Construire la donnée à envoyer dans le format Data
            data = struct.pack('B', status) + struct.pack('B', antenna) + struct.pack('B', read_power_msb) \
                + struct.pack('B', read_power_lsb) + struct.pack('B', write_power_msb) + struct.pack('B', write_power_lsb)

            # Envoi de la commande avec CMD et Data
            result = self.send_command(self.Commands.SET_POWER, data)
            return result
        else:
            print("Puissance de lecture/écriture invalide après conversion en dBm*100, doit être entre 0 et 65535")
            return None

    def set_region(self, region: Regions):
        """
        Fonction pour définir la bande de fréquence utilisé pour la RFID suivant la région 

        :param area: région du monde dans laquelle on travaille (énumération)
        """
        save_setting_flag = 0x00
        data = struct.pack('B', save_setting_flag) + struct.pack('B', region.value)

        result = self.send_command(self.Commands.SET_REGION, data)
        return result

    def get_region(self):
        """
        Fonction récupérer la bande de fréquence utilisé pour la RFID suivant la région 
        """
        result = self.send_command(self.Commands.GET_REGION)
        return result
    
    def start_inventory(self):
        """
        Fonction pour lancer la lecture de tag en continu
        """
        number_1 = 0x00
        number_2 = 0x01
        data = struct.pack('B', number_1) + struct.pack('B', number_2)
        frame = self.build_frame(self.Commands.START_INVENTORY, data)
        self.serialPort.write(frame)
        print(f"Commande envoyée : {binascii.hexlify(frame)}")
        time.sleep(0.1)
        return

    def stop_inventory(self):
        """
        Fonction pour arreter la lecture de tag en continu
        """
        frame = self.build_frame(self.Commands.STOP_INVENTORY)
        self.serialPort.write(frame)
        print(f"Commande envoyée : {binascii.hexlify(frame)}")
        time.sleep(0.1)
        return

    def start_inventory_loop(self):
        """
        Fonction pour demarrer le thread de lecture en continu
        """
        print("start_inventory_loop")
        self.start_inventory()
        self.inventory_loop_enable = True
        self.inventory_loop_thread = threading.Thread(target=self.inventory_loop)
        self.inventory_loop_thread.start()

    def stop_inventory_loop(self):
        """
        Fonction pour arreter le thread de lecture en continu
        """
        print("stop_inventory_loop")
        self.inventory_loop_enable = False
        if self.inventory_loop_thread is not None :
             self.inventory_loop_thread.join()

    def process_new_tag(self,epc, rssi):
        # Vérifier si l'epc existe déjà dans la liste
        for tag in self.inventory_list:
            if tag.epc == epc:
                # Mettre à jour le rssi et incrémenter le compteur
                tag.update(rssi)
                return

        # Si l'epc n'existe pas, l'ajouter à la liste
        new_tag = self.RFIDTag(epc, rssi)
        self.inventory_list.append(new_tag)

    def inventory_loop(self):
        print("inventory_loop")
        while self.inventory_loop_enable:
            frame = self.serialPort.read_until(self.frame_tail)
            if frame :
                self.decode_inventory_data(frame)
            time.sleep(0.01)
        self.stop_inventory()

    def decode_inventory_data(self, frame: bytes):
        """Décoder la réponse reçue du lecteur après la commande START_INVENTORY"""
        if frame.startswith(self.frame_header) and frame.endswith(self.frame_tail):
            frame_length = struct.unpack('>H', frame[2:4])[0]
            cmd = frame[4:5]
            data = frame[5:-3]  # Extraction des données (sans BCC et tail)
            bcc_received = frame[-3]  # BCC reçu

            # Calculer le BCC
            calculated_bcc = self.calculate_bcc(frame[2:-3])
            if calculated_bcc != struct.pack('B', bcc_received):
                print("BCC incorrect")
                return

            epc = data[2:14].hex()
            rssi_bytes = data[14:16]
            rssi_value = struct.unpack('>h', rssi_bytes)[0]  # RSSI en dBm * 10 (signed 16-bit)
            rssi = rssi_value / 10.0  # Conversion en dBm réel
            antenna = data[16]
            if (rssi >= self.rssi_filter_value):
                print(f"Tag EPC: {epc}, RSSI: {rssi}")
                # Vérifier si le tag EPC existe déjà dans inventory_list, sinon l'ajouter
                tag_exists = False
                for tag in self.inventory_list:
                    if tag['epc'] == epc:
                        if rssi < tag['rssi_min'] : 
                            tag['rssi_min'] = rssi
                        if rssi > tag['rssi_max'] :
                            tag['rssi_max'] = rssi
                        tag['rssi'] = rssi
                        tag['rssi_mean'] = (tag['counter']*tag['rssi'] + rssi) / (tag['counter']+1)
                        tag['counter'] += 1
                        tag_exists = True
                        break
                if not tag_exists:
                    self.inventory_list.append({'epc': epc, 'rssi': rssi,'rssi_mean': rssi, 'rssi_min': rssi, 'rssi_max': rssi, 'counter': 1})


    def get_inventory(self):
        return self.inventory_list
    
    def reset_reader(self):
        """
        Fonction récupérer la bande de fréquence utilisé pour la RFID suivant la région 
        """
        result = self.send_command(self.Commands.RESET_SOFTWARE)
        return result
    
    def set_rssi_filter_value(self,value):
        self.rssi_filter_value = value
        return
    
    def get_rssi_filter_value(self):
        return self.rssi_filter_value
    
if __name__ == "__main__":
    rfid_reader = ChainwayReaderInterface()  # Remplacer par le port série correct
    
    result = rfid_reader.get_power()
    if result != None : 
        print(f"get_power return : commande : {result['command']}, result : {result['decoded_data']}")
    time.sleep(1)
    
    result = rfid_reader.set_power(20,20)
    if result != None : 
        print(f"set_power return : commande : {result['command']}, result : {result['decoded_data']}")
    
    time.sleep(1)
    result = rfid_reader.get_power()
    if result != None : 
        print(f"get_power return : commande : {result['command']}, result : {result['decoded_data']}")
    
    time.sleep(5)
    rfid_reader.close()
