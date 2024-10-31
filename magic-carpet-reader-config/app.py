# app.py

from flask import Flask, render_template, request, jsonify
from threading import Thread
import time
from chainway_reader_interface import ChainwayReaderInterface

# Crée une instance de l'application Flask
app = Flask(__name__)

# Créez une instance de la classe RFIDReader
rfid_reader = ChainwayReaderInterface()

# Variable pour gérer l'inventaire
inventory_running = False
tags = []

# Définis une route pour la page d'accueil
@app.route('/')
def index():
    power_value = rfid_reader.get_power()  # Récupérer la puissance actuelle
    if power_value != None : 
        return render_template('index.html', power_value=power_value['decoded_data']['read_power'], tags=tags)
    else : 
        return render_template('index.html', tags=tags)

@app.route('/get_power', methods=['GET'])
def get_power():
    power_value = rfid_reader.get_power()  # Récupérer la puissance actuelle
    return jsonify(power=power_value['decoded_data']['read_power'])

@app.route('/set_power', methods=['POST'])
def set_power():
    new_power = int(request.form['power'])
    rfid_reader.set_power(new_power,new_power)
    return jsonify(success=True)

@app.route('/reset_reader', methods=['POST'])
def reset_reader():
    rfid_reader.reset_reader()
    return jsonify(success=True)

@app.route('/toggle_inventory', methods=['POST'])
def toggle_inventory():
    global inventory_running
    inventory_running = not inventory_running  # Inverse l'état de l'inventaire
    if inventory_running:
        rfid_reader.start_inventory_loop()
    elif not inventory_running :
        rfid_reader.stop_inventory_loop()
    return jsonify(success=True)

@app.route('/get_inventory', methods=['GET'])
def get_inventory():
    tags = rfid_reader.get_inventory()
    print(f'tags : {tags}')
    return jsonify(tags=tags)

@app.route('/clear_inventory', methods=['POST'])
def clear_inventory():
    rfid_reader.inventory_list.clear()  # Efface les valeurs dans inventory_list
    return jsonify(success=True)

# Lancer le serveur Flask
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1234, debug=True)