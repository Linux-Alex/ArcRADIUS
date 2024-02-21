from flask import Flask
import sqlite3
from pyrad import server, packet, dictionary
import hashlib
import logging
import ipaddress
import yaml
import os
import binascii
import socket
from pprint import pprint, pformat
import netifaces as ni
import pyotp
from flask import current_app
import json
from helper import createAddressFileIfNotExists, createDbIfNotExists

def read_config():
    try:
        with open('config.json', 'r') as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        print("Config file not found.")
        return {}


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"



if not os.path.exists("instance"):
    os.mkdir("instance")

if not os.path.exists(path=os.path.join(os.path.dirname(__file__), "logs")):
    os.mkdir(os.path.join(os.path.dirname(__file__), "logs"))

logging.basicConfig(filename=os.path.join(os.path.dirname(__file__), "logs", "radius_server.log"), level="INFO", format="%(asctime)s [%(levelname)-8s] %(message)s")

def validate_otp(secret_key, otp_code):
    """
    Validate OTP code against the secret key.

    Args:
    - secret_key (str): The secret key used to generate OTP codes.
    - otp_code (str): The OTP code to validate.

    Returns:
    - bool: True if the OTP code is valid, False otherwise.
    """
    try:
        totp = pyotp.TOTP(secret_key)
        return totp.verify(otp_code)
    except pyotp.InvalidToken:
        return False

def get_clients(srv):
    with app.app_context():
        print("Reading clients from file")

        # Create if not exists
        createAddressFileIfNotExists()

        try:
            doc = yaml.load(open(os.path.join(os.path.dirname(__file__), "clients", "address.yml"), 'r').read(), Loader=yaml.FullLoader)

            for entry in doc:
                if doc[entry]['type_net'] == "subnet":
                    net = ipaddress.IPv4Network(doc[entry]['IP'])
                    numbers = int(str(net[-1]).split(".")[-1]) - int(str(net[0]).split(".")[-1])
                    for i in range(0,numbers+1):
                        srv.hosts[str(net[i])] = server.RemoteHost(str(net[i]), bytes(doc[entry]['secret'], 'utf-8'), doc[entry]['name'])
                elif doc[entry]['type_net'] == "ip":
                    srv.hosts[doc[entry]['IP']] = server.RemoteHost(doc[entry]['IP'], bytes(doc[entry]['secret'], 'utf-8'), doc[entry]['name'])
        except Exception as error:
            print("Error: ", error)
            logging.error("Error: ", error)
            logging.error("Invalid clients config. Also empty clients file is not allowed.")
            exit(1)

        hostname = socket.gethostname()
        
        try:
            IPAddr = next((addr['addr'] for iface in ni.interfaces() for addr in ni.ifaddresses(iface).get(ni.AF_INET, []) if not addr['addr'].startswith('127.')), None)
        except Exception as error:
            print("Error: ", error)
            logging.error("Error: ", error)

        srv.BindToAddress(str(IPAddr))

        print("Hostname: {}, IP: {}".format(hostname, IPAddr))

        logging.info("Server listen on IP {}, port 1812".format(str(IPAddr)))
        print("Server listen on IP {}, port 1812".format(str(IPAddr)))

class RADIUSserver(server.Server):

    _collection = None

    def checkAccess(self, user, password, otp_code=None, check_password=True):
        if isinstance(otp_code, list):
            otp_code = otp_code[0]

        # Create initial database if it doesn't exist
        createDbIfNotExists()

        print("Checking access for user: {0} with password: {1} otp: {2}".format(user, password, otp_code))
        # return empty user
        conn = sqlite3.connect('/etc/arc-radius/instance/db.sqlite3')
        cursor = conn.cursor()

        if check_password:
            cursor.execute('SELECT otp_secret FROM user WHERE LOWER(username) = ? AND password = ?', (user.lower(), password))
        else:
            cursor.execute('SELECT otp_secret FROM user WHERE LOWER(username) = ?', (user.lower(),))
        user = cursor.fetchone()
        conn.close()

        print("OTP secret: ", user)

        if user is None or user[0] is None:
            return False
        
        # send accepted if otp is not needed
        if otp_code is None:
            return True
        
        # valid otp
        secret = user[0]
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code)


        # return User.query.filter_by(username=user, password=password).first() is not None

    def _HandleAuthPacket(self, pkt):
        server.Server._HandleAuthPacket(self, pkt)
        logging.info(msg="Received an authentication request from {0}".format(pkt['NAS-IP-Address'][0]))

        # Check if needing to save the packet and overwrite the last one
        config = read_config()
        save_last_package = config.get('save_last_package', False)
        if save_last_package:
            with open('last_package.txt', 'w') as f:
                f.write(pkt.__str__())
                f.write("\n--------------------\n")

                # print by each attribute in the packet
                for attr in pkt.keys():
                    pprint_string = pformat(pkt[attr])

                    f.write(attr + ": " + pprint_string + "\n")

                    # print also password decrypted
                    if attr == "User-Password":
                        try:
                            f.write("User-Password decrypted: " + pkt.PwDecrypt(pkt[attr][0]) + "\n")
                        except Exception as error:
                            f.write("User-Password decrypted: " + str(error) + "\n")


        reply = self.CreateReplyPacket(pkt)

        if len(pkt['User-Name']) > 0:
            try:
                # pwd = hashlib.sha256(pkt.PwDecrypt(pkt['User-Password'][0]).encode("utf-8")).hexdigest()
                pwd = pkt.PwDecrypt(pkt['User-Password'][0])#.encode("utf-8")
                # pwd to string

                # check if OTP is needed
                config = read_config()
                check_otp = config.get('check_otp', False)
                otp_code = None
                if check_otp:
                    password_and_otp_same_field = config.get('password_and_otp_same_field', False)
                    if password_and_otp_same_field:
                        otp_code = pwd[-6:]
                    else:
                        otp_pin_field = config.get('otp_pin_field', '')
                        if otp_pin_field == '':
                            otp_code = pkt['EAP-Message']
                        else:
                            otp_code = pkt[otp_pin_field][0]

                # check if password is needed
                check_password = config.get('check_password', False)

                if self.checkAccess(user=pkt['User-Name'][0], password=pwd, otp_code=otp_code, check_password=check_password):
                    logging.info(msg="Correct access from {0} with user {1}".format(pkt['NAS-IP-Address'][0], pkt['User-Name'][0]))
                    reply.code = packet.AccessAccept
                else:
                    logging.info(msg="Incorrect user credentials from {0} with user {1}".format(pkt['NAS-IP-Address'][0], pkt['User-Name'][0]))
                    reply.code = packet.AccessReject
            except Exception as error:
                logging.info(msg="Incorrect shared secret in access from {0} with user {1}".format(pkt['NAS-IP-Address'][0], pkt['User-Name'][0]))
                print("Error: ", error)
                reply.code = packet.AccessReject
            finally:
                self.SendReplyPacket(pkt.fd, reply)

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
        except OSError as e:
            if e.errno == 98:  # Address already in use
                return True
            else:
                raise
        return False
    

if __name__ == '__main__':
    # log start
    logging.info("Starting ArcRADIUS service")
    
    if is_port_in_use(1812):
        print("Error: Port 1812 is already in use.")
        logging.error("Error: Port 1812 is already in use.")
        exit(1)
        
    try:
        # create server and read dictionary
        srv = RADIUSserver(dict=dictionary.Dictionary(os.path.join(os.path.dirname(__file__), "dictionary", "dictionary.txt")))
        # add clients (address, secret, name)
        get_clients(srv=srv)
        # start server
        srv.Run()
    except Exception as error:
        print("Error: ", error)
        logging.exception("Error: Couldn't start ArcRADIUS service")  # Log the exception with traceback
