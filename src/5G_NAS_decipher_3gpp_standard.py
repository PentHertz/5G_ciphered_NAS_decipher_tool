#!/usr/bin/env python3
"""
5G NAS Deciphering Tool with ImGui
Cross-platform compatible (Windows/Linux)
"""

import imgui
from imgui.integrations.glfw import GlfwRenderer
import glfw
import threading
import queue
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
import pyshark
import sys
import os
import os.path
import subprocess
import platform
import shutil
from datetime import datetime
from time import sleep as module_time_sleep
import logging
import logging.handlers
from CryptoMobile.Milenage import Milenage
import pysnow
import pyzuc
from logging.handlers import QueueHandler
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

logging.basicConfig()
logger = logging.getLogger(name="decipher")


class TSharkNotFoundException(Exception):
    pass


class Decryption:
    def __init__(self, decrypt_suci, private_key, secret_key,
                 use_op, op, opc, file_location, _queue, tshark_path, new_bearer_id):
        """
        self.ue_dict contains all data for each UE like ngap_id, rand, encryption key, RES, use SUPI as index.
        It's a three dimensionals dictionary and key in first level is ran-UE-ngap-ID, key in second
        level dict is GNB-IP, third level dictionary contains a single UE's all kinds of data.
        """
        self.decrypt_suci = decrypt_suci
        self.private_key: bytes = private_key
        self.secret_key: bytes = secret_key
        self.use_op = use_op
        self.OP: bytes = op
        self.OPC: bytes = opc
        self.file_location = file_location
        self.queue = _queue
        self.TIME_OUT_FILTER_PCAP = 300
        self.ue_dict = {}
        self.amf_ip_list = []
        self.buffer = None
        self.capture = None
        self.filtered_file_name = None
        self.tshark_path = tshark_path
        self.new_bearer_id = new_bearer_id

    def call_milenage(self, sk, op: bytes, opc: bytes, rand, autn, sqn_xor_ak, amf, retrieved_mac):
        if opc:
            mil = Milenage(b'00')
            mil.set_opc(opc)
        elif op:
            mil = Milenage(op)
        else:
            return None, None, None

        res, ck, ik, ak = mil.f2345(sk, rand)
        sqn = (int.from_bytes(ak, byteorder='big') ^
               int.from_bytes(sqn_xor_ak, byteorder="big")).to_bytes(6, byteorder='big')
        computed_mac = mil.f1(sk, rand, sqn, amf)
        if computed_mac == retrieved_mac:
            return res, ck, ik
        else:
            logger.warning("warning: mac failure! one authentication request message skipped!\n")
            return None, None, None

    def get_tshark_path(self, tshark_path=None):
        """
        Finds the path of the tshark executable. If the user has provided a path
        it will be used. Otherwise default locations will be searched.
        Cross-platform compatible for Windows and Linux.
        """
        # If user specified path, check it first
        if self.tshark_path:
            if os.path.exists(self.tshark_path):
                return self.tshark_path
        
        # Try to find tshark in PATH
        tshark_in_path = shutil.which('tshark')
        if tshark_in_path:
            return tshark_in_path
        
        # Platform-specific default locations
        possible_paths = []
        
        if platform.system() == 'Windows':
            # Windows default locations
            for env in ('ProgramFiles(x86)', 'ProgramFiles'):
                program_files = os.getenv(env)
                if program_files is not None:
                    possible_paths.append(
                        os.path.join(program_files, 'Wireshark', 'tshark.exe')
                    )
            possible_paths.append(r'C:\Program Files\Wireshark\tshark.exe')
        else:
            # Linux/Unix default locations
            possible_paths.extend([
                '/usr/bin/tshark',
                '/usr/local/bin/tshark',
                '/usr/sbin/tshark',
            ])
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None

    def process_reg_request(self, packet, gnb_ip, amf_ip):
        logger.warning("start processing reg request.")
        ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
        if not (ran_ue_ngap_id in self.ue_dict):
            self.ue_dict[ran_ue_ngap_id] = {}

        if not gnb_ip in self.ue_dict[ran_ue_ngap_id]:
            self.ue_dict[ran_ue_ngap_id][gnb_ip] = {}

        self.ue_dict[ran_ue_ngap_id][gnb_ip]['amf_ip'] = amf_ip
        if not hasattr(packet.ngap, 'nas_5gs_mm_type_id'):
            logger.warning(
                f'error: mandatory IE type of ID missing in registrationRequest or identity response.'
                f'packet: IP identification: {packet.ip.id.raw_value},'
                f'src IP:{packet.ip.src} skip this packet!\n')
            return False

        if packet.ngap.nas_5gs_mm_type_id == '1':
            if hasattr(packet.ngap, 'nas_pdu'):
                try:
                    nas_pdu = packet.ngap.nas_pdu.raw_value
                    if nas_pdu.startswith('7e0041'):
                        id_length = int(nas_pdu[8:12], 16)
                        suci: str = nas_pdu[12:12 + id_length * 2]
                    elif nas_pdu.startswith('7e01') and nas_pdu[14:20] == '7e005c':
                        id_length = int(nas_pdu[20:24], 16)
                        suci: str = nas_pdu[24:24 + id_length * 2]
                    bcd_supi: str = ''
                except Exception as e:
                    logger.error("failed to get SUCI content, operation aborted.\n")
                    logger.error(f"the error info is : {str(e)}\n")
                    return False

                if suci[0] == '0':
                    if suci[13] == '0':
                        bcd_supi = suci[2:8] + suci[16:]
                    elif suci[13] == '1':
                        try:
                            if not self.private_key:
                                raise Exception('no private_key found for SUCI deciphering.')
                            imsi_prefix: str = suci[2:8]
                            routing_indicator = suci[8:12]
                            home_network_key_id = suci[14:16]
                            scheme_output = suci[16:106]
                            public_key_ue_bytes = bytes.fromhex(suci[16:80])
                            encrypted_msin: bytes = bytes.fromhex(suci[80:90])
                            mac_tag_from_message = suci[90:]
                            backend = default_backend()
                            private_key_amf = x25519.X25519PrivateKey.from_private_bytes(self.private_key)
                            public_key_ue = x25519.X25519PublicKey.from_public_bytes(public_key_ue_bytes)
                            shared_secret_key = private_key_amf.exchange(public_key_ue)
                            xkdf = X963KDF(
                                algorithm=hashes.SHA256(),
                                length=64,
                                sharedinfo=public_key_ue_bytes,
                                backend=backend
                            )
                            xkdf_output: bytes = xkdf.derive(shared_secret_key)
                            suci_enc_key: bytes = xkdf_output[0:16]
                            suci_icb: bytes = xkdf_output[16:32]
                            suci_mac_key: bytes = xkdf_output[32:]
                            self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_enc_key'] = suci_enc_key
                            self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_icb'] = suci_icb
                            self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_mac_key'] = suci_mac_key
                            computed_mac_tag: str = HMAC.new(suci_mac_key, encrypted_msin, SHA256).hexdigest()[0:16]
                            if computed_mac_tag == mac_tag_from_message:
                                crypto = AES.new(suci_enc_key, mode=AES.MODE_CTR, nonce=suci_icb[0:8],
                                                 initial_value=suci_icb[8:16])
                                plain_msin: bytes = crypto.decrypt(encrypted_msin)
                                bcd_supi = imsi_prefix + plain_msin.hex()
                                decrypted_suci: str = suci[0:2] + imsi_prefix + routing_indicator + '00' + \
                                                      home_network_key_id + plain_msin.hex()
                                decrypted_suci = decrypted_suci + (106 - len(decrypted_suci)) * 'f'
                                decrypted_suci_bytes = bytes.fromhex(decrypted_suci)
                                self.buffer = self.buffer.replace(bytes.fromhex(suci), decrypted_suci_bytes)
                            else:
                                raise Exception('found mac tag mismatched.')
                        except Exception as e:
                            logger.error("failed to decrypt SUCI based on profileA, operation aborted.\n")
                            logger.error(f"the error info is : {str(e)}\n")
                            return False
                    elif suci[13] == '2':
                        try:
                            if not self.private_key:
                                raise Exception('no private_key found for SUCI deciphering.')
                            imsi_prefix: str = suci[2:8]
                            routing_indicator = suci[8:12]
                            home_network_key_id = suci[14:16]
                            scheme_output = suci[16:108]
                            public_key_ue_bytes = bytes.fromhex(suci[16:82])
                            encrypted_msin: bytes = bytes.fromhex(suci[82:92])
                            mac_tag_from_message = suci[92:]
                            backend = default_backend()
                            private_key_amf_int = int(self.private_key.hex(), base=16)
                            private_key_amf = ec.derive_private_key(
                                private_key_amf_int, ec.SECP256R1(), backend)
                            public_key_amf = private_key_amf.public_key()
                            public_key_ue = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                                                                                          public_key_ue_bytes)
                            shared_key = private_key_amf.exchange(ec.ECDH(), public_key_ue)
                            xkdf = X963KDF(
                                algorithm=hashes.SHA256(),
                                length=64,
                                sharedinfo=public_key_ue_bytes,
                                backend=backend
                            )
                            xkdf_output: bytes = xkdf.derive(shared_key)
                            suci_enc_key: bytes = xkdf_output[0:16]
                            suci_icb: bytes = xkdf_output[16:32]
                            suci_mac_key: bytes = xkdf_output[32:]
                            computed_mac_tag: str = HMAC.new(suci_mac_key, encrypted_msin, SHA256).hexdigest()[0:16]
                            if computed_mac_tag == mac_tag_from_message:
                                self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_enc_key'] = suci_enc_key
                                self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_icb'] = suci_icb
                                self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_mac_key'] = suci_mac_key
                                crypto = AES.new(suci_enc_key, mode=AES.MODE_CTR, nonce=suci_icb[0:8],
                                                 initial_value=suci_icb[8:16])
                                plain_msin: bytes = crypto.decrypt(encrypted_msin)
                                bcd_supi = imsi_prefix + plain_msin.hex()
                                decrypted_suci: str = suci[0:2] + imsi_prefix + routing_indicator + '00' + \
                                                      home_network_key_id + plain_msin.hex()
                                decrypted_suci = decrypted_suci + (108 - len(decrypted_suci)) * 'f'
                                decrypted_suci_bytes = bytes.fromhex(decrypted_suci)
                                self.buffer = self.buffer.replace(bytes.fromhex(suci), decrypted_suci_bytes)
                            else:
                                raise Exception('found mac tag mismatched.')
                        except Exception as e:
                            logger.error("failed to decrypt SUCI, operation aborted.\n")
                            logger.error(f"the error info is :{str(e)}\n")
                            return False
                elif suci[0] == '1':
                    pass

                if bcd_supi:
                    supi = bcd_supi[1] + bcd_supi[0] + bcd_supi[3] + bcd_supi[5] + bcd_supi[4] + \
                           bcd_supi[2] + bcd_supi[7] + bcd_supi[6] + bcd_supi[9] + bcd_supi[8] + \
                           bcd_supi[11] + bcd_supi[10] + bcd_supi[13] + bcd_supi[12] + \
                           bcd_supi[15] + bcd_supi[14]
                    supi = supi.replace('f', '')
                    self.ue_dict[ran_ue_ngap_id][gnb_ip]['supi'] = supi

            if hasattr(packet.ngap, 'e212_mcc') and hasattr(packet.ngap, 'e212_mnc'):
                try:
                    mcc = '0' * (3 - len(packet.ngap.e212_mcc.get_default_value())) + \
                          packet.ngap.e212_mcc.get_default_value()
                    mnc = '0' * (3 - len(packet.ngap.e212_mnc.get_default_value())) + \
                          packet.ngap.e212_mnc.get_default_value()
                    self.ue_dict[ran_ue_ngap_id][gnb_ip]['mcc'] = mcc
                    self.ue_dict[ran_ue_ngap_id][gnb_ip]['mnc'] = mnc
                    self.ue_dict[ran_ue_ngap_id][gnb_ip]['snn'] = '5G:mnc' + mnc + '.mcc' + mcc + '.3gppnetwork.org'
                except Exception as e:
                    logger.warning(f'error: encountered error with mcc/mnc of '
                                   f'packet: IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src} skip handling mcc/mnc!\n')
                    return False
        elif packet.ngap.nas_5gs_mm_type_id == '2':
            pass
        elif packet.ngap.nas_5gs_mm_type_id == '3':
            pass
        elif packet.ngap.nas_5gs_mm_type_id == '4':
            pass
        elif packet.ngap.nas_5gs_mm_type_id == '5':
            pass
        else:
            return False
        return True

    def process_auth_request(self, packet, gnb_ip):
        ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
        try:
            abba = bytes.fromhex(packet.ngap.nas_5gs_mm_abba_contents.raw_value)
            rand = bytes.fromhex(packet.ngap.gsm_a_dtap_rand.raw_value)
            autn = bytes.fromhex(packet.ngap.gsm_a_dtap_autn.raw_value)
            sqn_xor_ak = bytes.fromhex(packet.ngap.gsm_a_dtap_autn_sqn_xor_ak.raw_value)
            amf = bytes.fromhex(packet.ngap.gsm_a_dtap_autn_amf.raw_value)
            mac = bytes.fromhex(packet.ngap.gsm_a_dtap_autn_mac.raw_value)
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['abba'] = abba
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['rand'] = rand
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['autn'] = autn
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['sqn_xor_ak'] = sqn_xor_ak
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['amf'] = amf
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['mac'] = mac

            res, ck, ik = self.call_milenage(self.secret_key, self.OP, self.OPC, rand, autn, sqn_xor_ak, amf, mac)
            if res is None:
                logger.warning(
                    f'error generating res/ck/ik, skip packet : IP identification: {packet.ip.id.raw_value},'
                    f'src IP:{packet.ip.src} \n')
                return False
            logger.info('compute CK/IK from auth_request message successfully!\n')

            snn: bytes = self.ue_dict[ran_ue_ngap_id][gnb_ip]['snn'].encode('ascii')
            supi: bytes = self.ue_dict[ran_ue_ngap_id][gnb_ip]['supi'].encode('ascii')
            if not snn or not supi:
                logger.warning(
                    f'error getting SNN or SUPI for this UE, skip packet : IP identification: {packet.ip.id.raw_value},'
                    f'src IP:{packet.ip.src}\n ')
                return False

            input_string = b'\x6a' + snn + len(snn).to_bytes(2, byteorder='big') \
                           + sqn_xor_ak + len(sqn_xor_ak).to_bytes(2, byteorder='big')
            input_key = ck + ik
            kausf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['kausf'] = kausf

            input_string = b'\x6c' + snn + len(snn).to_bytes(2, byteorder='big')
            input_key = kausf
            kseaf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['kseaf'] = kseaf

            abba = b'\x00\x00'
            input_string = b'\x6d' + supi + len(supi).to_bytes(2, byteorder='big') + abba + b'\x00\x02'
            input_key = kseaf
            kamf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['kamf'] = kamf
            logger.info('compute Kamf based on supi and CK/IK successfully!\n')
            return True

        except Exception as e:
            logger.warning(f'error: error handling authentication vector '
                           f'from packet : IP identification: {packet.ip.id.raw_value},'
                           f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            return False

    def process_securitymode_command(self, packet, gnb_ip):
        try:
            ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
            algorithm_id = packet.ngap.nas_pdu.raw_value[20]
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id'] = algorithm_id
            if algorithm_id == '0':
                return False
            if (ran_ue_ngap_id not in self.ue_dict) or (gnb_ip not in
                                                        self.ue_dict[ran_ue_ngap_id]) or (
                    'kamf' not in self.ue_dict[ran_ue_ngap_id][gnb_ip]):
                return False
            algorithm_type_dist = b'\x01'
            input_string = b'\x69' + algorithm_type_dist + b'\x00\x01' + \
                           bytes.fromhex('0' + algorithm_id) + b'\x00\x01'
            input_key = self.ue_dict[ran_ue_ngap_id][gnb_ip]['kamf']
            cipher_key = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())[16:]
            self.ue_dict[ran_ue_ngap_id][gnb_ip]['cipher_key'] = cipher_key
            logger.info("compute alg_enc key successfully!\n")
            return True
        except Exception as e:
            logger.warning(f'error: error handling security_mode_command message,'
                           f'skip packet : IP identification: {packet.ip.id.raw_value},'
                           f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            return False

    def decipher_nas(self, packet, gnb_ip, direction):
        ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
        if (ran_ue_ngap_id not in self.ue_dict) or (gnb_ip not in
                                                    self.ue_dict[ran_ue_ngap_id]) or (
                'cipher_key' not in self.ue_dict[ran_ue_ngap_id][gnb_ip]):
            logger.warning(f'error: no cipher key available for this UE found,'
                           f'skip packet : IP identification: {packet.ip.id.raw_value},'
                           f'src IP:{packet.ip.src} \n')
            return False
        try:
            msg_nas_count = int(packet.ngap.nas_5gs_seq_no.raw_value, base=16)
            if direction == 1:
                if 'local_downlink_nas_count' in self.ue_dict[ran_ue_ngap_id][gnb_ip]:
                    local_nas_count = self.ue_dict[ran_ue_ngap_id][gnb_ip]['local_downlink_nas_count']
                else:
                    local_nas_count = 0
            else:
                if 'local_uplink_nas_count' in self.ue_dict[ran_ue_ngap_id][gnb_ip]:
                    local_nas_count = self.ue_dict[ran_ue_ngap_id][gnb_ip]['local_uplink_nas_count']
                else:
                    local_nas_count = 0

            count_for_ciphering = None
            if msg_nas_count % 256 >= local_nas_count % 256:
                count_for_ciphering = local_nas_count = (local_nas_count // 256) * 256 + msg_nas_count % 256
            elif msg_nas_count % 256 < local_nas_count % 256:
                if local_nas_count % 256 > 250 and msg_nas_count % 256 < 5:
                    count_for_ciphering = local_nas_count = (local_nas_count // 256 + 1) * 256 + msg_nas_count % 256
                else:
                    count_for_ciphering = local_nas_count // 256 + msg_nas_count % 256

            if direction == 1:
                self.ue_dict[ran_ue_ngap_id][gnb_ip]['local_downlink_nas_count'] = local_nas_count
            elif direction == 0:
                self.ue_dict[ran_ue_ngap_id][gnb_ip]['local_uplink_nas_count'] = local_nas_count

            cipher_key = self.ue_dict[ran_ue_ngap_id][gnb_ip]['cipher_key']
            if hasattr(packet.ngap, 'nas_pdu'):
                nas_pdu = bytes.fromhex(packet.ngap.nas_pdu.raw_value)
            elif hasattr(packet.ngap, 'pdusessionnas_pdu'):
                nas_pdu = bytes.fromhex(packet.ngap.pdusessionnas_pdu.raw_value)
            else:
                raise Exception('no nas_pdu found!')

            outer_header = nas_pdu[0:7]
            ciphered_payload = nas_pdu[7:]
            bearer = self.new_bearer_id
            first_byte_of_bearer_and_direction = (bearer << 3) | (direction << 2)
            plain_payload = None

            if self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id'] == '2' and count_for_ciphering is not None:
                counter_block = count_for_ciphering.to_bytes(4, byteorder='big') + \
                                first_byte_of_bearer_and_direction.to_bytes(1, byteorder='big') + \
                                b'\x00\x00\x00' + b'\x00' * 8
                crypto = AES.new(cipher_key, mode=AES.MODE_CTR, nonce=counter_block[0:8],
                                 initial_value=counter_block[8:16])
                plain_payload = crypto.decrypt(ciphered_payload)
            elif self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id'] == '1' and count_for_ciphering is not None:
                plain_payload = pysnow.snow_f8(cipher_key, count_for_ciphering, bearer,
                                               direction, ciphered_payload, len(ciphered_payload) * 8)
            elif self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id'] == '3' and count_for_ciphering is not None:
                plain_payload = pyzuc.zuc_eea3(cipher_key, count_for_ciphering, bearer,
                                               direction, len(ciphered_payload) * 8, ciphered_payload)

            if plain_payload and plain_payload.startswith(b'\x7e'):
                self.buffer = self.buffer.replace(nas_pdu, outer_header + plain_payload)
                return True
        except Exception as e:
            logger.warning(f'error: error deciphering '
                           f' packet : IP identification: {packet.ip.id.raw_value},'
                           f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')

        return False

    def filter_pcap(self):
        if self.file_location:
            file_name = self.file_location
        else:
            logger.error("critical error: the pcap file doesn't exist!\n")
            return False

        if not os.path.exists(file_name):
            logger.error("critical error: the pcap file doesn't exist!\n")
            return False

        # Support both .pcap and .pcapng formats
        file_upper = file_name.upper()
        supported_extensions = ('.PCAP', '.CAP', '.PCAPNG')
        if not any(file_upper.endswith(ext) for ext in supported_extensions):
            logger.error("the input file must be ended with .pcap, .cap, or .pcapng!\n")
            return False

        # Cross-platform path handling - preserve original extension
        base_name, original_ext = os.path.splitext(file_name)
        # Use pcapng format for output to maintain compatibility with modern Wireshark
        self.filtered_file_name = base_name + '_filtered.pcapng'

        tshark_path = self.get_tshark_path()
        if tshark_path is None:
            logger.error('fatal error: no tshark executable from wireshark found in system, make sure you have '
                         'wireshark installed, or manually specify the path of tshark in GUI\n')
            return False

        # Cross-platform command construction
        if platform.system() == 'Windows':
            parameters = [tshark_path, '-r', f'"{file_name}"', '-2', '-R', 'ngap', '-w',
                          f'"{self.filtered_file_name}"']
            parameters = ' '.join(parameters)
        else:
            # Linux/Unix - no need for quotes around paths in subprocess
            parameters = [tshark_path, '-r', file_name, '-2', '-R', 'ngap', '-w', self.filtered_file_name]

        logger.info(f'Running tshark filter command...\n')
        
        try:
            if platform.system() == 'Windows':
                tshark_process = subprocess.Popen(parameters, shell=True)
            else:
                tshark_process = subprocess.Popen(parameters)
        except Exception as e:
            logger.error(f'Failed to start tshark process: {str(e)}\n')
            return False

        wait_count = 0
        while True:
            logger.info(f'waiting for pcap filtered by ngap protocol, {wait_count} seconds passed.\n')
            if wait_count > self.TIME_OUT_FILTER_PCAP:
                logger.error('filter pcap by ngap timed out, please use a smaller pcap '
                             'instead or filter it by ngap manually before decrypting it!\n')
                tshark_process.kill()
                return False
            if tshark_process.poll() is not None:
                tshark_process.kill()
                return True
            else:
                module_time_sleep(1)
                wait_count += 1

    def main_test(self):
        if self.filter_pcap():
            logger.info("filter pcap by ngap protocol finished, now start decrypting!\n")
        else:
            logger.error('error filtering pcap by ngap protocol, operation aborted!\n')
            return False

        if not os.path.exists(self.filtered_file_name):
            logger.error(
                f'error: the file {self.filtered_file_name} seems not generated successfully, operation aborted!\n')
            return False

        with open(self.filtered_file_name, "rb") as file:
            self.buffer = file.read()

        if self.tshark_path:
            self.capture = pyshark.FileCapture(self.filtered_file_name, display_filter='nas-5gs',
                                               tshark_path=self.tshark_path)
        else:
            self.capture = pyshark.FileCapture(self.filtered_file_name, display_filter='nas-5gs')

        packet_number = 0
        for packet in self.capture:
            packet_number += 1
            if not (hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst')
                    and hasattr(packet, 'ngap') and hasattr(packet.ngap, 'ran_ue_ngap_id')
                    and (hasattr(packet.ngap, 'nas_pdu') or hasattr(packet.ngap, 'pdusessionnas_pdu'))
                    and hasattr(packet.ngap, 'procedurecode')
                    and hasattr(packet.ngap, 'nas_5gs_security_header_type')):
                logger.warning(f'error: one or more mandatory IE in packet {packet_number} is missing, skip this packet!\n')
                continue
            else:
                try:
                    ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
                except Exception as e:
                    logger.warning(
                        f'error: error handling ran_ue_ngap_id in {packet_number}, skip this packet!\n')
                    continue

            if packet.ngap.procedurecode.raw_value == '0f':
                try:
                    gnb_ip = packet.ip.src.raw_value
                    amf_ip = packet.ip.dst.raw_value
                except Exception as e:
                    logger.warning(
                        f'error: error handling source/dest IP in {packet_number}, skip this packet!\n')
                    continue
                if not hasattr(packet.ngap, 'nas_5gs_mm_message_type'):
                    logger.warning(
                        f'error: one or more mandatory IE in packet {packet_number} is missing, skip this packet!\n')
                    continue
                if amf_ip and (amf_ip not in self.amf_ip_list):
                    self.amf_ip_list.append(amf_ip)
                if packet.ngap.nas_5gs_mm_message_type.raw_value == '41':
                    self.process_reg_request(packet, gnb_ip, amf_ip)
                elif packet.ngap.nas_5gs_mm_message_type.raw_value == '4c':
                    pass

            elif packet.ngap.procedurecode.raw_value == '04' or packet.ip.src.raw_value in self.amf_ip_list:
                try:
                    gnb_ip = packet.ip.dst.raw_value
                    amf_ip = packet.ip.src.raw_value
                except Exception as e:
                    logger.warning(
                        f'error: error handling src/dst IP in {packet_number}, skip this packet!\n')
                    continue

                if not ((ran_ue_ngap_id in self.ue_dict) and (gnb_ip in self.ue_dict[ran_ue_ngap_id]) and
                        ('snn' in self.ue_dict[ran_ue_ngap_id][gnb_ip]) and (
                                'supi' in self.ue_dict[ran_ue_ngap_id][gnb_ip])):
                    logger.warning(
                        f'error: error finding matched UE record in dictionary'
                        f' for packet#{packet_number}, skip this packet!\n')
                    continue

                direction = 1
                security_header_type = packet.ngap.nas_5gs_security_header_type.raw_value
                if security_header_type == '0':
                    if hasattr(packet.ngap, 'nas_5gs_mm_message_type'):
                        if packet.ngap.nas_5gs_mm_message_type.raw_value == '56':
                            if amf_ip and (amf_ip not in self.amf_ip_list):
                                self.amf_ip_list.append(amf_ip)
                            self.process_auth_request(packet, gnb_ip)

                elif security_header_type == '1' or security_header_type == '3':
                    try:
                        if packet.ngap.nas_pdu.raw_value[18:20] == '5d':
                            if amf_ip and (amf_ip not in self.amf_ip_list):
                                self.amf_ip_list.append(amf_ip)
                            self.process_securitymode_command(packet, gnb_ip)
                    except Exception as e:
                        logger.error(
                            'failed to handle integrity enabled downlink message, probably securityModeCommand message.\n')
                        logger.error(f'the error info is :{str(e)}\n')
                        continue

                elif security_header_type == '2' or security_header_type == '4':
                    if self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id'] == '0':
                        logger.info(f'skip packet {packet_number} due to null encryption.\n')
                        continue
                    if self.decipher_nas(packet, gnb_ip, direction):
                        logger.info(f'deciphering packet {packet_number} successfully!\n')
                    else:
                        logger.error(f'error deciphering packet {packet_number}\n')
                    continue

            elif packet.ngap.procedurecode.raw_value == '2e' or packet.ip.dst.raw_value in self.amf_ip_list:
                try:
                    gnb_ip = packet.ip.src.raw_value
                    amf_ip = packet.ip.dst.raw_value
                except Exception as e:
                    logger.warning(
                        f'error: error handling src/dst IP in {packet_number}, skip this packet!\n')
                    continue

                if hasattr(packet.ngap, 'nas_5gs_mm_message_type') and \
                        packet.ngap.nas_5gs_mm_message_type.raw_value == '5c':
                    self.process_reg_request(packet, gnb_ip, amf_ip)

                if not ((ran_ue_ngap_id in self.ue_dict) and (gnb_ip in self.ue_dict[ran_ue_ngap_id]) and
                        ('snn' in self.ue_dict[ran_ue_ngap_id][gnb_ip]) and (
                                'supi' in self.ue_dict[ran_ue_ngap_id][gnb_ip])):
                    logger.warning(
                        f'error: error finding matched UE record in dictionary'
                        f' for packet#{packet_number}, skip this packet!\n')
                    continue

                direction = 0
                security_header_type = packet.ngap.nas_5gs_security_header_type.raw_value
                if security_header_type == '0' or security_header_type == '1' or security_header_type == '3':
                    if packet.ngap.nas_5gs_mm_message_type.raw_value == '57':
                        if amf_ip and (amf_ip not in self.amf_ip_list):
                            self.amf_ip_list.append(amf_ip)

                elif security_header_type == '2' or security_header_type == '4':
                    if self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id'] == '0':
                        logger.info(f'skip packet {packet_number} due to null encryption.\n')
                        continue
                    if self.decipher_nas(packet, gnb_ip, direction):
                        logger.info(f'deciphering packet {packet_number} successfully!\n')
                    else:
                        logger.error(f'error deciphering packet {packet_number}\n')
                    continue

            else:
                logger.error(
                    f'packet {packet_number} not belongs to any of initialUE/uplinktransport/dlinktransport'
                    f'skipped this packet!\n')
                continue

        try:
            with open(self.filtered_file_name, "wb") as file:
                file.write(self.buffer)
            logger.info(f'file {self.filtered_file_name} with deciphered content created!\n')
            del self.buffer, self.ue_dict, self.amf_ip_list
            return True
        except Exception as e:
            logger.error("error happened during writing decrypted content into pcap, operation aborted!\n")
            logger.debug(f"the error info is : {str(e)}")
            return False


# #################################################################
# **********************ImGui GUI Part*****************************
# #################################################################

class ImGuiApp:
    def __init__(self):
        self.queue = queue.Queue()
        self.decryption = None
        self.thread = None
        self.running = True
        
        # GUI state variables
        self.decrypt_suci = False
        self.private_key_input = ""
        self.secret_key_input = ""
        self.use_op = True  # True for OP, False for OPC
        self.op_input = ""
        self.opc_input = ""
        self.pcap_file_input = ""
        self.specify_tshark_path = False
        self.tshark_path_input = ""
        self.new_bearer_id = 0  # 0 for old spec, 1 for new spec
        
        # Log display
        self.log_messages = []
        self.max_log_lines = 1000
        
        # Initialize logging
        self.LOGFILE = "decipher" + str(datetime.now()).replace(":", "-").replace(" ", "-") + ".log"
        self.init_log(logging.INFO)
        
        # ImGui/GLFW initialization
        if not glfw.init():
            raise Exception("Could not initialize GLFW")
        
        # Create window
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
        glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
        glfw.window_hint(glfw.OPENGL_FORWARD_COMPAT, glfw.TRUE)
        
        self.window = glfw.create_window(1200, 800, "5G NAS Deciphering Tool", None, None)
        if not self.window:
            glfw.terminate()
            raise Exception("Could not create GLFW window")
        
        glfw.make_context_current(self.window)
        glfw.swap_interval(1)  # Enable vsync
        
        # Initialize ImGui
        imgui.create_context()
        self.impl = GlfwRenderer(self.window)
        
        # Set default tshark path for Windows
        if platform.system() == 'Windows':
            self.tshark_path_input = r'C:\Program Files\Wireshark\tshark.exe'

    def init_log(self, log_level=logging.INFO):
        try:
            logger.propagate = False
            logger.setLevel(log_level)

            ch = logging.handlers.RotatingFileHandler(self.LOGFILE,
                                                      mode='a', maxBytes=10000000, backupCount=5)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            ch.setLevel(log_level)
            logger.addHandler(ch)

            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            if self.queue:
                queue_handler = QueueHandler(self.queue)
                queue_handler.setFormatter(formatter)
                queue_handler.setLevel(log_level)
                logger.addHandler(queue_handler)

            logger.debug("log file is generated by file name:" + self.LOGFILE)
            return logger
        except Exception as e:
            print("initialize a new log file and writing into it failure,"
                  " make sure your current account has write privilege to current directory!\n")
            logger.error("error: " + str(e) + '\n')
            return logger

    def process_queue(self):
        """Process messages from the queue and add to log display"""
        while not self.queue.empty():
            try:
                msg = self.queue.get_nowait()
                if msg:
                    if isinstance(msg, str):
                        self.log_messages.append(msg)
                    elif isinstance(msg, logging.LogRecord):
                        self.log_messages.append(msg.getMessage())
                    
                    # Limit log buffer size
                    if len(self.log_messages) > self.max_log_lines:
                        self.log_messages = self.log_messages[-self.max_log_lines:]
            except queue.Empty:
                break

    def file_dialog(self, file_types="pcap"):
        """Simple file dialog using system commands"""
        if platform.system() == 'Windows':
            try:
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk()
                root.withdraw()
                if file_types == "pcap":
                    filename = filedialog.askopenfilename(
                        title="Select PCAP file",
                        filetypes=[
                            ("PCAP files", "*.pcap *.pcapng *.cap"),
                            ("All files", "*.*")
                        ]
                    )
                else:
                    filename = filedialog.askopenfilename()
                root.destroy()
                return filename
            except:
                logger.warning("Could not open file dialog. Please type path manually.")
                return ""
        else:
            # For Linux, we'll use zenity if available, otherwise manual input
            try:
                if file_types == "pcap":
                    result = subprocess.run(
                        ['zenity', '--file-selection', '--title=Select PCAP file',
                         '--file-filter=PCAP files (*.pcap, *.pcapng, *.cap) | *.pcap *.pcapng *.cap',
                         '--file-filter=All files | *'],
                        capture_output=True, text=True, timeout=60
                    )
                else:
                    result = subprocess.run(['zenity', '--file-selection'], 
                                          capture_output=True, text=True, timeout=60)
                return result.stdout.strip()
            except:
                logger.warning("zenity not found. Please type path manually or install zenity.")
                return ""

    def start_decryption(self):
        """Start decryption in a separate thread"""
        try:
            # Validate and convert inputs
            decrypt_suci = 1 if self.decrypt_suci else 0
            
            private_key = None
            if decrypt_suci:
                try:
                    private_key = bytes.fromhex(self.private_key_input.strip())
                    if len(private_key) != 32:
                        raise ValueError("Private key must be 32 bytes (64 hex characters)")
                except:
                    logger.error("Invalid private key format!\n")
                    return
            
            try:
                secret_key = bytes.fromhex(self.secret_key_input.strip())
                if len(secret_key) != 16:
                    raise ValueError("Secret key must be 16 bytes (32 hex characters)")
            except:
                logger.error("Invalid secret key format!\n")
                return
            
            op = None
            opc = None
            if self.use_op:
                try:
                    op = bytes.fromhex(self.op_input.strip())
                    if len(op) != 16:
                        raise ValueError("OP must be 16 bytes (32 hex characters)")
                except:
                    logger.error("Invalid OP format!\n")
                    return
                use_op = 1
            else:
                try:
                    opc = bytes.fromhex(self.opc_input.strip())
                    if len(opc) != 16:
                        raise ValueError("OPC must be 16 bytes (32 hex characters)")
                except:
                    logger.error("Invalid OPC format!\n")
                    return
                use_op = 2
            
            file_location = self.pcap_file_input.strip()
            if not file_location:
                logger.error("Please specify PCAP file location!\n")
                return
            
            tshark_path = None
            if self.specify_tshark_path:
                tshark_path = self.tshark_path_input.strip()
            
            # Create decryption object
            self.decryption = Decryption(decrypt_suci, private_key, secret_key, use_op, op,
                                        opc, file_location, self.queue, tshark_path, self.new_bearer_id)
            
            # Start decryption thread
            self.thread = threading.Thread(target=self.decryption.main_test, daemon=True)
            self.thread.start()
            logger.info("Decryption started...\n")
            
        except Exception as e:
            logger.error(f"Error starting decryption: {str(e)}\n")

    def render_gui(self):
        """Render the ImGui interface"""
        imgui.new_frame()
        
        # Main window
        imgui.set_next_window_size(1180, 780)
        imgui.set_next_window_position(10, 10)
        imgui.begin("5G NAS Deciphering Tool", flags=imgui.WINDOW_NO_RESIZE | imgui.WINDOW_NO_MOVE | imgui.WINDOW_NO_COLLAPSE)
        
        # SUCI Decryption Section
        imgui.text_colored("SUCI Decryption Settings", 0.3, 0.8, 1.0, 1.0)
        imgui.separator()
        
        _, self.decrypt_suci = imgui.checkbox("Decrypt SUCI", self.decrypt_suci)
        imgui.same_line()
        imgui.text_colored("(Input hex value only, 32 bytes / 64 hex chars)", 0.5, 0.5, 1.0, 1.0)
        
        if self.decrypt_suci:
            imgui.text("Private Key (Network):")
            imgui.same_line(200)
            imgui.push_item_width(600)
            _, self.private_key_input = imgui.input_text("##private_key", self.private_key_input, 256)
            imgui.pop_item_width()
        
        imgui.spacing()
        imgui.spacing()
        
        # Authentication Parameters Section
        imgui.text_colored("Authentication Parameters (5G AKA)", 0.3, 0.8, 1.0, 1.0)
        imgui.separator()
        imgui.text_colored("(Input hex value only, 16 bytes / 32 hex chars)", 0.5, 0.5, 1.0, 1.0)
        
        imgui.text("Secret Key (UE):")
        imgui.same_line(200)
        imgui.push_item_width(600)
        _, self.secret_key_input = imgui.input_text("##secret_key", self.secret_key_input, 256)
        imgui.pop_item_width()
        
        imgui.spacing()
        
        # OP/OPC Radio buttons
        imgui.text("Key Type:")
        imgui.same_line(200)
        if imgui.radio_button("Use OP", self.use_op):
            self.use_op = True
        imgui.same_line()
        if imgui.radio_button("Use OPC", not self.use_op):
            self.use_op = False
        
        if self.use_op:
            imgui.text("OP Value:")
            imgui.same_line(200)
            imgui.push_item_width(600)
            _, self.op_input = imgui.input_text("##op", self.op_input, 256)
            imgui.pop_item_width()
        else:
            imgui.text("OPC Value:")
            imgui.same_line(200)
            imgui.push_item_width(600)
            _, self.opc_input = imgui.input_text("##opc", self.opc_input, 256)
            imgui.pop_item_width()
        
        imgui.spacing()
        imgui.spacing()
        
        # Bearer ID Section
        imgui.text_colored("Bearer ID Specification", 0.3, 0.8, 1.0, 1.0)
        imgui.separator()
        
        imgui.text("Bearer ID:")
        imgui.same_line(200)
        if imgui.radio_button("Old Spec 33.501 (Bearer=0)", self.new_bearer_id == 0):
            self.new_bearer_id = 0
        imgui.same_line()
        if imgui.radio_button("New Spec (Bearer=1)", self.new_bearer_id == 1):
            self.new_bearer_id = 1
        
        imgui.spacing()
        imgui.spacing()
        
        # File Selection Section
        imgui.text_colored("PCAP File Selection", 0.3, 0.8, 1.0, 1.0)
        imgui.separator()
        imgui.text_colored("(Supports .pcap, .pcapng, and .cap formats)", 0.5, 0.5, 1.0, 1.0)
        
        imgui.text("PCAP File:")
        imgui.same_line(200)
        imgui.push_item_width(500)
        _, self.pcap_file_input = imgui.input_text("##pcap", self.pcap_file_input, 512)
        imgui.pop_item_width()
        imgui.same_line()
        if imgui.button("Browse##pcap"):
            filename = self.file_dialog("pcap")
            if filename:
                self.pcap_file_input = filename
        
        imgui.spacing()
        
        # TShark Path Section
        _, self.specify_tshark_path = imgui.checkbox("Specify TShark Path (uncheck for auto-detect)", 
                                                     self.specify_tshark_path)
        
        if self.specify_tshark_path:
            imgui.text("TShark Path:")
            imgui.same_line(200)
            imgui.push_item_width(500)
            _, self.tshark_path_input = imgui.input_text("##tshark", self.tshark_path_input, 512)
            imgui.pop_item_width()
            imgui.same_line()
            if imgui.button("Browse##tshark"):
                filename = self.file_dialog()
                if filename:
                    self.tshark_path_input = filename
        
        imgui.spacing()
        imgui.spacing()
        
        # Action Buttons
        if imgui.button("Start Decryption", width=150, height=30):
            self.start_decryption()
        
        imgui.same_line()
        if imgui.button("Exit", width=150, height=30):
            self.running = False
        
        imgui.spacing()
        imgui.spacing()
        
        # Log Display Section
        imgui.text_colored("Real-time Log", 0.3, 0.8, 1.0, 1.0)
        imgui.separator()
        
        imgui.begin_child("log_region", 0, 250, border=True)
        for msg in self.log_messages:
            imgui.text(msg)
        # Auto-scroll to bottom
        if imgui.get_scroll_y() >= imgui.get_scroll_max_y():
            imgui.set_scroll_here_y(1.0)
        imgui.end_child()
        
        imgui.spacing()
        imgui.text_colored(f"Platform: {platform.system()} | Log file: {self.LOGFILE}", 0.5, 0.5, 0.5, 1.0)
        
        imgui.end()
        
        imgui.render()
        self.impl.render(imgui.get_draw_data())

    def run(self):
        """Main application loop"""
        while not glfw.window_should_close(self.window) and self.running:
            glfw.poll_events()
            self.impl.process_inputs()
            self.process_queue()
            
            self.render_gui()
            
            glfw.swap_buffers(self.window)
        
        self.shutdown()

    def shutdown(self):
        """Clean up resources"""
        self.impl.shutdown()
        glfw.terminate()
        logger.info("Application closed.\n")
        sys.exit(0)


def main():
    """Main entry point"""
    try:
        app = ImGuiApp()
        app.run()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
