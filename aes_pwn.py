import chipwhisperer.capture.ChipWhispererCapture as cwc
from PySide.QtCore import *
from PySide.QtGui import *
import sys

import time
from Crypto.Cipher import AES
import csv
import binascii

import os

sboxInv = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]


def hexStrToByteArray(hexStr):
    ba = bytearray()
    for s in hexStr.split():
        ba.append(int(s, 16))
    return ba


def pe():
    QCoreApplication.processEvents()


def send_encrypting_request(cap, ser, plaintext, key, ser_output_length, desired_sbox_byte = 0, debug = True):
    """
    Sends command to ser to encrypt the plaintext with key and reads ser_output_length bytes on ser output
    :param debug:
    :param desired_sbox_byte:
    :param cap:
    :param ser:
    :param plaintext:
    :param key:
    :param ser_output_length:
    :return:
    """

    # Flush clears input buffer
    ser.flush()
    # Sending the key to the XMEGA through the serial
    ser.write("k" + binascii.hexlify(key) + "\n")
    # Always wait a while after r/w the serial
    time.sleep(0.1)

    # Sending desired byte of the output of the first sbox
    ser.write("s" + str(desired_sbox_byte) + "\n")
    time.sleep(0.1)

    # Put the scope on and process event
    cap.scope.arm()
    pe()
    # Sending the plain to the XMEGA through the serial
    ser.write("p" + binascii.hexlify(plaintext) + "\n")

    # START Measurement Phase
    if cap.scope.capture(update=True, NumberPoints=None, waitingCallback=pe):
        if debug is True:
            print "Timeout"

    # Read response : 33 + extra. Specifying length avoids waiting for
    # timeout to occur.
    respdata = ser.read(33 + ser_output_length)

    return respdata


def payload(file, ser, app, cap, myaes_key, desired_byte, debug=True):
    # Create an aray that will contain the AES input
    myaes_input = bytearray(os.urandom(16))

    # Create the null message
    # for i in range(0, 16):
    # myaes_input [i] = 0

    # Create an object cipher for AES in ECB mode, and parameterized with myaes_key
    cipher = AES.new(str(myaes_key), AES.MODE_ECB)

    # Flush clears input buffer
    ser.flush()
    # Sending the key to the XMEGA through the serial
    ser.write("k" + binascii.hexlify(myaes_key) + "\n")
    # Always wait a while after r/w the serial
    time.sleep(0.1)

    # Sending desired byte of the output of the first sbox
    ser.write("s" + str(desired_byte) + "\n")
    time.sleep(0.1)

    # Put the scope on and process event
    cap.scope.arm()
    pe()
    # Sending the plain to the XMEGA through the serial
    ser.write("p" + binascii.hexlify(myaes_input) + "\n")

    # START Measurement Phase
    if cap.scope.capture(update=True, NumberPoints=None, waitingCallback=pe):
        if debug is True:
            print "Timeout"
    # else:
    # if debug is True:
    # print "Capture OK"
    # END Measurement Phase

    # Get the answer
    myaes_output = bytearray(cipher.encrypt(str(myaes_input)))

    # if debug is True:
    # Print the key and the plain
    # if debug is True:
    # print "k" + binascii.hexlify(myaes_key)
    # if debug is True:
    # print "p" + binascii.hexlify(myaes_input)

    # Read response, which is 33 bytes long. Specifying length avoids waiting for
    # timeout to occur.
    respdata = ser.read(33 + 6)
    # if debug is True:
    # print "On ATXMega, AES(s,m)= " + respdata
    # Compare with the onsite computation
    # if debug is True:
    # print "Expected Output     = o" + binascii.hexlify(myaes_output)

    error = 0
    if respdata.split('+')[0][1:].lower() != binascii.hexlify(myaes_output).lower():
        if debug is True:
            print "[ERROR] results did not match)"
        error += 1

    if debug is True:
        print "On ATXMega, AES(s,m)= " + respdata.split('+')[0].lower()
    if debug is True:
        print "Expected Output     = o" + binascii.hexlify(myaes_output)
    if debug is True:
        print "Desired byte after sbox : " + respdata.split('+')[2] + " (index " + respdata.split('+')[
        1] + ")"

    # Scope data is contained in scope.datapoints
    # if debug is True:
    # print cap.scope.datapoints

    # Write te measurements in the CSV file
    file.writerow(myaes_input)
    file.writerow(cap.scope.datapoints)
    return error


def setup():
    # Make the application and get the main module
    app = cwc.makeApplication()
    cap = cwc.ChipWhispererCapture()

    # Setting the OpenADC Interface
    cmds = [['Generic Settings', 'Scope Module', 'ChipWhisperer/OpenADC'],
            ['Generic Settings', 'Target Module', 'Simple Serial'],
            ['Generic Settings', 'Trace Format', 'ChipWhisperer/Native'],
            ['OpenADC Interface', 'connection', 'ChipWhisperer Lite'],
            ['Target Connection', 'connection', 'ChipWhisperer-Lite']
            ]
    for cmd in cmds: cap.setParameter(cmd)

    # Connect to scope
    cap.doConDisScope(True)
    pe()

    # Setting the Scope
    cmds = [['CW Extra', 'CW Extra Settings', 'Trigger Pins', 'Target IO4 (Trigger Line)', True],
            ['CW Extra', 'CW Extra Settings', 'Target IOn Pins', 'Target IO1', 'Serial RXD'],
            ['CW Extra', 'CW Extra Settings', 'Target IOn Pins', 'Target IO2', 'Serial TXD'],
            ['OpenADC', 'Clock Setup', 'CLKGEN Settings', 'Desired Frequency', 7370000.0],
            ['CW Extra', 'CW Extra Settings', 'Target HS IO-Out', 'CLKGEN'],
            ['OpenADC', 'Clock Setup', 'ADC Clock', 'Source', 'CLKGEN x4 via DCM'],
            ['OpenADC', 'Trigger Setup', 'Total Samples', 100],
            ['OpenADC', 'Trigger Setup', 'Offset', 1500],
            ['OpenADC', 'Gain Setting', 'Setting', 45],
            ['OpenADC', 'Trigger Setup', 'Mode', 'rising edge'],
            # Final step: make DCMs relock in case they are lost
            ['OpenADC', 'Clock Setup', 'ADC Clock', 'Reset ADC DCM', None],
            ]
    for cmd in cmds: cap.setParameter(cmd)

    # Connect to serial port to XMEGA
    ser = cap.target.driver.ser
    ser.con()

    # Create a pointer on a csv file
    file = csv.writer(open("aes_traces.csv", "ab"))

    return app, cap, ser, file


def get_desired_byte(count, desired_byte, debug=True):
    if debug is True:
        print("Launching with " + str(count) + " samples and retrieving byte number " + str(
        desired_byte) + " of desired state.")

    # Setup Lab
    app, cap, ser, file = setup()

    # Create an AES key To recover By SCA
    myaes_key = hexStrToByteArray("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")

    errors = 0
    for i in range(count):
        errors += payload(file, ser, app, cap, myaes_key, desired_byte)

    if errors == 0:
        if debug is True:
            print "All calculations were successfull"

    # The following should delete the CWC Main window and disconnect
    # where appropriate
    cap.deleteLater()
    sys.exit(app.exec_())


def dpa_attack(debug = True):
    """
    Launch a DPA attack assuming we have internal state information leakage on selected byte
    :return:
    """
    box_size = 16
    sbox = ""
    extra_output_length = 6

    # Setup Lab
    app, cap, ser, file = setup()

    # Create an AES key To recover By SCA
    secret_key = "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"
    myaes_key = hexStrToByteArray(secret_key)

    if debug:
        print "Generated secret keys ..."

    if debug:
        print "Generated random known plaintext ..."
        print "Transferring full AES encryption command to XMEGA ChipWhisperer ..."

    recovered_key = [None] * box_size
    tmp_key = [None] * box_size
    for i in range(box_size):
        # Create random plaintext
        plaintext = bytearray(os.urandom(16))
        output = send_encrypting_request(cap, ser, plaintext, myaes_key, extra_output_length, i, True)
        # sbox += output.split('+')[2]
        sbox = output.split('+')[2]
        state = subBytesInv(sbox)
        addRoundKey(state, plaintext[i:i+1])
        tmp_key[i] = state[0]

    key = key_hex_to_str(tmp_key)

    if debug:
        print "Encryption completed."
        #print "[SECRET] Retrieved internal secret sbox state : " + sbox

    # Retrieve Key from Sbox and plaintext
    # state = subBytesInv(sbox)
    if debug:
        #p_state = str(state)
        #print "[SECRET] Retrieved internal secret addRoundKey output : " + p_state
        print "Recovering secret key ..."
    # addRoundKey(state, plaintext)

    # key = key_hex_to_str(state)

    if debug and key.lower() == secret_key.lower():
        print "Attack Successful !"
        print ""
        print "[SECRET] Recovered secret key " + key

    #print key



    # The following should delete the CWC Main window and disconnect
    # where appropriate
    cap.deleteLater()
    sys.exit(app.exec_())


def key_hex_to_str(state):
    key = ""
    for i in range(len(state)):
        k = hex(state[i])[2:]
        if k == "0":
            k = "00"
        key += k + " "
    return key[:-1]


def subBytesInv(state):
    hex_state = [None] * (len(state)/2)
    for i in range(len(state)/2):
        # Convert str to hex per byte
        hex_state[i] = sboxInv[int(state[2*i:2*i+2], 16)]
    return hex_state


# XOR each byte of the roundKey with the state table
def addRoundKey(state, roundKey):
    for i in range(len(state)):
        state[i] = state[i] ^ roundKey[i]


# launch(1, 2)

dpa_attack()
