from struct import unpack
from io import BytesIO
import math
import binascii
from schema import PidTagSchema
import json

# [MS-OXOAB]: Offline Address Book (OAB) File Format and Schema
# https://interoperability.blob.core.windows.net/files/MS-OXOAB/%5bMS-OXOAB%5d.pdf

def hexify(PropID):
    return "{0:#0{1}x}".format(PropID, 10).upper()[2:]

def lookup(ulPropID):
    if hexify(ulPropID) in PidTagSchema:
        (PropertyName, PropertyType) = PidTagSchema[hexify(ulPropID)]
        return PropertyName
    else:
        return hex(ulPropID)

def gettype(PropID):
    # The property type is infered from the last 2 bytes of PropID
    typebytes = PropID[-4:]
    if typebytes == "0003":
        return "PtypInteger32"
    if typebytes == "000B":
        return "PtypBoolean"
    if typebytes == "000D":
        return "PtypObject"
    if typebytes == "001E":
        return "PtypString8"
    if typebytes == "001F":
        return "PtypString"
    if typebytes == "0102":
        return "PtypBinary"
    if typebytes == "1003":
        return "PtypMultipleInteger32"
    if typebytes == "101E":
        return "PtypMultipleString8"
    if typebytes == "101F":
        return "PtypMultipleString"
    if typebytes == "1102":
        return "PtypMultipleBinary"
    return "Unknown(ProdID=%s)" % PropID

# Custom JSON encoder to encode bytes
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return str(obj)
        return json.JSONEncoder.default(self, obj)

json_out = open('test.json', 'w')

# When reading a binary file, always add a 'b' to the file open mode
with open('udetails.oab', 'rb') as f:
    (ulVersion, ulSerial, ulTotRecs) = unpack('<III', f.read(4 * 3))
    assert ulVersion == 32, 'This only supports OAB Version 4 Details File'
    print("Total Record Count: ", ulTotRecs)
    # OAB_META_DATA
    cbSize = unpack('<I', f.read(4))[0]
    # print("OAB_META_DATA")
    meta = BytesIO(f.read(cbSize - 4))
    # the length of the header attributes
    # we don't know and don't really need to know how to parse these
    HDR_cAtts = unpack('<I', meta.read(4))[0]
    print("rgHdrAtt HDR_cAtts",HDR_cAtts)
    for rgProp in range(HDR_cAtts):
        ulPropID = unpack('<I', meta.read(4))[0]
        ulFlags  = unpack('<I', meta.read(4))[0]
        # print(rgProp, lookup(ulPropID), ulFlags)
    # these are the attributes that we actually care about
    OAB_cAtts = unpack('<I', meta.read(4))[0]
    OAB_Atts = []
    print("rgOabAtts OAB_cAtts", OAB_cAtts)
    for rgProp in range(OAB_cAtts):
        ulPropID = unpack('<I', meta.read(4))[0]
        ulFlags  = unpack('<I', meta.read(4))[0]
        # print(rgProp, lookup(ulPropID), ulFlags)
        OAB_Atts.append(ulPropID)
    print("Actual Count", len(OAB_Atts))
    # OAB_V4_REC (Header Properties)
    cbSize = unpack('<I', f.read(4))[0]
    f.read(cbSize - 4)

    # now for the actual stuff
    while True:
        read = f.read(4)
        if read == b'':
            break
        # this is the size of the chunk, incidentally its inclusive
        cbSize = unpack('<I', read)[0]
        # so to read the rest, we subtract four
        chunk = BytesIO(f.read(cbSize - 4))
        # Format presenceBitArray as bits string
        presenceBitArray = bytearray(chunk.read(int(math.ceil(OAB_cAtts / 8.0))))
        presenceBitArrayStr = "".join( ['{:08b}'.format(b) for b in presenceBitArray] )
        print("\n----------------------------------------")
        # print("Chunk Size: ", cbSize)

        def read_str():
            # strings in the OAB format are null-terminated
            buf = b""
            while True:
                n = chunk.read(1)
                if n == b"\0" or n == b"":
                    break
                buf += n
            return buf.decode("utf-8")

        def read_int():
            # integers are cool aren't they
            byte_count = unpack('<B', chunk.read(1))[0]
            if 0x81 <= byte_count <= 0x84:
                byte_count = unpack('<I', (chunk.read(byte_count - 0x80) + b"\0\0\0")[0:4])[0]
            else:
                assert byte_count <= 127, "byte count must be <= 127"
            return byte_count

        rec = {}

        # Loop through all possible attributes
        for i in range(OAB_cAtts):
            # check if attribute is present for this entry
            if presenceBitArrayStr[i] == "0":
                continue
            # Get PropID
            PropID = hexify(OAB_Atts[i])
            # If PropID not in schema, name it Unknown(PropID)
            if PropID not in PidTagSchema:
                Name = "Unknown(%s)" % PropID
            else:
                Name = PidTagSchema[PropID]
            # Get Type from PropID
            Type = gettype(PropID)
            # Extract value based on attribute type
            if Type == "PtypString8" or Type == "PtypString":
                val = read_str()
                rec[Name] = val
                print("%s (%s) : %s" % (Name,Type,val))
            elif Type == "PtypBoolean":
                val = unpack('<?', chunk.read(1))[0]
                rec[Name] = val
                print("%s (%s) : %s" % (Name,Type,val))
            elif Type == "PtypInteger32":
                val = read_int()
                rec[Name] = val
                print("%s (%s) : %s" % (Name,Type,val))
            elif Type == "PtypBinary":
                bin = chunk.read(read_int())
                rec[Name] = binascii.b2a_hex(bin)
                print("%s (%s) len=%s %s" % (Name, Type, len(bin), binascii.b2a_hex(bin)))
            elif Type == "PtypMultipleString" or Type == "PtypMultipleString8":
                byte_count = read_int()
                print("%s (%s[%s])" % (Name,Type,byte_count))
                arr = []
                for i in range(byte_count):
                    val = read_str()
                    arr.append(val)
                    print("\t(%s) %s" % (i,val))
                rec[Name] = arr
            elif Type == "PtypMultipleInteger32":
                byte_count = read_int()
                print("%s (%s[%s])" % (Name,Type,byte_count))
                arr = []
                for i in range(byte_count):
                    val = read_int()
                    if Name == "OfflineAddressBookTruncatedProperties":
                        val = hexify(val)
                        if val in PidTagSchema:
                            val = PidTagSchema[val]
                        else:
                            val = "Unknown(%s)" % val
                    arr.append(val)
                    print("\t(%s) %s" % (i,val))
                rec[Name] = arr
            elif Type == "PtypMultipleBinary":
                byte_count = read_int()
                print("%s (%s[%s])" % (Name,Type,byte_count))
                arr = []
                for i in range(byte_count):
                    bin_len = read_int()
                    bin = chunk.read(bin_len)
                    arr.append(binascii.b2a_hex(bin))
                    print("\t(%s) len=%s %s" % (i,bin_len, binascii.b2a_hex(bin)))
                rec[Name] = arr
            else:
                raise Exception("Unknown property type (" + Type + ")")
                
        remains = chunk.read()
        if len(remains) > 0:
            raise Exception("This record contains unexpected data at the end: " + remains)
        
        json_out.write(json.dumps(rec, cls=BytesEncoder) + '\n')
        
