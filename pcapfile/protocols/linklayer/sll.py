import ctypes
import struct
from .ethernet import payload_type


class Sll(ctypes.Structure):
    """
    Represents an SLL frame.
    """

    _fields_ = [('type', ctypes.c_ushort)]

    payload = None

    def __init__(self, packet, layers=0):
        super(Sll, self).__init__()
        self.type = struct.unpack('!H', packet[14:16])[0]

        self.payload = packet[16:]

        if layers:
            self.load_network(layers)

    def load_network(self, layers=1):
        """
        Given an Ethernet frame, determine the appropriate sub-protocol;
        If layers is greater than zerol determine the type of the payload
        and load the appropriate type of network packet. It is expected
        that the payload be a hexified string. The layers argument determines
        how many layers to descend while parsing the packet.
        """
        if layers:
            ctor = payload_type(self.type)[0]
            if ctor:
                ctor = ctor
                payload = self.payload
                self.payload = ctor(payload, layers - 1)
            else:
                # if no type is found, do not touch the packet.
                pass

    def __str__(self):
        frame = 'type %s'
        frame = frame % (payload_type(self.type)[1])
        return frame
