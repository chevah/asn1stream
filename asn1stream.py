"""
ASN1 handling over streams in a fixed memory space.
"""
from __future__ import absolute_import, unicode_literals

from enum import IntEnum


class Numbers(IntEnum):
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    ObjectDescription = 0x07
    Instance = 0x08
    Real = 0x09
    Enumerated = 0x0a
    EnumeratedPDV = 0x0b
    UTF8String = 0x0c
    RelativeObjectIdentifier = 0x0d
    #
    # Gap in specs.
    #
    Sequence = 0x10
    Set = 0x11
    NumericString = 0x12
    PrintableString = 0x13
    TeletexString = 0x14
    VideotexString = 0x15
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    GraphicString = 0x19
    VisibleString = 0x1a
    GeneralString = 0x1b
    UniversalString = 0x1c
    CharacterString = 0x1d
    UnicodeString = 0x1e


class Types(IntEnum):
    Constructed = 0x20
    Primitive = 0x00


class Classes(IntEnum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xc0


class ASN1Error(Exception):
    """
    General error raised when the API is not used as expected.
    """


class ASN1SyntaxError(ASN1Error):
    """
    Error during ASN1 decoding. Don't know how to handle the received data.

    Maybe invalid data, maybe unsupported features.
    """


class ASN1WantMore(Exception):
    """
    Raised when more data needs to be read.
    """

class ASN1TooMuch(Exception):
    """
    Raised when the current buffer is too big.
    """



class Tag(object):
    def __init__(self, number, type, cls, length, raw):
        self.number = number
        self.type = type
        self.cls = cls
        self.length = length
        self.raw = raw

    def __repr__(self):
        return 'N:x%02x T:x%02x C:x%02x L:%s' % (
            self.number, self.type, self.cls, self.length)


class StreamingASN1Decoder(object):
    """
    ASN.1 decoder. Understands BER (and DER which is a subset).

    It is designed to parse the encoded input as provided in chunks.
    """

    MAX_BUFFER_SIZE = 200 * 1024

    def __init__(self):  # type: () -> None
        self._buffer = b''

        self._last_tag = None
        self._flush_size = 0

        self._resetTag()

    def _resetTag(self):
        self._prev_tag = self._last_tag
        self._prev_size = self._flush_size
        self._last_tag = None
        self._flush_size = 0

    def dataReceived(self, data):
        """
        Called when we got more data to decode.

        Will raise ASN1TooMuch when the buffer can't receive more data.
        """
        if len(self._buffer) + len(data) > self.MAX_BUFFER_SIZE:
            raise ASN1TooMuch(
                'Call read() or flush() before piping more data.')

        self._buffer += data

    def getTag(self):
        """
        Return the current tag header.

        Raises an error if tag can't be fully read.
        """
        if self._last_tag and self._last_tag.type != Types.Constructed:
            raise ASN1Error(
                'You need to read current tag value, before continuing.')

        read_cursor = [0]

        def read_byte():
            """
            Return the next input byte.

            Raise an error when more data is needed.
            """
            try:
                result = ord(self._buffer[read_cursor[0]])
                read_cursor[0] += 1
                return result
            except IndexError:
                raise ASN1WantMore('Premature end of input.')

        byte = read_byte()
        cls = byte & 0xc0
        typ = byte & 0x20
        nr = byte & 0x1f
        if nr == 0x1f:
            # Long form of tag encoding
            nr = 0
            while True:
                byte = read_byte()
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break

        # Now read the length.
        byte = read_byte()
        if byte & 0x80:
            # Long form of length encoding.
            count = byte & 0x7f
            if count == 0x7f:
                raise ASN1SyntaxError('ASN1 syntax error')

            if count > 64:
                raise ASN1Error(
                    'Length size larger than 64bits are not supported.')

            bytes_data = self._read_bytes(read_cursor[0], count)
            read_cursor[0] += count
            length = 0
            for byte in bytes_data:
                length = (length << 8) | ord(byte)

            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte

        self._last_tag = Tag(
            number=nr,
            type=typ,
            cls=cls,
            length=length,
            raw=self._buffer[:read_cursor[0]],
            )
        self._buffer = self._buffer[read_cursor[0]:]

        return self._last_tag

    def read(self, tag):  # type: (Number) -> (Tag, any)
        """This method decodes one ASN.1 tag from the input and returns it as a
        ``(tag, value)`` tuple. ``tag`` is a 3-tuple ``(nr, typ, cls)``,
        while ``value`` is a Python object representing the ASN.1 value.
        The offset in the input is increased so that the next `Decoder.read()`
        call will return the next tag. In case no more data is available from
        the input, this method returns ``None`` to signal end-of-file.

        Returns:
            `Tag`, value: The current ASN.1 tag and its value.

        Raises:
            `Error`
        """
        if tag.type != Types.Primitive:
            raise ASN1Error('Only primitive types can be read.')

        nr = tag.number
        length = tag.length

        bytes_data = self._read_bytes(0, length)
        self._buffer = self._buffer[length:]
        if tag.cls != Classes.Universal:
            value = bytes_data
        elif nr == Numbers.Boolean:
            value = self._decode_boolean(bytes_data)
        elif nr in (Numbers.Integer, Numbers.Enumerated):
            value = self._decode_integer(bytes_data)
        elif nr == Numbers.Null:
            value = self._decode_null(bytes_data)
        elif nr == Numbers.ObjectIdentifier:
            value = self._decode_object_identifier(bytes_data)
        elif nr in (
            Numbers.PrintableString, Numbers.IA5String, Numbers.UTCTime
                ):
            value = bytes_data.decode('utf-8')
        else:
            value = bytes_data

        self._resetTag()
        return value

    def dump(self, tag):
        """
        Return the raw data for tag.
        """
        length = tag.length
        result = self._read_bytes(0, length)
        self._buffer = self._buffer[length:]
        self._resetTag()
        return tag.raw + result

    def flush(self):
        """
        Return the partial raw value of the current tag.

        Return empty bytes string when no data is yet available.

        Return `None` if all data was flushed.
        """
        if not self._last_tag:
            raise ASN1Error('Nothing to flush.')

        remaining = self._last_tag.length - self._flush_size

        if not remaining:
            self._resetTag()
            return None

        chunk = self._buffer[:remaining]
        read_size = len(chunk)
        self._flush_size += read_size
        self._buffer = self._buffer[read_size:]
        return chunk

    def _read_bytes(self, start, count):  # type: (int) -> bytes
        """Return the next ``count`` bytes of input. Raise error on
        end-of-input."""
        bytes_data = self._buffer[start:start + count]

        if len(bytes_data) != count:
            raise ASN1WantMore('Premature end of input.')

        return bytes_data

    @staticmethod
    def _decode_boolean(bytes_data):  # type: (bytes) -> bool
        """Decode a boolean value."""
        if len(bytes_data) != 1:
            raise ASN1SyntaxError('ASN1 syntax error')
        if bytes_data[0] == '\x00':
            return False
        return True

    @staticmethod
    def _decode_integer(bytes_data):  # type: (bytes) -> int
        """Decode an integer value."""
        values = [ord(b) for b in bytes_data]
        # check if the integer is normalized
        if (
            len(values) > 1
            and (
                values[0] == 0xff
                and values[1] & 0x80
                or values[0] == 0x00
                and not (values[1] & 0x80)
                )):
            raise ASN1SyntaxError('ASN1 syntax error')
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break

                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = value
        except OverflowError:
            pass
        return value

    @staticmethod
    def _decode_octet_string(bytes_data):  # type: (bytes) -> bytes
        """Decode an octet string."""
        return bytes_data

    @staticmethod
    def _decode_null(bytes_data):  # type: (bytes) -> any
        """Decode a Null value."""
        if len(bytes_data) != 0:
            raise ASN1SyntaxError('ASN1 syntax error')
        return None

    @staticmethod
    def _decode_object_identifier(bytes_data):  # type: (bytes) -> str
        """Decode an object identifier."""
        result = []
        value = 0
        for i in range(len(bytes_data)):
            byte = ord(bytes_data[i])
            if value == 0 and byte == 0x80:
                raise ASN1SyntaxError('ASN1 syntax error')
            value = (value << 7) | (byte & 0x7f)
            if not byte & 0x80:
                result.append(value)
                value = 0
        if len(result) == 0 or result[0] > 1599:
            raise ASN1SyntaxError('ASN1 syntax error')
        result = [result[0] // 40, result[0] % 40] + result[1:]
        result = list(map(str, result))
        return str('.'.join(result))
