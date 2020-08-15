"""
Tests for ASN1 streaming implementation.

openssl asn1parse -inform DER -i -in dump.asn1
"""
from __future__ import unicode_literals
import unittest

from asn1crypto.cms import RecipientInfos

import asn1stream as asn1


# This is an cms.ContentInfo dump.
TEST_DATA = (
    b'0\x82\x04w\x06\t*\x86H\x86\xf7\r\x01\x07\x03\xa0\x82\x04h0\x82\x04d\x02'
    b'\x01\x001\x81\xe50\x81\xe2\x02\x01\x000K0F1\x0b0\t\x06\x03U\x04\x06\x13'
    b'\x02GB1\x0f0\r\x06\x03U\x04\n\x13\x06Chevah1\x120\x10\x06\x03U\x04\x0b'
    b'\x13\tChevah CA1\x120\x10\x06\x03U\x04\x03\x13\tChevah CA\x02\x01\x0e0\r'
    b'\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x81\x80X\x92\x92\x939\xef'
    b'\x9f\xc2\xb7<\xa6\x9a\xa2\x8cO\x08\x03\xd8\x88\x05\xbf\x90\xe1\xd0\xb7'
    b'\xf8\x94\xbe\xecO$\x0b\xcc\xe6\xb2\x9a&U\t.dX\xa2\x7f*;g\xb4\x90#\xd8y'
    b'\xe2\r\x88\xe2\xc1\xda53\x1a\xe4w\xd3\xa5=h\xfcUl\xd3\xaf\xe1\xe3\xad'
    b'\x97\xdf\xfd#\x0f=D/z4$\xdc}\x88\xc1\xf9\xea\xcd)\xaf\xd4+\xa2k\xc0\x98'
    b'F\x86\xa6\x82\xc8\xdc\xa8ED\x9ee\xfe\xd3LG=\xf9\x9e\x88\x1a"1\xb3\xb4'
    b'\x9e\xe3\x900\x82\x03u\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x14\x06\x08*\x86H\x86\xf7\r\x03\x07\x04\x08\xfa\x1a\xf8^v\xec\x1a\x1c\x80\x82\x03P9\xaa\xc0\xc4#\xd7X\xcfI,Q\xb2\xa1\xf6\xde\x1b\x9fB\x9b<\xd2K\xad\x82\xb1\xe5\x81|1\xd1\xae\x98\x98\x1b\xb9\xeb\xdc\x8b\x9f\xcd\xa3\x1a\r\xfb\x04\x88\x17\x01>\\\x18\\\xb4\xdelu\x06\xd9:\xe8\xc2+\x17\x91Vm\xb1\xe4\x89P4\xc9\x99\xdfMI\x9a\xb6\t\xb1\x1dO\xbc\xae\xa3\x84\x80@u\xe6\t\xf2~U\xf6$mi{\xf0\xb27\xcdo9\x9f\x88>\xc8\xdd\x16n\xd6\xb3\xb12g\xdb\x94\x1f\xd8WX\xcde\x0e\x82\xde\xd1o\xc6J\xc2-\x11\x7f6W\xd9T\x9fu\x1c\nC\xe7n\x05\x8c\xfd\xda\xda\x10\xd6\x13\x11\xb0\x89l\xfb \x00\x95\x93\xb7Vl\xc5\x05.\xcb\x87\xdd\xe1lK\x03^]\x9dS\xeb\xc2\x07f\xf7\xa3)\xdf\x96\xa6\xc0W\xbblJ\x1e\xd3\x0f\x97u;(\xc5\x14\xdb\xf4\xa5\xe6j(S\xf9\xfd\xb7\'\x9a\xb8\xc7>q\xe4\xe6C\xfd\x8b=;\xac\x9e\xf9\x9b>\xd6\x85=\x8d4[\xd5\xfd\x9f{\x0eANNxf\xa1\x85v\xe8\x9c\xbbF\xc5\xfb\xfb=\xe1\x92\xa7\xef\x8b+9hp\x06>A\x95\xe1\xb2\x94\x7f\xa8,\xe1\x1dpu\xcb\xdaSX\x80\xe1\xa6\xe2\x1f\x872](\xdc\xe0N\xdex\xf5F\xc9]E56\xe6\\\xc5`\xf4\x88\xd1H|\xd6\xa0\n\xa8"`\xf4p{C\xf0\xe0B\x8cR \x95\xa7i\x05I u\xf2ma\x06\xe7\x0f6\xf4h\x02\xdfwB\x08\xfe!\x1d\x17L\x18:\xd1\xa6\x1a+\xa9\x95[~"D\xb0\x94\xbb\x01X\x85\x17)J\xee\\4xB#&XP\xa6\\\xd6\xae\xd3\xc4\xec8j\x95\x07[\x18\x83\x93\xec\xb5O\xa5\xb0\xccue\xae1UL\xf0\xe4+\ruw\x8b\xc9\xbf\xb1I\xac\xf5\x82\xbd&j|K\x1c\xe4\x8d&\xb2e\x1a\xddum\xb7\xd6\x83%\xf5\xf6w\x06\x9f\xd6\x088\xdc\x8f\xe6u\x15\xa7)\xff\xd8S\xde\xa5\x9a\xd3\xcb\t\xda\xd6\xde\xa0oP\xba\xa0\xc9\\8\x16\x0c\'\xd5\xd5\xbd\xfdva\xbd\xd9P@\xcdp\x04\x8eF\xcdx\xe1\xbe\xed\x10\xec\xd7F\xd4\xfe4h i5T\xc8}vf\xad\xc1\xfc\x88\xd8b\x98\xb3KX1&\xe9\x97\xcf\xc1d\x89\xe8{\xaa\xd1\xbe\xf9\x9ewQ-D\x14g1\xd2(G\x92:B\xe0\x9fw\xeev\xbfO\xb5b\xdc\xd7+\xaa\n\xd2W0\xae\xc7\x91O\x13\xf5\xfb\xe1G\xb4$\xaaX\xf8$\xf8y\x80\x12\x0cR\xac\xef@\x18`\xf2\xad\xbbI{\x15o&Fp\xf1X\xea\xbc\x901b\xeavc\x81tKY\x10\n\xabf\xfb\x95\x15\x0c\xb1\xd1\x82\x8a\x06\xea#\x10\xec\xc2$@\x1d\xfb\xa7\x1dP\x9c\x0e\x89r\xeb\xe9i\'\xc5\x15\xc4a\n*G\xa6y\x83fB\xc5i\xf07\x17\x10\x14\xebp\xc7\t\x93k\x17\x00\x1c|LK\xc6\xb1\x05\xf2\xb8L\xd7p\xe3\x8fF\xbc\t\xbdA\x8a\xdd\x12\x82%\xda\x9a B\xf4@\xbf\xe3n\x96(R\x12z\x13\xc5M\x16\xaeZ\x88pc\xdb\xa5\x1b\xd3\xb2!x\\O\x9c\xe1\x03\xb5;\xdf\t\xa0\xba\xd8\x89\xc5F?\x84\x1e\xb9_@\xd8-\x8ao\xf4\xf9\x1d2\xea_hHs\xb2I\xaf9\xfc\x17\x0f\xb5\x923\x82PI\xd1\t\xea\x1aa\x05\xe2\x88\xe4\xb6\xe4\xe3`\xa5%\xfa\'g E\x7f9\x10\xfa+A\xaa\xf9M0)\xbd\x7f\xdf\xa3\xf5\xe48F\xb5\x80\x14\xe1\xa5y@\x06f*\x82\x1e\x94L\xe9\x0c\x17\xe6\xf9b'
    )


class TestStreamingASN1Decoder(unittest.TestCase):
    """
    Tests for StreamingASN1Decoder.
    """

    def test_init(self):
        sut = asn1.StreamingASN1Decoder()

        self.assertRaises(
            asn1.ASN1WantMore,
            sut.getTag
            )

    def test_getTag_want_more(self):
        """
        Will return the tag, as soon as all header is available.
        """
        sut = asn1.StreamingASN1Decoder()

        for i in range(3):
            sut.dataReceived(TEST_DATA[i:i + 1])
            self.assertRaises(
                asn1.ASN1WantMore,
                sut.getTag
                )

        sut.dataReceived(TEST_DATA[3:4])
        result = sut.getTag()

        self.assertEqual(asn1.Numbers.Sequence, result.number)
        self.assertEqual(asn1.Types.Constructed, result.type)
        self.assertEqual(asn1.Classes.Universal, result.cls)
        self.assertEqual(1143, result.length)

    def test_getTag_continue(self):
        """
        Will return the tag and consume the stream.
        """
        sut = asn1.StreamingASN1Decoder()

        sut.dataReceived(TEST_DATA[0:4])
        result = sut.getTag()
        self.assertEqual(asn1.Numbers.Sequence, result.number)

        # Stream is consumed.
        self.assertRaises(
            asn1.ASN1WantMore,
            sut.getTag
            )

        # Once more data is available, it can read the next tag.
        sut.dataReceived(TEST_DATA[4:6])

        result = sut.getTag()
        self.assertEqual(asn1.Numbers.ObjectIdentifier, result.number)
        self.assertEqual(asn1.Types.Primitive, result.type)
        self.assertEqual(asn1.Classes.Universal, result.cls)
        self.assertEqual(9, result.length)

    def test_read(self):
        """
        Will return the tag and consume the stream.
        """
        sut = asn1.StreamingASN1Decoder()

        sut.dataReceived(TEST_DATA[0:6])
        sut.getTag()
        tag = sut.getTag()

        self.assertRaises(
            asn1.ASN1WantMore,
            sut.read, tag
            )

        # Partial data received.
        sut.dataReceived(TEST_DATA[6:10])
        self.assertRaises(
            asn1.ASN1WantMore,
            sut.read, tag
            )

        # All value data received.
        sut.dataReceived(TEST_DATA[10:15])
        result = sut.read(tag)

        # enveloped_data UID
        self.assertEqual(b'1.2.840.113549.1.7.3', result)

        # Steam was consumed.
        self.assertRaises(
            asn1.ASN1WantMore,
            sut.getTag
            )

        sut.dataReceived(TEST_DATA[15:100])
        # Content sequence and BER marker.
        tag = sut.getTag()
        self.assertEqual(0, tag.number)
        tag = sut.getTag()
        self.assertEqual(asn1.Numbers.Sequence, tag.number)

        # CMS version
        tag = sut.getTag()
        self.assertEqual(asn1.Numbers.Integer, tag.number)
        result = sut.read(tag)
        self.assertEqual(0, result)

        # recipient_infos set.
        tag = sut.getTag()
        self.assertEqual(asn1.Numbers.Set, tag.number)

    def test_read_constructed(self):
        """
        Will return the tag and consume the stream.
        """
        sut = asn1.StreamingASN1Decoder()

        sut.dataReceived(TEST_DATA[0:6])
        tag = sut.getTag()

        error = self.assertRaises(
            asn1.ASN1Error,
            sut.read, tag
            )

        self.assertEqual('Only primitive types can be read.', error.message)

    def test_dump(self):
        """
        Will return the raw data for the tag, including the tag itself.
        """
        sut = asn1.StreamingASN1Decoder()

        sut.dataReceived(TEST_DATA[0:100])
        # Root sequence.
        sut.getTag()
        # Content type.
        sut.read(sut.getTag())
        # Content itself
        sut.getTag()
        sut.getTag()
        # CMS version
        self.assertEqual(0, sut.read(sut.getTag()))

        # recipient_infos set.
        tag = sut.getTag()
        self.assertEqual(asn1.Numbers.Set, tag.number)

        # Full data not available.
        self.assertRaises(
            asn1.ASN1WantMore,
            sut.dump, tag
            )

        sut.dataReceived(TEST_DATA[100:300])

        raw = sut.dump(tag)

        # Raw data can be parsed by any external ASN1 decoder.
        result = RecipientInfos.load(raw)
        self.assertEqual(
            'rsa', result.native[0]['key_encryption_algorithm']['algorithm'])

        # The cursor is advanced
        # EncryptedContentInfo sequence.
        tag = sut.getTag()
        self.assertEqual(asn1.Numbers.Set, tag.number)
        # content_type -> data OID
        self.assertEqual('1.2.840.113549.1.7.1', sut.read(tag))
