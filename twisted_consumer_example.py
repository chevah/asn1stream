from __future__ import unicode_literals
import asn1stream as asn1
from twisted.internet.interfaces import IConsumer
from zope.interface import implementer


@implementer(IConsumer)
class ASN1StreamConsumer(object):
    """
    Shared code for consuming and processing ASN1 streams.

    It will parse the ASN1 structure, up to the point where it reached a
    large tag and when it will generate chunks from that tag.
    """
    # List of step used to parse the stream.
    # Should be defined by each subclass
    _steps = None

    def __init__(self):
        self._producer = None
        self._decoder = asn1.StreamingASN1Decoder()
        # Consumer of the decrypted payload.
        self._consumer = None
        # Result of the last step.
        self._last_tag = None

    def _chunkReceived(self, data):
        """
        Called when tag value is consumed.
        """
        raise NotImplementedError('Implement _chunkReceived.')

    def registerProducer(self, producer):
        """
        Signal that we are receiving data from a streamed request.

        Only stream producer is supported.
        """
        self._producer = producer

    def unregisterProducer(self):
        """
        Called when all data was received.
        """
        self._producer = None
        if not self._consumer:
            return

        self._consumer.write(self._finalize())
        self._consumer.unregisterProducer()
        self._consumer = None

    def close(self):
        """
        Called when all the data was received.
        """

    def write(self, data):
        """
        Called by transport when encrypted raw content is received.
        """
        self._decoder.dataReceived(data)
        self._process()

    def _process(self):
        """
        Called after raw encrypted/encapsulated data was received.
        """
        if not self._steps:
            return self._consumeContent()

        while self._steps:
            try:
                self._last_tag = self._steps[0](self._last_tag)
            except asn1.ASN1WantMore:
                return
            # Step done.
            self._steps.pop(0)

        self._consumeContent()

    def _consumeContent(self):
        """
        Called each time we got raw encrypted data.
        """
        if not self._last_tag:
            try:
                self._last_tag = self._decoder.getTag()
            except asn1.ASN1WantMore:
                # Next chunk not ready
                return

        while self._last_tag.raw != b'\x00\x00':
            data = self._decoder.flush()

            if data is None:
                # Current chunk done.
                # Go to next chunk and prepare to fail to read the full
                # new chunk.
                self._last_tag = None
                try:
                    self._last_tag = self._decoder.getTag()
                except asn1.ASN1WantMore:
                    # Next chunk not ready yet.
                    return

                if self._last_tag.raw == b'\x00\x00':
                    return

                data = self._decoder.flush()

            if not data:
                # No more data available.
                return

            self._chunkReceived(data)

    def _getTag(self, ignored):
        """
        Parse the next tag.
        """
        return self._decoder.getTag()

    def _consumeContext(self, tag):
        """
        The encrypted data might be constructed from multiple chunks.
        """
        if tag.cls != asn1.Classes.Context:
            # Not a context
            return tag

        if tag.length == 0:
            # A context with unknown lenght.
            return self._decoder.getTag()

        if tag.type == asn1.Types.Constructed:
            # A constucted context
            return self._decoder.getTag()

        # Just return the context as it should be read.
        return tag


class DumpCompressedCMS(ASN1StreamConsumer):
    """
    Print all the data of the compressed data from cms.ContentInfo sequence.

    It navigates the cms.ContentInfo data and ignores the CMSVersion and
    ContentType.
    """

    def __init__(self):
        super(DumpCompressedCMS, self).__init__()
        self._steps = [
            self._getTag,  # The root ContentInfo.
            self._getTag, self._decoder.read,  # ContentType - compressed_data
            self._getTag,  # Any tag - content.
            self._getTag,  # CompressedData sequence
            self._getTag, self._decoder.read,  # CMSVersion
            self._getTag,  self._parseAlgorithm,
            self._getTag,  # EncapsulatedContentInfo sequence,
            self._getTag, self._decoder.read,  # ContentType - data
            self._getTag, self._consumeContext,
            ]
        # Algorithm used by the compressed data.
        self._algorithm = None

    def _parseAlgorithm(self, tag):
        """
        Called when we got the compression algorithms.
        """
        self._algorithm = cms.CompressionAlgorithm().load(
            self._decoder.dump(tag))

    def _chunkReceived(self, data):
        """
        Calld for each fragment of the compressed data.
        """
        print(data)
