# asn1stream

Handling ASN.1 over streamed data. Fixed memory space.

This repo is a draft.
The code is beta state.
The API is alpha.

The purpose of this code is to allow encoding and decoding ASN.1 for a
streamed input which does not allow seeking and while keeping the memory
space constant.

An example of usage is receiving large files over an encrypted or
compressed AS2 message.

Reusing some code from [asn1](https://github.com/andrivet/python-asn1) package.

MIT licence.

Usage principles for decoder:

* The Tag class is a minimal and generic representation of the tag,
  without any semantics.

* Initiate a new decoder for each steam.

* Use StreamingASN1Decoder.dataReceived(bytes) to input chunked data.
  Will raise ASN1TooMuch when too much data is received without being consumed.
  Call read() or flush() to consume the data.

* Use StreamingASN1Decoder.getTag() to read the current tag.
  Will raise ASN1WantMore if no tag can be read.
  You will need to call dataReceived(bytes)
  before calling getTag() again.

* Use StreamingASN1Decoder.read(tag) to return the whole value of the tag.
  Will raise ASN1WantMore if the whole tag value is not yet available.
  You can call dataReceived(bytes) to add more data and try again.
  This is designed only for the case in which you know that the value is
  small. See flush()

* Use StreamingASN1Decoder.dump(tag) to return the ASN1 encoding of the tag
  and value.
  Will raise ASN1WantMore if the compete value is not yet available.
  Design for small values.
  The result can then be used in specialized Python ASN1 parser like
  asn1crypto or pyasn1.

* Use StreamingASN1Decoder.flush(tag) to read chunks of a tag.
  Will never raise ASN1WantMore.
  Return `None` when the whole value was read.
  Can return empty bytes when no value is yet available.
