using System.Diagnostics;
using System.Formats.Cbor;
using System.Text;

namespace cose.Impl
{
    internal /*static*/ class Cose
    {
        const byte EmptyStringByte = 0xa0;
        public /*static*/ void Decode(ReadOnlyMemory<byte> source)
        {
            var reader = new CborReader(source);

            // First, I want to traverse the whole payload as an experiment.
            while (true) 
            {
                var state = reader.PeekState();
                if (state == CborReaderState.Finished)
                {
                    PrintStateAndValue(state, 0);
                    break;
                }

                switch (state)
                {
                    case CborReaderState.Tag:
                        CborTag tag = reader.ReadTag();
                        PrintStateAndValue(state, tag);
                        break;

                    case CborReaderState.StartArray:
                        int? arrayLength = reader.ReadStartArray();
                        PrintStateAndValue(state, arrayLength);
                        break;

                    case CborReaderState.EndArray:
                        reader.ReadEndArray();
                        PrintStateAndValue(state, 0);
                        break;

                    case CborReaderState.ByteString:
                        // First array element is the protected bucket, in the happy path it is empty,
                        // but we should deal with it eventually.
                        // .
                        byte[] bstr = reader.ReadByteString();
                        PrintStateAndValue(state, bstr);
                        break;

                    case CborReaderState.StartMap:
                        int? mapLength = reader.ReadStartMap();
                        PrintStateAndValue(state, mapLength);
                        break;

                    case CborReaderState.EndMap:
                        reader.ReadEndMap();
                        PrintStateAndValue(state, 0);
                        break;

                    case CborReaderState.UnsignedInteger:
                        ulong ulongValue = reader.ReadUInt64();
                        PrintStateAndValue(state, ulongValue);
                        break;

                    case CborReaderState.NegativeInteger:
                        long longValue = reader.ReadInt64();
                        PrintStateAndValue(state, longValue);
                        break;
                    default:
                        throw new Exception("Unknown state: " + state);
                }
            }
        }

        private void PrintStateAndValue<T>(CborReaderState state, T value)
        {
            Console.Write($"state: {state}, value: {value} ");

            if (value is byte[] bytes)
            {
                Console.Write($"bstr length: {bytes.Length} ");
                Console.Write($"content: {BitConverter.ToString(bytes)} ");
                Console.Write($"utf-8: {Encoding.UTF8.GetString(bytes)} ");
            }
            
            Console.WriteLine();
        }

        public void Decode2(ReadOnlyMemory<byte> source)
        {
            var reader = new CborReader(source);

            CborReaderState state = reader.PeekState();

            // Is a supported tag or untagged. Q: should we assume COSE_Sign1 if untagged?
            if (state == CborReaderState.Tag)
            {
                ulong tag = (ulong)reader.ReadTag(); // Can you read the tag as a ulong to avoid the cast?
                if (tag != CoseConstants.COSE_Sign1)
                {
                    CoseHelpers.ThrowUnexpectedTag(tag);
                }
            }

            // All COSE structures are CBOR arrays.
            state = reader.PeekState();
            if (state != CborReaderState.StartArray)
            {
                CoseHelpers.ThrowInvalidToken(state);
            }

            // COSE_Sign[1] must contain 4 array elements.
            int? arrayLength = reader.ReadStartArray();
            if (arrayLength != 4)
            {
                CoseHelpers.Throw($"Incorrect CBOR Array length; expected: 4, actual: {arrayLength}");
            }

            var headerParameters = new Dictionary<object, object>();

            // Protected header as bstr (empty or serialized map). 
            ReadProtectedHeader(reader, headerParameters);

            // Unprotected header as map.

            // Content/payload as bstr.

            // Signature(s).
        }

        private static void ReadProtectedHeader(CborReader reader, Dictionary<object, object> headerParameters)
        {
            CborReaderState state = reader.PeekState();
            if (state != CborReaderState.ByteString)
            {
                CoseHelpers.Throw($"Incorrect type at Protected header; expected: {CborReaderState.ByteString}, actual: {state}");
            }

            ReadOnlyMemory<byte> protectedHeaderAsBstr = reader.ReadByteString();
            if (protectedHeaderAsBstr.Length == 0)
            {
                CoseHelpers.Throw("protected header was incorrect; expected a zero-length string or a map");
            }
            else if (protectedHeaderAsBstr.Length == 1 && protectedHeaderAsBstr.Span[0] == EmptyStringByte)
            {
                // zero-length string case signals that the protected header is empty.
                return;
            }

            // Protected header is not empty, proceed to decode the CBOR map.
            ReadProtectedHeaderCore(protectedHeaderAsBstr);
        }

        // TODO: Think if read-header logic can be reused for unprotected.
        private static void ReadProtectedHeaderCore(ReadOnlyMemory<byte> protectedHeaderAsBstr)
        {
            // deserialize map.
            var reader = new CborReader(protectedHeaderAsBstr);
            int? mapLength = reader.ReadStartMap(); // this will defer validation to the reader, is that OK?

            for (int i = 0; i < mapLength; i++)
            {
                // COSE only accepts strings and integers as map labels.
                // Labels in each of the maps MUST be unique.
                // Applications SHOULD verify that the same label does not
                // occur in both the protected and unprotected headers.

                // key of the CBOR map key-value pair. It is called label in COSE to avoid confussion with criptographic key.
                int? label = reader.PeekState() switch
                {
                    CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger => reader.ReadInt32(),
                    CborReaderState.TextString => Convert.ToInt32(reader.ReadInt32()),
                    _ => null
                };

                if (label is null)
                {
                    CoseHelpers.Throw("Invalid value type in header parameter");
                }

                int? value = null;
                // From Table 2 and https://www.iana.org/assignments/cose/cose.xhtml 
                // TODO:
                // * Think if we should throw
                // * Think if we shouldn't validate common header params in here and defer validation after all header params were retrieved.
                switch ((CommonHeaderParameters)label)
                {
                    case CommonHeaderParameters.Alg: // (int / tstr)
                        if (CoseHelpers.IsInteger(reader.PeekState()))
                        {
                            value = reader.ReadInt32();
                        }
                        else if (reader.PeekState() == CborReaderState.TextString)
                        {
                            value = Convert.ToInt32(reader.ReadTextString());
                        }
                        else
                        {
                            CoseHelpers.Throw("Invalid value type in header parameter");
                        }
                        break;

                    case CommonHeaderParameters.Crit: // ([+label])
                        if (reader.PeekState() != CborReaderState.StartArray)
                        {
                            CoseHelpers.Throw("Invalid value type in header parameter");
                        }

                        // TODO
                        break;

                    case CommonHeaderParameters.ContentType: // (tstr / uint)
                        if (reader.PeekState() == CborReaderState.TextString)
                        {
                            // TODO
                        }
                        else if (reader.PeekState() == CborReaderState.UnsignedInteger)
                        {
                            // TODO
                        }
                        else
                        {
                            CoseHelpers.Throw("Invalid value type in header parameter");
                        }
                        break;
                    case CommonHeaderParameters.Kid: // (bstr)
                        if (reader.PeekState() != CborReaderState.ByteString)
                        {
                            CoseHelpers.Throw("Invalid value type in header parameter");
                        }
                        // TODO
                        break;
                    case CommonHeaderParameters.IV: // (bstr) maybe it can be collepsed with above case.
                        if (reader.PeekState() != CborReaderState.ByteString)
                        {
                            CoseHelpers.Throw("Invalid value type in header parameter");
                        }
                        // TODO
                        break;
                    case CommonHeaderParameters.PartialIV: // (bstr)
                        if (reader.PeekState() != CborReaderState.ByteString)
                        {
                            CoseHelpers.Throw("Invalid value type in header parameter");
                        }
                        // TODO
                        break;
                    case CommonHeaderParameters.CounterSignature: // (COSE_Signature / [+COSE_Signature])
                            // TODO
                        break;

                    default:
                        // TODO
                        break;
                }

                Debug.Assert(value != null);
            }
        }
    }
}
