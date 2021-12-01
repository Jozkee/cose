﻿using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace cose
{
    internal static class CoseHelpers
    {
        internal static void ThrowInvalidToken(CborReaderState state)
        {
            throw new Exception($"Invalid token {state}");
        }

        internal static void ThrowUnexpectedTag(ulong cborTag)
        {
            // TODO: refine this message to indicate whether the tag is a COSE tag or not.
            throw new Exception($"Unpexted tag: {(CborTag)cborTag}");
        }

        internal static void Throw(string message)
        {
            throw new Exception(message);
        }

        internal static bool IsInteger(CborReaderState state)
            => state == CborReaderState.UnsignedInteger || state == CborReaderState.NegativeInteger;
    }
}
