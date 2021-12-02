namespace cose
{
    internal static class CoseConstants
    {
        // COSE tags https://datatracker.ietf.org/doc/html/rfc8152#page-8 Table 1.

        // Supported
        internal const uint COSE_Sign1 = 18;

        // Planned to support but not yet supported
        const uint COSE_Sign = 98;
        const uint COSE_Encrypt = 96;
        const uint COSE_Encrypt0 = 16;

        // Not planned to support
        const uint COSE_Mac = 97;
        const uint COSE_Mac0 = 17;

        // https://datatracker.ietf.org/doc/html/rfc8152#section-3.1 or Table 2.
        internal const int Alg = 1;
        internal const int Crit = 2;
        internal const int ContentType = 3;
        internal const int Kid = 4;
        internal const int IV = 5;
        internal const int PartialIV = 6;
        internal const int CounterSignature = 7;
    }

    internal enum CommonHeaderParameters
    {
        Alg,
        Crit,
        ContentType,
        Kid,
        IV,
        PartialIV,
        CounterSignature,
    }
}
