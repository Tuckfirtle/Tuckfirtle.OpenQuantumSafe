// Copyright (C) 2022, The Tuckfirtle Developers
// 
// Please see the included LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Tuckfirtle.OpenQuantumSafe.Exception;

namespace Tuckfirtle.OpenQuantumSafe;

public class Signature : IDisposable
{
    private class Native
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        public readonly struct OQS_SIG
        {
            /// <summary>
            /// Printable string representing the name of the signature scheme.
            /// </summary>
            public readonly string MethodName;

            /// <summary>
            /// Printable string representing the version of the cryptographic algorithm.
            /// </summary>
            public readonly string Version;

            /// <summary>
            /// The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission.
            /// </summary>
            public readonly byte ClaimedNistLevel;

            /// <summary>
            /// Whether the signature offers EUF-CMA security (TRUE) or not (FALSE).
            /// </summary>
            [MarshalAs(UnmanagedType.U1)]
            public readonly bool IsEufCma;

            /// <summary>
            /// The (maximum) length, in bytes, of public keys for this signature scheme.
            /// </summary>
            public readonly nuint PublicKeyLength;

            /// <summary>
            /// The (maximum) length, in bytes, of secret keys for this signature scheme.
            /// </summary>
            public readonly nuint SecretKeyLength;

            /// <summary>
            /// The (maximum) length, in bytes, of signatures for this signature scheme.
            /// </summary>
            public readonly nuint SignatureLength;

            public readonly KeypairDelegate GenerateKeypair;

            public readonly SignDelegate Sign;

            public readonly VerifyDelegate Verify;

            /// <summary>
            /// Keypair generation algorithm.
            /// </summary>
            /// <param name="publicKey">The public key represented as a byte string.</param>
            /// <param name="secretKey">The secret key represented as a byte string.</param>
            /// <returns>Success or Error</returns>
            public delegate Status KeypairDelegate(ref byte publicKey, ref byte secretKey);

            /// <summary>
            /// Signature generation algorithm.
            /// </summary>
            /// <param name="signature">The signature on the message represented as a byte string.</param>
            /// <param name="signatureLength">The length of the signature.</param>
            /// <param name="message">The message to sign represented as a byte string.</param>
            /// <param name="messageLength">The length of the message to sign.</param>
            /// <param name="secretKey">The secret key represented as a byte string.</param>
            /// <returns>Success or Error</returns>
            public delegate Status SignDelegate(ref byte signature, ref nuint signatureLength, in byte message, nuint messageLength, in byte secretKey);

            /// <summary>
            /// Signature verification algorithm.
            /// </summary>
            /// <param name="message">The message represented as a byte string.</param>
            /// <param name="messageLength">The length of the message.</param>
            /// <param name="signature">The signature on the message represented as a byte string.</param>
            /// <param name="signatureLength">The length of the signature.</param>
            /// <param name="publicKey">The public key represented as a byte string.</param>
            /// <returns>Success or Error</returns>
            public delegate Status VerifyDelegate(in byte message, nuint messageLength, in byte signature, nuint signatureLength, in byte publicKey);
        }

        [DllImport("oqs")]
        public static extern IntPtr OQS_SIG_alg_identifier(nuint i);

        [DllImport("oqs")]
        public static extern int OQS_SIG_alg_count();

        [DllImport("oqs", CharSet = CharSet.Ansi)]
        public static extern int OQS_SIG_alg_is_enabled(string methodName);

        [DllImport("oqs", CharSet = CharSet.Ansi)]
        public static extern IntPtr OQS_SIG_new(string methodName);

        [DllImport("oqs")]
        public static extern void OQS_SIG_free(in IntPtr sig);
    }

    private IntPtr _signaturePtr;
    private readonly Native.OQS_SIG _signature;

    public static string[] SupportedMechanism { get; }

    public static string[] EnabledMechanism { get; }

    /// <summary>
    /// Printable string representing the name of the signature scheme.
    /// </summary>
    public string MethodName => _signature.MethodName;

    /// <summary>
    /// Printable string representing the version of the cryptographic algorithm.
    /// </summary>
    public string Version => _signature.Version;

    /// <summary>
    /// The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission.
    /// </summary>
    public byte ClaimedNistLevel => _signature.ClaimedNistLevel;

    /// <summary>
    /// Whether the signature offers EUF-CMA security (TRUE) or not (FALSE).
    /// </summary>
    public bool IsEufCma => _signature.IsEufCma;

    /// <summary>
    /// The (maximum) length, in bytes, of public keys for this signature scheme.
    /// </summary>
    public nuint PublicKeyLength => _signature.PublicKeyLength;

    /// <summary>
    /// The (maximum) length, in bytes, of secret keys for this signature scheme.
    /// </summary>
    public nuint SecretKeyLength => _signature.SecretKeyLength;

    /// <summary>
    /// The (maximum) length, in bytes, of signatures for this signature scheme.
    /// </summary>
    public nuint SignatureLength => _signature.SignatureLength;

    static Signature()
    {
        var supportedMechanism = new List<string>();
        var enabledMechanism = new List<string>();

        var mechanismCount = Native.OQS_SIG_alg_count();

        for (var i = 0; i < mechanismCount; i++)
        {
            var mechanismName = Marshal.PtrToStringAnsi(Native.OQS_SIG_alg_identifier((nuint) i));
            if (mechanismName == null) throw new OpenQuantumSafeException($"{nameof(mechanismName)} is null.");

            supportedMechanism.Add(mechanismName);

            if (Native.OQS_SIG_alg_is_enabled(mechanismName) == 1)
            {
                enabledMechanism.Add(mechanismName);
            }
        }

        SupportedMechanism = supportedMechanism.ToArray();
        EnabledMechanism = enabledMechanism.ToArray();
    }

    public Signature(string signatureAlgorithm)
    {
        if (!SupportedMechanism.Contains(signatureAlgorithm)) throw new MechanismNotSupportedException(signatureAlgorithm);
        if (!EnabledMechanism.Contains(signatureAlgorithm)) throw new MechanismNotEnabledException(signatureAlgorithm);

        _signaturePtr = Native.OQS_SIG_new(signatureAlgorithm);
        if (_signaturePtr == IntPtr.Zero) throw new OpenQuantumSafeException($"Not enough memory to create {signatureAlgorithm} instance.");

        _signature = Marshal.PtrToStructure<Native.OQS_SIG>(_signaturePtr);
    }

    ~Signature()
    {
        ReleaseUnmanagedResources();
    }

    /// <summary>
    /// Keypair generation algorithm.
    /// </summary>
    /// <param name="publicKey">The public key represented as a byte string.</param>
    /// <param name="secretKey">The secret key represented as a byte string.</param>
    public void GenerateKeypair(out byte[] publicKey, out byte[] secretKey)
    {
        if (_signaturePtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(Signature));

        publicKey = new byte[PublicKeyLength];
        secretKey = new byte[SecretKeyLength];

        var result = _signature.GenerateKeypair(ref Unsafe.AsRef(publicKey[0]), ref Unsafe.AsRef(secretKey[0]));
        if (result != Status.Success) throw new OpenQuantumSafeException(result);
    }

    /// <summary>
    /// Keypair generation algorithm.
    /// </summary>
    /// <param name="publicKey">The public key represented as a byte string.</param>
    /// <param name="secretKey">The secret key represented as a byte string.</param>
    public void GenerateKeypair(Span<byte> publicKey, Span<byte> secretKey)
    {
        if (_signaturePtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(Signature));
        
        var result = _signature.GenerateKeypair(ref MemoryMarshal.GetReference(publicKey), ref MemoryMarshal.GetReference(secretKey));
        if (result != Status.Success) throw new OpenQuantumSafeException(result);
    }

    /// <summary>
    /// Signature generation algorithm.
    /// </summary>
    /// <param name="signature">The signature on the message represented as a byte string.</param>
    /// <param name="message">The message to sign represented as a byte string.</param>
    /// <param name="secretKey">The secret key represented as a byte string.</param>
    public void Sign(out byte[] signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey)
    {
        if (_signaturePtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(Signature));

        signature = new byte[SignatureLength];
        var signatureLength = (nuint) 0;

        var result = _signature.Sign(ref Unsafe.AsRef(signature[0]), ref signatureLength, MemoryMarshal.GetReference(message), (nuint) message.Length, MemoryMarshal.GetReference(secretKey));
        if (result != Status.Success) throw new OpenQuantumSafeException(result);
        if (signatureLength == SignatureLength) return;

        Array.Resize(ref signature, (int) signatureLength);
    }

    /// <summary>
    /// Signature generation algorithm.
    /// </summary>
    /// <param name="signature">The signature on the message represented as a byte string.</param>
    /// <param name="message">The message to sign represented as a byte string.</param>
    /// <param name="secretKey">The secret key represented as a byte string.</param>
    /// <returns>Length of the signature.</returns>
    public int Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey)
    {
        if (_signaturePtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(Signature));

        var signatureLength = (nuint) 0;

        var result = _signature.Sign(ref MemoryMarshal.GetReference(signature), ref signatureLength, MemoryMarshal.GetReference(message), (nuint) message.Length, MemoryMarshal.GetReference(secretKey));
        if (result != Status.Success) throw new OpenQuantumSafeException(result);

        return (int) signatureLength;
    }

    /// <summary>
    /// Signature verification algorithm.
    /// </summary>
    /// <param name="message">The message represented as a byte string.</param>
    /// <param name="signature">The signature on the message represented as a byte string.</param>
    /// <param name="publicKey">The public key represented as a byte string.</param>
    /// <returns>Success or Error</returns>
    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (_signaturePtr == IntPtr.Zero) throw new ObjectDisposedException(nameof(Signature));

        var result = _signature.Verify(MemoryMarshal.GetReference(message), (nuint) message.Length, MemoryMarshal.GetReference(signature), (nuint) signature.Length, MemoryMarshal.GetReference(publicKey));

        return result switch
        {
            Status.Success => true,
            Status.Error => false,
            Status.ExternalLibErrorOpenSsl => false,
            var _ => throw new ArgumentOutOfRangeException()
        };
    }

    private void ReleaseUnmanagedResources()
    {
        Native.OQS_SIG_free(_signaturePtr);
        _signaturePtr = IntPtr.Zero;
    }

    public void Dispose()
    {
        ReleaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }
}