using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Nethereum.Hex.HexConvertors.Extensions;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace AlephVault.Unity.EVMGames.LocalStorage
{
    namespace Types
    {
        /// <summary>
        ///   This is a locally stored account.
        ///   It contains an encrypted private key.
        /// </summary>
        public class AccountBox
        {
            [JsonProperty("private_key")]
            private string encryptedPrivateKey;

            /// <summary>
            ///   The encrypted private key.
            /// </summary>
            [JsonIgnore]
            public string EncryptedPrivateKey => encryptedPrivateKey;

            // The order of the elliptic curve used here.
            private static BigInteger ECOrder = BigInteger.Parse(
                "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".ToLower(),
                NumberStyles.AllowHexSpecifier
            );
            
            // Parses and validates the private key from a
            // 0x... (64 digits) hexadecimal string.
            private static BigInteger ParsePrivateKey(string privateKey)
            {
                if (privateKey == null)
                {
                    throw new ArgumentNullException(nameof(privateKey));
                }

                BigInteger privateKeyValue;
                try
                {
                    privateKeyValue = BigInteger.Parse("0" + privateKey, NumberStyles.AllowHexSpecifier);
                    if (privateKeyValue.CompareTo(1) < 0 || privateKeyValue.CompareTo(ECOrder) >= 0)
                    {
                        throw new Exception();
                    }
                }
                catch (Exception e)
                {
                    throw new ArgumentException("Invalid private key");
                }

                return privateKeyValue;
            }

            // Hashes the non-null passphrase (passphrases are always
            // mandatory, even if "", to encrypt).
            private static byte[] HashPassphrase(string passphrase)
            {
                using SHA256 sha256Hash = SHA256.Create();
                return sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
            }

            // Encrypts the private key using a passphrase.
            private static byte[] Symmetric(
                byte[] privateKeyBytes, byte[] passphraseKeyBytes, bool forEncryption = true
            )
            {
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new AesEngine());
                cipher.Init(forEncryption, new KeyParameter(passphraseKeyBytes));
                byte[] result = cipher.DoFinal(privateKeyBytes);
                return result;
            }

            /// <summary>
            ///   Stores the private key and encrypts it using a passphrase.
            /// </summary>
            /// <param name="privateKey">The private key to encrypt</param>
            /// <param name="passphrase">The passphrase to use</param>
            /// <exception cref="ArgumentNullException">The private key is null</exception>
            /// <exception cref="ArgumentException">The private key has the wrong format</exception>
            public void SetEncrypted(string privateKey, string passphrase)
            {
                BigInteger privateKeyValue = ParsePrivateKey(privateKey);
                byte[] rawPrivateKeyBytes = privateKeyValue.ToByteArray();
                byte[] paddedPrivateKeyBytes = new byte[64];
                Array.Copy(
                    rawPrivateKeyBytes, 0, 
                    paddedPrivateKeyBytes, 64 - rawPrivateKeyBytes.Length,
                    rawPrivateKeyBytes.Length
                );
                byte[] passphraseKeyBytes = HashPassphrase(passphrase ?? "");
                encryptedPrivateKey = Symmetric(paddedPrivateKeyBytes, passphraseKeyBytes).ToHex();
            }

            /// <summary>
            ///   Recovers the stored private key by decrypting the message
            ///   properly (using a given passphrase). If the returned key
            ///   is not plausible, then a proper exception will be raised.
            /// </summary>
            /// <param name="passphrase">The passphrase to use for decryption</param>
            /// <exception cref="ArgumentException">The provided passphrase is not plausible</exception>
            /// <exception cref="InvalidOperationException">The is no currently encrypted key</exception>
            /// <returns>The private key, in 0x... format</returns>
            public string Recover(string passphrase)
            {
                if (string.IsNullOrEmpty(encryptedPrivateKey))
                {
                    throw new InvalidOperationException("No value is set in this box");
                }
                
                byte[] passphraseKeyBytes = HashPassphrase(passphrase ?? "");
                string decryptedValue = Symmetric(
                    encryptedPrivateKey.HexToByteArray(), passphraseKeyBytes, false
                ).ToHex();
                string decryptedPrivateKey = decryptedValue.Substring(
                    decryptedValue.Length - 64, 64
                );
                BigInteger parsedPrivateKey = BigInteger.Parse(
                    "0" + decryptedPrivateKey, NumberStyles.AllowHexSpecifier
                );
                if (parsedPrivateKey.CompareTo(1) < 0 || parsedPrivateKey.CompareTo(ECOrder) >= 0)
                {
                    throw new ArgumentException("Passphrase not plausible");
                }

                return decryptedPrivateKey;
            }
        }
    }
}
