using System;
using System.Linq;
using System.Numerics;
using NBitcoin;
using Newtonsoft.Json;
using AlephVault.Unity.EVMGames.Vendor.Nethereum.HdWallet;
using Nethereum.Web3.Accounts;

namespace AlephVault.Unity.EVMGames.LocalStorage
{
    namespace Types
    {
        /// <summary>
        ///   This is a list of local boxes.
        ///   See <see cref="AccountBox" /> for more details.
        /// </summary>
        public class LocalSettings
        {
            // This is a fixed amount of different boxes.
            public const int NumBoxes = 64;

            // This is a fixed passphrase used to initialize fake settings.
            private const string FakePassphrase = "Passphrase for random initialization";

            // Each account is stored here.
            [JsonProperty("account_boxes")]
            private AccountBox[] accountBoxes;

            /// <summary>
            ///   Retrieves one of the account boxes.
            /// </summary>
            /// <param name="index">The index of the box to retrieve</param>
            public AccountBox this[int index]
            {
                get
                {
                    CheckItHasAccountBoxes();
                    return accountBoxes[index];
                }
            }

            private void CheckItHasAccountBoxes()
            {
                if (accountBoxes == null)
                    throw new InvalidOperationException(
                        "The account boxes are not initialized. This operation " +
                        "is only valid for de-serialized LocalSettings instances and " +
                        "for instances created via MakeEmpty()"
                    );
            }

            /// <summary>
            ///   Makes an almost-truly random private key.
            /// </summary>
            private static string MakeRandomPrivateKey()
            {
                RNGCryptoServiceProviderRandom rng = new RNGCryptoServiceProviderRandom();
                byte[] randomBytes = new byte[4];
                rng.GetBytes(randomBytes);
                int index = BitConverter.ToInt32(randomBytes, 0) & 0x7FFFFFFF;
                return new Wallet(Wordlist.English, WordCount.TwentyFour).GetAccount(index).PrivateKey.Substring(2);
            }

            /// <summary>
            ///   Creates a new, random-filled, set of local settings.
            /// </summary>
            /// <returns>The new local settings</returns>
            public static LocalSettings MakeEmpty()
            {
                LocalSettings settings = new LocalSettings();
                settings.accountBoxes = Enumerable.Range(1, NumBoxes).Select(_ => new AccountBox()).ToArray();
                foreach (AccountBox box in settings.accountBoxes)
                {
                    box.SetEncrypted(MakeRandomPrivateKey(), FakePassphrase);
                }

                return settings;
            }

            /// <summary>
            ///   Sets, in the box, a new private key which is encrypted
            ///   by the given passphrase. WARNING: THE PREVIOUS KEY IS
            ///   LOST FOREVER, IF ANY.
            /// </summary>
            /// <param name="boxIndex">The box index</param>
            /// <param name="privateKey">The private key</param>
            /// <param name="passphrase">The passphrase</param>
            /// <exception cref="InvalidOperationException">The boxes are not set</exception>
            /// <exception cref="ArgumentNullException">The private key is null</exception>
            /// <exception cref="ArgumentException">The private key has the wrong format</exception>
            public void SetEncrypted(int boxIndex, string privateKey, string passphrase)
            {
                CheckItHasAccountBoxes();
                accountBoxes[boxIndex].SetEncrypted(privateKey, passphrase);
            }

            /// <summary>
            ///   Completely destroys the data in the current box, thus
            ///   leaving this box with garbage. WARNING: THE PREVIOUS
            ///   KEY IS LOST FOREVER, IF ANY.
            /// </summary>
            /// <param name="boxIndex">The vox index</param>
            public void Reset(int boxIndex)
            {
                SetEncrypted(boxIndex, MakeRandomPrivateKey(), FakePassphrase);
            }

            /// <summary>
            ///   Tries to recover the local account private key.
            ///   Either the account is retrieved successfully, or
            ///   a random account is retrieved due to bad decryption,
            ///   or an error is raised due to non-plausibility of
            ///   the chosen key for the currently encrypted value.
            /// </summary>
            /// <param name="boxIndex">The box index</param>
            /// <param name="passphrase">The passphrase</param>
            /// <param name="chainId">The optional chain id</param>
            /// <exception cref="InvalidOperationException">
            ///   The is no currently encrypted key in the chosen box,
            ///   or the boxes are not set
            /// </exception>
            /// <exception cref="ArgumentException">
            ///   The provided passphrase is not plausible for the chosen box
            /// </exception>
            /// <returns>The recovered key</returns>
            public Account Recover(int boxIndex, string passphrase, BigInteger? chainId = null)
            {
                CheckItHasAccountBoxes();
                return new Account(accountBoxes[boxIndex].Recover(passphrase), chainId);
            }
        }
    }
}
