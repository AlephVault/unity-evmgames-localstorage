using System.IO;
using Newtonsoft.Json;
using UnityEngine;

namespace AlephVault.Unity.EVMGames.LocalStorage
{
    namespace Samples
    {
        using Types;
        
        public class Sample : MonoBehaviour
        {
            // Start is called before the first frame update
            void Start()
            {
                AccountBox box = new AccountBox();
                box.SetEncrypted("0000000000000000000000000000000000000000000000000000000000000005", "Hello");
                Debug.Log(box.EncryptedPrivateKey);
                string recovered = box.Recover("Hello");
                Debug.Log($"{recovered}, {recovered.Length}");
        
                LocalSettings newSettings = LocalSettings.MakeEmpty();
                TextWriter textWriter = new StringWriter();
                JsonSerializer.Create().Serialize(textWriter, newSettings);
                Debug.Log(textWriter.ToString());
            }
        }
    }
}
