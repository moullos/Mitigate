using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Mitigate
{
    class NetworkRestrictionUtils
    {
        class TestFile
        {
            public string Url { get; set; }
            public string Hash { get; set; }
        }

        static Dictionary<string, TestFile> TestFiles = new Dictionary<string, TestFile>
        {
            {"chm", new TestFile {
                Url=@"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm",
                Hash="bf78b5f5223e2ab13c919bbcb023a18a362661701e2433abd29a3d8fde503735"
            } }
        };

        private static string ComputeSha256Hash(byte[] rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(rawData);

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
        public static bool IsFileTypeBlocked(string filetype)
        {
            if (!TestFiles.ContainsKey(filetype))
                throw new Exception(String.Format("Test file for filetype {0} not specified", filetype));

            TestFile FileInfo = TestFiles[filetype];
            byte[] FileContents;
            using (var w = new System.Net.WebClient())
            {
                try
                {
                    FileContents = w.DownloadData(FileInfo.Url);
                }
                catch (System.Net.WebException)
                {
                    return false;
                }
            }
            return !ComputeSha256Hash(FileContents).Equals(FileInfo.Hash);
        }
    }
}
