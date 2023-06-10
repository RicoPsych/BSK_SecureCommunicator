using Microsoft.Win32;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using static System.Net.Mime.MediaTypeNames;

namespace Communicator
{
    [Serializable]
    class Frame
    {
        public int type { get; set; }
        public byte[] content { get; set; }


        public Frame(int type, byte[] content)
        {
            this.type = type;
            this.content = content;
        }
    }
    [Serializable] //Add file name for sending more files at the same time??
    class FileFrame : Frame
    {
        public int order { get; set; }
//        public string name { get; set; }  
        public FileFrame(int type, byte[] content, int order) : base(type, content)
        {
            this.order = order;
        }
    }
    [Serializable]
    class FileInfoFrame : Frame
    {
        public int size { get; set; }
        public int size_bytes { get; set; }
        public string extension { get; set; }
        public string name { get; set; }    
        public FileInfoFrame(int type, byte[] content, int size, int size_bytes,string name, string extension) : base(type, content)
        {
            this.size = size;
            this.size_bytes = size_bytes;
            this.extension = extension;
            this.name = name;
        }
    }

    class Communicator
    {

        public String ip { get; set; }
        public Int32 port_listen { get; set; }

        public String send_ip { get; set; }
        public Int32 port_send { get; set; }


        SHA256 sha256 { get; set; }

        public String user { get; set; }
        public String password { get; set; }
        public String recipient { get; set; }
        RSA rsa;



        public bool session_key { get; set; }
        public int listening { get; set; }
        public bool port_taken { get; set; }
        public bool listen { get; set; }
        public bool loggedIn { get; set; }


        Byte[] recipient_key { get; set; } = new byte[32];
        Byte[] local_key { get; set; } = new byte[32];

        Byte[] aes_key { get; set; } = new Byte[32];
        Byte[] aes_IV { get; set; } = new Byte[16];
        public CipherMode mode { get; set; }

        TcpListener server = null;
        TcpClient sender = null;
        Thread listener = null;

        public Communicator()
        {
            port_listen = 10000;
            port_send = 11000;

            ip = "127.0.0.1";
            send_ip = "127.0.0.1";

            
            session_key = false;
            port_taken = false;

            loggedIn= false;
            mode = CipherMode.CBC; //CipherMode.ECB
            listen = false;
            server = null;

            rsa = RSA.Create();
            sha256 = SHA256.Create();

            //rsa.ExportParameters();

            //setup keys
            Aes aes = Aes.Create();
            aes_IV = aes.IV;
            aes_key = aes.Key;
        }


        public void Register() {

            //sha256.ComputeHash(Encoding.ASCII.GetBytes(user));
            if (Directory.Exists(Directory.GetCurrentDirectory() + "\\" + user))
            {
                return;
            }
        
            Directory.CreateDirectory(Directory.GetCurrentDirectory()+"\\"+user);

            byte[] pass_hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(password));//Set key
            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\pass", pass_hash);

            Aes aes = Aes.Create();

            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\IV", aes.IV);

            //Encode
            mode = CipherMode.CBC;  
            
            //byte[] privKey = Encrypt(rsa.ExportRSAPrivateKey(), pass_hash, aes.IV);
            //byte[] pubKey = rsa.ExportRSAPublicKey();

            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\privateKey", Encrypt(rsa.ExportRSAPrivateKey(), pass_hash, aes.IV));

            File.WriteAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\publicKey", rsa.ExportRSAPublicKey());

        }


        public void Login()
        {
            if (!Directory.Exists(Directory.GetCurrentDirectory() + "\\" + user) || password == null)
            {
                return;
            }
            byte[] input_pass = sha256.ComputeHash(Encoding.ASCII.GetBytes(password));
            byte[] real_pass/* = Encoding.ASCII.GetBytes();*/ = //new byte[32];
            File.ReadAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\pass");//.Read(real_pass, 0, 32);

            if (!input_pass.SequenceEqual(real_pass)){
                return;
            } 
            byte[] priv_key = File.ReadAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\privateKey");
            byte[] IV = File.ReadAllBytes(Directory.GetCurrentDirectory() + "\\" + user + "\\IV");

            //byte[] key = DecryptToBytes(priv_key, real_pass, IV);

            rsa = RSA.Create();

            local_key = DecryptToBytes(priv_key, real_pass, IV);
            int count;
            rsa.ImportRSAPrivateKey(local_key, out count);
            

            loggedIn = true;

            //Set flag
        }

        public void Logout()
        {

            StopListening();
            local_key = null;
            loggedIn = false;
        }

        public void ChangeRecipient()
        {
            if (!Directory.Exists(Directory.GetCurrentDirectory() + "\\" + recipient))
            {
                return;
            }
            recipient_key = File.ReadAllBytes(Directory.GetCurrentDirectory() + "\\" + recipient + "\\publicKey");
            
            int count; 
            rsa.ImportRSAPublicKey(recipient_key,out count);
        }



        public void Send(Frame data)
        {

            try
            {
                //sender = new TcpClient(send_ip, port_send);
                if (sender == null || sender.Client == null)
                {
                    MessageBox.Show("Sender is Null");

                    Console.WriteLine("Sender is Null");
//                    throw new Exception("Sender null");
                    return;
                }

                Thread.BeginCriticalRegion();
                NetworkStream stream = sender.GetStream();
                IFormatter formatter = new BinaryFormatter();
                formatter.Serialize(stream, data);//EXCEPTION WHEN SENDING WITHOUT CONNECTING
                Thread.EndCriticalRegion();
            }
            catch (IOException e)
            {
                MessageBox.Show("Recipient not listening");

                Console.WriteLine("IOException: {0}", e);
                //throw e;
            }
            catch (NullReferenceException e)
            {
                Console.WriteLine("NullReferenceException: {0}", e);
            }

            catch (ArgumentNullException e)
            {
                Console.WriteLine("ArgumentNullException: {0}", e);
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10061))
                {

                    //MessageBox.Show("Cannot connect to client!");
                    
                    //MessageBox.Show("Cannot connect to client! \n " + e);
                    //ZMIENIC NA JAKIES LOGI / STATUS BAR
                    throw e;
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                    throw e;
                }
                
            }
            
        }

        public void SendEncryptedText(string text)
        {

            if (!loggedIn)
            {
                MessageBox.Show("Not Logged In");
                return;
            }
            try
            {
                Send(new Frame(2, Encrypt(text, aes_key, aes_IV)));
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10061))
                {

                    MessageBox.Show("Cannot connect to client!");
//                    MessageBox.Show("Cannot connect to client! \n " + e);
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }
            catch(Exception e)
            {
                MessageBox.Show("sender null");
            }
        }

        public void ReceiveEncryptedFile(string name,string extension, byte[] part)
        {
            FileStream writeStream = File.OpenWrite(name + "encrypted." + extension);
            writeStream.Position = writeStream.Length;
            writeStream.Write(part);
            writeStream.Close();
            writeStream.Dispose();
        }

        public void ReadEncryptedFile(string name, string extension)
        {
            FileStream fileStream = File.OpenRead(name + "encrypted." + extension);
            FileStream writeStream = File.OpenWrite(name + "decrypted."+ extension);

            byte[] file_byte = new byte[fileStream.Length];
            byte[] enc_file_byte = null;


            while (fileStream.Read(file_byte) != 0)
            {
            }
            //writeStream.Write(DecryptToBytes(file_byte, aes_key, aes_IV));

            enc_file_byte = DecryptToBytes(file_byte, aes_key, aes_IV);

            //for (int i = 0; i < (int)Math.Round((double)enc_file_byte.Length / 256); i++)
            //{
            //    int size = Math.Min(256, enc_file_byte.Length - i * 256);

            //    writeStream.Write(enc_file_byte, i * 256, size);
            //}

            writeStream.Write(enc_file_byte);


            fileStream.Close();
            fileStream.Dispose();
            writeStream.Close();
            writeStream.Dispose();
            File.Delete(name + "encrypted." + extension);
        }


        public void SendFileInfo(int size,int size_bytes, string name, string ext)
        {
            if (!loggedIn)
            {
                MessageBox.Show("Not Logged In");
                return;
            }

            try
            {
                Send(new FileInfoFrame(3, null, size, size_bytes, name, ext));
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10061))
                {

                    MessageBox.Show("Cannot connect to client!");
                    //                    MessageBox.Show("Cannot connect to client! \n " + e);
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }

        }

        public void SendEncryptedFile(string path, ProgressBar progressBar)
        {
            if (!loggedIn)
            {
                MessageBox.Show("Not Logged In");
                return;
            }

            using FileStream fileStream = File.OpenRead(path);
            string ext = path.Split('.').Last();
            string name = path.Split('\\').Last();
            //using FileStream writeStream = File.OpenWrite(path + "enc."+path.Split('.').Last());
            byte[] file_byte = new byte[fileStream.Length];
            byte[] enc_file_byte = null;
            

            while (fileStream.Read(file_byte) != 0)
            {
            }
            //Send(new FileFrame(3, file_byte, 0, true, path.Split('.').Last()));
            fileStream.Close();
            fileStream.Dispose();



            enc_file_byte = Encrypt(file_byte, aes_key, aes_IV);

            int packetNum = (int)Math.Round((double)enc_file_byte.Length / 256);
            //******
            SendFileInfo(packetNum, enc_file_byte.Length, name, ext);
            //******
            //********Segmented
            for (int i = 0; i < packetNum; i++)
            {
                int size = Math.Min(256, enc_file_byte.Length - i * 256);

                progressBar.Dispatcher.Invoke(() =>
                {
                    progressBar.Value = (i* 100 / packetNum);
                });

                //SEND
                byte[] part = new byte[size];
                Array.Copy(enc_file_byte, i * 256, part, 0, size);
                Send(new FileFrame(4, part, i));
                //writeStream.Write(enc_file_byte, i * 256, size);
            }

            //********Whole
            //writeStream.Write(enc_file_byte);

        }

        public void SendSessionKeyAndIV()
        {
            if (!loggedIn)
            {
                MessageBox.Show("Not Logged In");
                return;
            }

            //Encrypt With RSA
            Byte[] aes_key_IV = new Byte[48];
            aes_IV.CopyTo(aes_key_IV, 32);
            aes_key.CopyTo(aes_key_IV, 0);

            ChangeRecipient();
            aes_key_IV = RSAEncryption(aes_key_IV, rsa.ExportParameters(false),false);
            //rsa.Encrypt(aes_key_IV,RSAEncryptionPadding.OaepSHA256);

            Frame frame = new Frame(1, aes_key_IV);
            //MessageBox.Show("Send session key and IV.");
            try {
                //encrypt
                Send(frame);
                listening = 2;
                session_key = true;
            }
            catch (SocketException e )
            {

                //didnt connect
                session_key = false;
                return;
            }

        }

 
        public void StopListening()//Disconnecting causes some problems with rsa private key decryption.
        {
            //stop listening for keys or messages
            session_key = false;
            listen = false;
            if (server != null)
                server.Stop();
            //server = null;

            aes_key = null;
            aes_IV = null;

            port_taken = false;

            if (sender != null)
            {
                sender.Close();
                sender.Dispose();
            }
            sender = null;
            //*********** ????????????????? private key reset?
            int count;
            rsa.ImportRSAPrivateKey(local_key, out count); //
        }

 

        public void StartListener(Grid grid, ProgressBar DownloadProgressBar)
        {
            if (!loggedIn)
            {
                MessageBox.Show("Not Logged In");
                return;
            }

            Aes aes = Aes.Create();
            aes_IV = aes.IV;
            aes_key = aes.Key;

            listen = true;
            listener = new Thread(new ThreadStart(() => Listener(grid, DownloadProgressBar)));
            listener.Start();
            try
            {
                sender = new TcpClient(send_ip, port_send);
            } catch (SocketException e)
            {
                MessageBox.Show("Recipient not found");
            }
        }

        private void StartServer()
        {
            if (server != null)
                server.Stop();
            server = new TcpListener(IPAddress.Parse(ip), port_listen);
        }


        private void Listener(Grid messageBox, ProgressBar progressBar)
        {
            StartServer();
            try
            {
                listening = 1;
                server.Start();
                IFormatter formatter = new BinaryFormatter();
                string file_name = "";
                string extension = "";
                int last_packet = -1;
                //start listening 
                using TcpClient client = server.AcceptTcpClient();
                using NetworkStream sender_stream = client.GetStream();
                while (listen && client != null )
                {
                    Frame frame = null;
                    try
                    {
                        frame = (Frame)formatter.Deserialize(sender_stream);
                    }
                    catch (SerializationException ex) {
                        Console.WriteLine(ex.ToString());
                    }

                    if (!listen)
                    {
                        break;
                    }

                    if (frame == null )
                    {
                        continue;
                    }

                    else if (frame.type == 1) //Receive key and IV
                    {
                        try
                        {
                            //Decrypt recieved key and IV
                            frame.content = RSADecryption(frame.content, rsa.ExportParameters(true), false); 
                                //rsa.Decrypt(frame.content, RSAEncryptionPadding.OaepSHA256);
                            //Array.Copy(frame.content, 0, aes_key, 0, 32);
                            //Array.Copy(frame.content, 32, aes_IV, 0, 16);

                            //session_key = true;
                            //listening = 2;
                            ////MessageBox.Show("Received session key and IV.");
                            //Console.WriteLine("Received session key and IV.");
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show("Different recipient");
                            continue;
                        }
                        Thread.BeginCriticalRegion();
                        Array.Copy(frame.content, 0, aes_key, 0, 32);
                        Array.Copy(frame.content, 32, aes_IV, 0, 16);
                        session_key = true;
                        listening = 2;

                        Thread.EndCriticalRegion();
                        //MessageBox.Show("Received session key and IV.");
                        Console.WriteLine("Received session key and IV.");
                    }
                    else if (frame.type == 2) //Receive MSG
                    {
                        String data = "";
                        try
                        {
                            Byte[] cipherText = new byte[frame.content.Length];
                            Array.Copy(frame.content, cipherText, frame.content.Length);

                            data += Decrypt(cipherText, aes_key, aes_IV);
                            Thread.BeginCriticalRegion();
                            messageBox.Dispatcher.Invoke(() =>
                            {
                                RowDefinition rowdef = new RowDefinition();
                                rowdef.MinHeight = 0.1;
                                messageBox.RowDefinitions.Add(new RowDefinition());

                                TextBlock message = new TextBlock();
                                message.Text = data;
                                message.TextAlignment = System.Windows.TextAlignment.Left;
                                message.TextWrapping = System.Windows.TextWrapping.Wrap;
                                message.VerticalAlignment = System.Windows.VerticalAlignment.Top;
                                message.Background = new SolidColorBrush(Colors.LightCyan);

                                Grid.SetRow(message, messageBox.RowDefinitions.Count - 1);
                                Grid.SetColumn(message, 0);
                                messageBox.Children.Add(message);
                            });
                            Thread.EndCriticalRegion();
                        }
                        catch (CryptographicException e)
                        {
                            MessageBox.Show("Crpyto Error");
                        }
                        //catch( ArgumentNullException e)
                        //{
                        //    //MessageBox.Show("Null Error");
                        //}
                    }
                    else if (frame.type == 3)//Receive FileInfo
                    {
                        file_name = ((FileInfoFrame)frame).name;
                        extension = ((FileInfoFrame)frame).extension;
                        last_packet = ((FileInfoFrame)frame).size - 1;

                        SaveFileDialog saveFileDialog = new SaveFileDialog();
                        saveFileDialog.DefaultExt = extension;
                        saveFileDialog.FileName = file_name;
                        if (saveFileDialog.ShowDialog() == true)
                        {
                            file_name = saveFileDialog.FileName;
                        }
                    }
                    else if (frame.type == 4) //Receive File
                    {
                        ReceiveEncryptedFile(file_name, extension, frame.content);

                        Thread.BeginCriticalRegion();
                        progressBar.Dispatcher.Invoke(() =>
                        {
                            progressBar.Value = ((FileFrame)frame).order * 100 / last_packet;
                        });
                        Thread.EndCriticalRegion();
                        //(FileInfoFrame)frame;
                        if (((FileFrame)frame).order == last_packet)
                        {
                            ReadEncryptedFile(file_name, extension);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Dismissed Packets");
                    }
                }
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10004))
                {
                    Console.WriteLine("Listener Stopped");
                }
                else if (e.ErrorCode.Equals(10048))
                {
                    MessageBox.Show("Port is unavailable");
//                    MessageBox.Show("Port is unavailable: " + e);
                    //port_taken = true;
                    //throw;
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }
            finally
            {
                if(sender != null)
                    sender.Close();
                server.Stop();
                listening = 0;
                listen = false;
            }
        }


        private byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {

            byte[] encrypted;
            // Create an Rijndael object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                aesAlg.Mode = mode;
                
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                
                using (MemoryStream msEncrypt = new MemoryStream()) {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt)) {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        private byte[] Encrypt(byte[] plainText, byte[] Key, byte[] IV)
        {

            byte[] encrypted;
            // Create an Rijndael object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = mode;

                //ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV), CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainText);
                        csEncrypt.FlushFinalBlock();
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }


        private string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || cipherText.Length <= 0)
                throw new ArgumentNullException("key");
            if (IV == null || cipherText.Length <= 0)
                throw new ArgumentNullException("IV");


            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;


            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = mode;
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        private byte[] DecryptToBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");

            byte[] plainText = null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = mode;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(cipherText,0, cipherText.Length);
                        csDecrypt.FlushFinalBlock();     
                        //plainText = new byte[msDecrypt.Length];                        
                        plainText = msDecrypt.ToArray();
                    }
                }
            }
            return plainText;
        }


        static public byte[] RSAEncryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    encryptedData = RSA.Encrypt(Data, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        static public byte[] RSADecryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    decryptedData = RSA.Decrypt(Data, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

    }
}
