using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

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

    class Communicator
    {
        

        public Int32 port_listen { get; set; }

        public Int32 port_send { get; set; }

        public String ip { get; set; }

        public String send_ip { get; set; }
        public CipherMode mode { get; set; }
        public bool session_key { get; set; }

        public int listening { get; set; }
        public bool port_taken { get; set; }
        public bool listen { get; set; }

        Byte[] aes_key { get; set; } = new Byte[32];
        Byte[] aes_IV { get; set; } = new Byte[16];

        TcpListener server = null;

        Thread listener = null;

        public Communicator()
        {
            port_listen = 10000;
            port_send = 11000;

            ip = "127.0.0.1";
            send_ip = "127.0.0.1";
            session_key = false;
            port_taken = false;

            mode = CipherMode.CBC; //CipherMode.ECB

            //aes_key = new Byte[32];
            //aes_IV = new Byte[16];
            listen = false;
            server = null;

            //setup keys
            Aes aes = Aes.Create();
            aes_IV = aes.IV;
            aes_key = aes.Key;
        }


        public void SendEncryptedText(string text)
        {
            try
            {
                
                Send(new Frame(2, Encrypt(text, aes_key, aes_IV)));
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10061))
                {
                    MessageBox.Show("Cannot connect to client! \n " + e);
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }
        }

        public void Send(Frame data) 
        {
            try
            {
                Int32 port = port_send;
                using TcpClient client = new TcpClient(send_ip, port);

                NetworkStream stream = client.GetStream();

                IFormatter formatter = new BinaryFormatter();

                formatter.Serialize(stream, data);
                
                //old
                //stream.Write(data, 0, data.Length);
            }
            catch (ArgumentNullException e)
            {

                Console.WriteLine("ArgumentNullException: {0}", e);
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10061))
                {
                    //MessageBox.Show("Cannot connect to client! \n " + e);
                    //ZMIENIC NA JAKIES LOGI / STATUS BAR
                    throw;
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                    throw;
                }
                
            }

        }

        public void SendSessionKeyAndIV()
        {
            Byte[] aes_key_IV = new Byte[48];
            aes_IV.CopyTo(aes_key_IV, 32);
            aes_key.CopyTo(aes_key_IV, 0);

            Frame frame = new Frame(1,aes_key_IV);

            //MessageBox.Show("Send session key and IV.");
            try {
                //encrypt
                Send(frame);
            }
            catch (SocketException e)
            {
                //didnt connect
                session_key = false;
                return;
            }


            listening = 2;
            session_key = true;

            //if (server != null && server.Server.IsBound)     IF multiple listeners
            //    server.Stop();  //stop listening for key 


            //if (key_listener != null && key_listener.IsAlive)
            //    key_listener.Join();
        }

 
        public void StopListening()
        {
            //stop listening for keys or messages
            session_key = false;
            listen = false;
            if (server != null)
                server.Stop();
            //StopListeningKey();
            //StopListeningMsg();

            

            //server = null;
            port_taken = false;
            listening = 0;
        }

 

        public void StartListener(Grid grid)
        {
            
            listen = true;
            listener = new Thread(new ThreadStart(() => Listener(grid)));
            listener.Start();
        }

        /// <summary>
        /// ////////////////////////////////////////////////////////////////////////////////////
        /// </summary>
        /// <param name="grid"></param>
        //private void Listener(Grid grid)
        //{
        //    while (listen) {
        //        StartServer();

        //        if (server != null && !port_taken)
        //            SessionKeyListener();

        //        if (server != null && session_key)
        //            MessageListener(grid);
        //    }
        //}
        /// ////////////////////////////////////////////////////////////////////////////////////
        private void StartServer()
        {
            if (server != null)
                server.Stop();
            server = new TcpListener(IPAddress.Parse(ip), port_listen);
        }


        private void Listener(Grid messageBox)
        {
            StartServer();
            try
            {
                listening = 1;
                server.Start();
                IFormatter formatter = new BinaryFormatter();

                while (listen)
                {

                 

                    using TcpClient client = server.AcceptTcpClient();
                    NetworkStream sender_stream = client.GetStream();


                    Frame frame = (Frame)formatter.Deserialize(sender_stream);

                    if (frame.type == 1)
                    {

                        Array.Copy(frame.content, 0, aes_key, 0, 32);
                        Array.Copy(frame.content, 32, aes_IV, 0, 16);

                        session_key = true;
                        listening = 2;
                        //MessageBox.Show("Received session key and IV.");
                        Console.WriteLine("Received session key and IV.");
                    }

                    else if (frame.type == 2)
                    {
                        String data = "";
                        try
                        {

                            Byte[] cipherText = new byte[frame.content.Length];
                            Array.Copy(frame.content, cipherText, frame.content.Length);

                            data += Decrypt(cipherText, aes_key, aes_IV);
                        }
                        catch (CryptographicException e)
                        {
                            MessageBox.Show("Crpyto Error");
                        }

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
                    MessageBox.Show("Port is unavailable: " + e);
                    port_taken = true;
                    //throw;
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }
            finally
            {
                server.Stop();
                listening = 0;
            }
        }


        private void SessionKeyListener()
        {
            if (session_key)
                return;

            try
            {
                listening = 1;
                server.Start();
                Byte[] bytes = new Byte[48];

                while (session_key == false) {

                    Console.Out.WriteLine("Waiting for Key...");
                    using TcpClient client = server.AcceptTcpClient();
                    NetworkStream sender_stream = client.GetStream();

                    //int i;

                    IFormatter formatter = new BinaryFormatter();
                    Frame frame = (Frame)formatter.Deserialize(sender_stream);

                    //while ((i = sender_stream.Read(bytes, 0, bytes.Length)) != 0)
                    //{
                    //    if (i == 48)
                    //    {
                    if (frame.type == 1) { 

                        Array.Copy(frame.content, 0, aes_key, 0, 32);
                        Array.Copy(frame.content, 32, aes_IV, 0, 16);

                        session_key = true;

                        MessageBox.Show("Received session key and IV.");
                        Console.WriteLine("Received session key and IV.");
                    }
                    else
                    {
                        Console.WriteLine("Dismissed Packets");
                    }
                    //}
                }
            }
            catch (SocketException e){
                if (e.ErrorCode.Equals(10004)){
                    Console.WriteLine("Key Listener Stopped");
                }
                else if (e.ErrorCode.Equals(10048))
                {
                    MessageBox.Show("Port is unavailable: " + e);
                    port_taken = true;
                    throw;
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }
            finally {
                server.Stop();
                listening = 0;
            }
        }

        public void MessageListener(Grid messageBox)
        {
            //key_listener.Join();
            if (session_key == false)
                return;

            try
            {
                listening = 2;
                server.Start();
                Console.WriteLine("Start Listening");

                Byte[] bytes = new Byte[512];
                String data = "";


                while (session_key)
                {
                    using TcpClient client = server.AcceptTcpClient();
                    data = null;
                    NetworkStream sender_stream = client.GetStream();
                    //int i;
                    //while ((i = sender_stream.Read(bytes, 0, bytes.Length)) != 0)
                    //{


                    IFormatter formatter = new BinaryFormatter();
                    Frame frame = (Frame)formatter.Deserialize(sender_stream);
                    if (frame.type == 2)
                    {
                        try
                        {

                            Byte[] byte_ = new byte[frame.content.Length];
                            Array.Copy(frame.content, byte_, frame.content.Length);

                            data += Decrypt(frame.content, aes_key, aes_IV);
                        }
                        catch (CryptographicException e)
                        {
                            MessageBox.Show("Crpyto Error");
                        }
                        //}

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
                    }
                }
            }
            catch (SocketException e)
            {
                if (e.ErrorCode.Equals(10004))
                {
                    Console.WriteLine("Msg Listener Stopped");
                }
                else if (e.ErrorCode.Equals(10048))
                {
                    port_taken = true;
                    MessageBox.Show("Port is unavailable: " + e);
                    throw;
                }
                else
                {
                    MessageBox.Show("SocketException: " + e);
                }
            }
            finally
            {
                server.Stop();
                listening = 0;
            }
        }


        private byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {

            byte[] encrypted;
            // Create an Rijndael object
            // with the specified key and IV.
            using (Aes rijAlg = Aes.Create())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                rijAlg.Mode = mode;
                
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

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

        private string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");

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

    }
}
