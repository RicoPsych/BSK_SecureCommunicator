using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Timers;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CommunicatorWPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        Communicator.Communicator communicator = new Communicator.Communicator();

        public MainWindow()
        {
            InitializeComponent();

            Timer statusUpdater = new Timer() ;
            statusUpdater.Elapsed += StatusBarUpdater;
            statusUpdater.Interval = 300;
            statusUpdater.Enabled = true;

        }

        private void SendText(object sender, RoutedEventArgs e)
        {
            RowDefinition rowdef = new RowDefinition(); 
            rowdef.MinHeight = 0.1;
            this.MessageBoxGrid.RowDefinitions.Add(new RowDefinition());

            TextBlock message = new TextBlock();

            message.MinHeight = 0.1;
            message.Text = this.SendBox.Text;
            message.TextAlignment = System.Windows.TextAlignment.Right;
            message.Background = new SolidColorBrush(Colors.Green);
            message.TextWrapping = System.Windows.TextWrapping.Wrap;
            message.VerticalAlignment = System.Windows.VerticalAlignment.Top;

            Grid.SetRow(message, MessageBoxGrid.RowDefinitions.Count-1);
            Grid.SetColumn(message, 1);
            this.MessageBoxGrid.Children.Add(message);

            this.MessageBoxScroll.ScrollToBottom();

            communicator.SendEncryptedText(this.SendBox.Text);

            this.SendBox.Text = "";
        }






        private void Connect(object sender, RoutedEventArgs e)
        {
            if(!communicator.listen)
                communicator.StartListener(MessageBoxGrid);
            
            communicator.SendSessionKeyAndIV();
        }
        private void Disconnect(object sender, RoutedEventArgs e)
        {
            communicator.StopListening();

//            communicator.StartListener(MessageBoxGrid); In main
  
            
            //    communicator.ListenForSessionKeyAndIV();
            //    communicator.ListenForMsg(this.MessageBoxGrid);
        }



        private void RadioButtonCBC(object sender, RoutedEventArgs e)
        {
            communicator.mode = System.Security.Cryptography.CipherMode.CBC;
        }

        private void RadioButtonECB(object sender, RoutedEventArgs e)
        {
            communicator.mode = System.Security.Cryptography.CipherMode.ECB;
        }

        private void IPSendChange(object sender, TextChangedEventArgs e)
        {
            communicator.send_ip = this.ip_send_box.Text;
        }
        private void IPListenChange(object sender, TextChangedEventArgs e)
        {
            communicator.ip = this.ip_listen_box.Text;
        }

        private void PortChange(object sender, TextChangedEventArgs e)
        {
            communicator.port_listen = Int32.Parse(this.port_listen_box.Text);
        }

        private void SenderPortChange(object sender, TextChangedEventArgs e)
        {
            communicator.port_send = Int32.Parse(this.port_send_box.Text);
        }

        private void StatusBarUpdater(object source, ElapsedEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                if (communicator.listening == 1)
                {
                    ListeningStatus.Background = new SolidColorBrush(Colors.Orange);
                }
                else if (communicator.listening == 2)
                {
                    ListeningStatus.Background = new SolidColorBrush(Colors.Green);
                }
                else
                {

                    ListeningStatus.Background = new SolidColorBrush(Colors.Red);
                }

                if (communicator.session_key)
                {
                    SessionStatus.Background = new SolidColorBrush(Colors.Green);
                }
                else
                {
                    SessionStatus.Background = new SolidColorBrush(Colors.Red);
                }
            });

        }
    }
}
