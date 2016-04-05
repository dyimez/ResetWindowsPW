using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using System.DirectoryServices;
using System.Diagnostics;
using System.Configuration;

namespace ResetWindowsPW
{
    public partial class Main : Form
    {
        private string _username = string.Empty;
        private string _password = string.Empty;
        private string _domainname = string.Empty;

        public Main()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string suser = txtUser.Text;

            if (string.IsNullOrEmpty(suser) == true)
                return;


            EncryptionMgr encryptionmgr = new EncryptionMgr();

            //debug
            string applicationName = Environment.GetCommandLineArgs()[0];

            //live
            //string applicationName = Environment.GetCommandLineArgs()[0] + ".exe";
        
            string exePath = System.IO.Path.Combine(Environment.CurrentDirectory, applicationName);
            System.Configuration.Configuration config = ConfigurationManager.OpenExeConfiguration(exePath);

            string configusername = config.AppSettings.Settings["user"].Value.ToString();
            string configpassword = config.AppSettings.Settings["password"].Value.ToString();
            string configdomainname = config.AppSettings.Settings["domain"].Value.ToString();
            string configisclosed = config.AppSettings.Settings["flag"].Value.ToString();

            _username = encryptionmgr.Decrypt(configusername);
            _password = encryptionmgr.Decrypt(configpassword);
            _domainname = encryptionmgr.Decrypt(configdomainname);

            //string sArg = " /C net user " + suser + " /domain /active:yes";
            string sArg = " /" + configisclosed + " net user " + suser + " /domain /active:yes";

            System.Security.SecureString ssPassword = new System.Security.SecureString();

            for (int x = 0; x < _password.Length; x++)
            {
                ssPassword.AppendChar(_password[x]);
            }

            ProcessStartInfo psInfo = new ProcessStartInfo("cmd", sArg);

            psInfo.CreateNoWindow = true;
            psInfo.UserName = _username;
            psInfo.Password = ssPassword;
            psInfo.Domain = _domainname;
            psInfo.UseShellExecute = false;

            Process process = new Process();
                
            process.StartInfo = psInfo;
            process.Start();
        }
    }
}
