using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using MetroFramework;

namespace DB_Editor
{
    public partial class AddNewSignatureForm : MetroFramework.Forms.MetroForm
    {
        public bool Add;
        public byte[] signature;

        public AddNewSignatureForm()
        {
            InitializeComponent();

            //Добавление типов вирусов в комбоБокс
            for(byte type = (byte)VirusType.Trojan; type < (byte)VirusType.Unknown; type++)
            {
                this.TypeComboBox.Items.Add(((VirusType)type).ToString());
            }
        }

        private void metroButton1_Click(object sender, EventArgs e)
        {
            if(TypeComboBox.Text.Length < 3)
            {
                MetroMessageBox.Show(this, "Выберите тип вируса!");
                return;
            }

            if(this.metroTextBox_NAME.Text.Length < 3)
            {
                MetroMessageBox.Show(this, "Слишком короткое название!");
                return;
            }

            if (this.metroTextBox3.Text.Length < 8)
            {
                MetroMessageBox.Show(this, "Слишком короткая сигнатура!");
                return;
            }

            {
                string[] stringBytes = this.metroTextBox3.Text.Split(' ');
                signature = new byte[stringBytes.Length];

                for(int b = 0; b < signature.Length; b++)
                {
                    try
                    {
                        signature[b] = Convert.ToByte(stringBytes[b], 16);
                    }
                    catch(Exception ex)
                    {
                        MetroMessageBox.Show(this, "Произошла ошибка при проверке сигнатуры\n" + ex.Message);
                        return;
                    }
                }
            }

            Add = true;
            this.Close();
        }

        private void metroButton2_Click(object sender, EventArgs e)
        {
            Add = false;
            this.Close();
        }
    }
}
