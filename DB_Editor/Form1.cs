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

using System.IO;


namespace DB_Editor
{
    public partial class Form1 : MetroFramework.Forms.MetroForm
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void metroTile2_Click(object sender, EventArgs e)
        {
            var res = openFileDialog1.ShowDialog();

            if (res == DialogResult.OK)
            {
                try
                {
                    SignaturesDB.Path = openFileDialog1.FileName;
                    SignaturesDB.DBFile = File.Open(openFileDialog1.FileName, FileMode.Open, FileAccess.ReadWrite);
                    SignaturesDB.Load();

                    new Editor().ShowDialog();
                }
                catch (Exception ex)
                {
                    MetroMessageBox.Show(this, "Ошибка открытия файла\n" + ex.Message);
                }
            }
        }

        private void metroTile1_Click(object sender, EventArgs e)
        {
            saveFileDialog1.FileName = "newDB.db";
            var result = saveFileDialog1.ShowDialog();

            if(result == DialogResult.OK)
            {
                SignaturesDB.Path = saveFileDialog1.FileName;
                SignaturesDB.DBFile = File.Create(saveFileDialog1.FileName);

                new Editor().ShowDialog();
            }
        }
    }

    public static class SignaturesDB
    {
        public static string Path;
        public static FileStream DBFile;

        public static List<VirusInfo> Signatures = new List<VirusInfo>();
        private static Random Gen = new Random();

        public static void Load()
        {
            var reader = new BinaryReader(DBFile);

            while(DBFile.Position < DBFile.Length)
            {
                byte id = reader.ReadByte();
                byte[] signature = reader.ReadBytes(reader.ReadByte());
                string name = reader.ReadString();

                Signatures.Add(new VirusInfo(id, signature, name));
            }
        }

        public static VirusInfo getById(byte id)
        {
            for(int index = 0; index < Signatures.Count; index++)
            {
                if(Signatures[index].ID == id)
                {
                    return Signatures[index];
                }
            }

            return null;
        }

        public static byte genId()
        {
            return Convert.ToByte(Gen.Next(10, 255));
        }

        public static void UpdateList(ListView list, string baseNameText = "          ")
        {
            list.Items.Clear();

            foreach (VirusInfo info in SignaturesDB.Signatures)
            {
                var item = list.Items.Add(info.ID.ToString());
                item.SubItems.Add(baseNameText + info.Name);

                string signature = string.Empty;
                foreach (byte b in info.Signature)
                {
                    signature += b < 0xF ? "0" : "" + Convert.ToString(b, 16) + " ";
                }

                item.SubItems.Add(signature);
            }
        }

        public static void Update(byte id, string name, byte[] signature)
        {
            var sig = getById(id);
            sig.Name = name;
            sig.Signature = signature;
        }

        public static void Add(byte id, string name, byte[] signature)
        {
            Signatures.Add(new VirusInfo(id, signature, name));            
        }

        public static int GetDBSize()
        {
            int size = 0;

            foreach(VirusInfo info in Signatures)
            {
                //ID, Длина сигнатуры, сигнатура, длина имени, имя
                size += 1 + 1 + info.Signature.Length + 1 + info.Name.Length;
            }

            return size;
        }

        public static void Save()
        {
            DBFile.Close();
            File.Delete(Path);

            DBFile = File.Create(Path);

            var Writer = new BinaryWriter(DBFile);

            foreach(VirusInfo info in Signatures)
            {
                Writer.Write(info.ID);

                Writer.Write(Convert.ToByte(info.Signature.Length));
                Writer.Write(info.Signature);

                Writer.Write(info.Name);

                Writer.Flush();
            }
        }

        public static void Delete(byte id)
        {
            for (int index = 0; index < Signatures.Count; index++)
            {
                if (Signatures[index].ID == id)
                {
                    Signatures.RemoveAt(index);
                    break;
                }
            }
        }

        public static void Close()
        {
            DBFile.Close();
            Signatures.Clear();
        }
    }

    public class VirusInfo
    {
        public byte ID;
        public byte[] Signature;
        public string Name;

        public VirusInfo(byte id, byte[] signatures, string name)
        {
            this.ID = id;
            this.Signature = signatures;
            this.Name = name;
        }
    }
}
