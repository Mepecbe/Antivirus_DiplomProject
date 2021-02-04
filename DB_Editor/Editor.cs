using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using Tulpep.NotificationWindow;

namespace DB_Editor
{
    public partial class Editor : MetroFramework.Forms.MetroForm
    {
        public Editor()
        {
            InitializeComponent();
        }

        private void Editor_Shown(object sender, EventArgs e)
        {
            SignaturesDB.UpdateList(this.metroListView1);
        }

        private void добавитьToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var form = new AddNewSignatureForm();

            form.metroTextBox_ID.Text = SignaturesDB.genId().ToString();
            form.ShowDialog();

            if (form.Add)
            {
                SignaturesDB.Add(
                    byte.Parse(form.metroTextBox_ID.Text),
                    form.metroTextBox_NAME.Text,
                    form.signature
                    );

                SignaturesDB.UpdateList(this.metroListView1);
                btn_ApplyChanges.Visible = true;
            }
        }

        private void metroButton1_Click(object sender, EventArgs e)
        {
            {
                SignaturesDB.Save();
                SignaturesDB.DBFile.Close();
            }

            {
                var notify = new PopupNotifier();
                notify.TitleText = "DB Editor";
                notify.ContentText = "Изменения сохранены";
                notify.Popup();
            }

            this.Close();
        }

        private void удалитьToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (this.metroListView1.SelectedItems.Count == 0)
            {
                return;
            }

            var item = this.metroListView1.SelectedItems[0];

            SignaturesDB.Delete(byte.Parse(item.SubItems[0].Text));
            SignaturesDB.UpdateList(this.metroListView1);

            btn_ApplyChanges.Visible = true;
        }

        private void Editor_FormClosing(object sender, FormClosingEventArgs e)
        {
            SignaturesDB.Close();
        }
    }
}
