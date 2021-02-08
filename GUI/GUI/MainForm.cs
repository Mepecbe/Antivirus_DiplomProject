﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;

using MetroFramework.Forms;
using Tulpep.NotificationWindow;
using API_Client_Library;

using GUI.Components.ScanManager;
using GUI.Components.Configurations;

namespace GUI
{
    public partial class MainForm : MetroFramework.Forms.MetroForm
    {
        public static Mutex files_sync = new Mutex();
        public static Queue<ScannedFileInfo> files = new Queue<ScannedFileInfo>();

        public static Mutex viruses_sync = new Mutex();
        public static Queue<VirusFileInfo> viruses = new Queue<VirusFileInfo>();

        public static System.Windows.Forms.Timer Updater = new System.Windows.Forms.Timer();
        public static bool ScanEnabled = false;
        private static int CountShown = 0;

        public MainForm()
        {
            InitializeComponent();

            ScanManager.Init(this);

            {
                TabControl.Multiline = true;
                TabControl.Appearance = TabAppearance.Buttons;
                TabControl.ItemSize = new System.Drawing.Size(0, 1);
                TabControl.SizeMode = TabSizeMode.Fixed;
                TabControl.TabStop = false;
            }

            {
                API.Init();

                API.onScanCompleted += APIHandlers.OnScannedFile;
                API.onScanFound += APIHandlers.OnFoundVirus;
                API.onVirusInfo += APIHandlers.virusInfo;
            }

            {
                Updater.Tick += MyTimer_Tick;
                Updater.Interval = 200;
                Updater.Enabled = true;
            }

            {
                //Применение настроек касающихся ядра
                API.SetAutoScanRemovableDevices(Configuration.AutoScanRemovableDevices);
            }

            {
                metroCheckBox1.Checked = Configuration.Notify_FoundVirus;
                metroCheckBox2.Checked = Configuration.AutoScanRemovableDevices;
            }
        }



        private void MyTimer_Tick(object sender, EventArgs e)
        {
            if (ScanManager.State == ScanState.Active)
            {
                return;
            }

            if(files.Count > 0)
            {
                files_sync.WaitOne();
                {
                    var fileInfo = files.Dequeue();


                    var popup = new PopupNotifier()
                    {
                        ContentText = $"Сканирование завершено\n{fileInfo.file}",
                        TitleText = "Antivirus"                        
                    };

                    //popup.Popup();
                }
                files_sync.ReleaseMutex();
            }


            if (viruses.Count > 0 && CountShown < viruses.Count)
            {
                viruses_sync.WaitOne();
                {
                    var fileInfo = viruses.Peek();

                    var popup = new PopupNotifier()
                    {
                        ContentText = $"Обнаружена угроза\n{fileInfo.file}",
                        TitleText = "Antivirus"
                    };

                    popup.Popup();

                    CountShown++;
                }
                viruses_sync.ReleaseMutex();
            }
        }

        #region Кнопки переключения между вкладками
        private void ScanButton_Click_2(object sender, EventArgs e)
        {
            this.TabControl.SelectTab(1);
        }

        private void settingsButton_Click_1(object sender, EventArgs e)
        {
            this.TabControl.SelectTab(2);
        }

        private void QuarantineButton_Click_1(object sender, EventArgs e)
        {
            this.TabControl.SelectTab(3);
        }

        private void ExceptionsButton_Click_1(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 4;
        }

        private void UpdateButton_Click_1(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 5;
        }

        private void page_exceptions_back_to_main_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
        }

        /// <summary>
        /// Отмена сканирования (при настройке)
        /// </summary>
        private void metroButton9_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
        }

        private void metroButton10_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
        }
        private void metroButton11_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
        }
        private void metroButton8_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
        }
        #endregion

        private void добавитьПапкуToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var result = folderBrowserDialog1.ShowDialog();

            if(result == DialogResult.OK)
            {
                var newItem = this.ScanObjectsList.Items.Add((this.ScanObjectsList.Items.Count + 1).ToString());
                newItem.SubItems.Add("       " + folderBrowserDialog1.SelectedPath);
            }
        }

        private void добавитьФайлToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var result = openFileDialog1.ShowDialog();

            if (result == DialogResult.OK)
            {
                var newItem = this.ScanObjectsList.Items.Add((this.ScanObjectsList.Items.Count + 1).ToString());
                newItem.SubItems.Add("       " + openFileDialog1.FileName);
            }
        }

        /// <summary>
        /// Начать сканирование
        /// </summary>
        private void metroButton2_Click(object sender, EventArgs e)
        {
            if(ScanObjectsList.Items.Count == 0)
            {
                return;
            }

            this.TabControl.SelectedIndex = 6;

            var files = new List<string>();
            var dirs = new List<string>();

            foreach (ListViewItem Item in ScanObjectsList.Items)
            {
                if (Item.SubItems[0].Text.LastIndexOf('.') > Item.SubItems[0].Text.LastIndexOf('\\'))
                {
                    files.Add(Item.SubItems[0].Text);
                }
                else
                {
                    dirs.Add(Item.SubItems[1].Text);
                }
            }

            ScanManager.StartScan(dirs.ToArray());
        }

        /// <summary>
        /// При открытии вкладки отображения процесса сканирования
        /// </summary>
        private void tabPage7_Enter(object sender, EventArgs e)
        {
            this.active_scan_updater.Start();
        }

        /// <summary>
        /// Обновление данных на странице процесса сканирования
        /// </summary>
        private void active_scan_updater_Tick(object sender, EventArgs e)
        {
            {
                this.page_active_scan_all_count.Text = ScanManager.CountAllFiles.ToString();
                this.page_active_scan_scanned.Text = ScanManager.CountAllScannedFiles.ToString();
                this.foundVirusesCount.Text = ScanManager.foundViruses.Count.ToString();
            }

            {
                this.progressBar.Maximum = ScanManager.CountAllFiles;
                this.progressBar.Value = ScanManager.CountAllScannedFiles;
            }

            {
                this.scanProgressSpinner.Maximum = ScanManager.CountAllFiles;
                this.scanProgressSpinner.Value = ScanManager.CountAllScannedFiles;
            }

            {
                this.label_scanned_file.Text = ScanManager.LastScanned;
            }

            if (ScanManager.CountAllFiles == ScanManager.CountAllScannedFiles)
            {
                this.TabControl.SelectedIndex = 7;
                page_scan_result_all_scanned.Text = ScanManager.CountAllScannedFiles.ToString();

                int number = 0;

                foreach(VirusFileInfo info in ScanManager.foundViruses)
                {
                    var item = metroListView4.Items.Add(number.ToString());
                    item.SubItems.Add(info.file);
                    item.SubItems.Add("Trojan");
                    item.Tag = info;
                }
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            ScanManager.Stop();
            API.ApiStop();
            Updater.Stop();
        }

        /// <summary>
        /// Отменить(завершить) сканирование
        /// </summary>
        private void metroButton3_Click(object sender, EventArgs e)
        {
            //pass
            ScanManager.Abort();

            ScanManager.CountAllFiles = ScanManager.CountAllScannedFiles;
        }

        /// <summary>
        /// Приостановить сканирование
        /// </summary>
        private void metroButton4_Click(object sender, EventArgs e)
        {
            //pass
        }

        /// <summary>
        /// Нажатие кнопки "Выполнить действия" на вкладке результатов сканирования
        /// </summary>
        private void metroButton12_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
        }

        private void metroCheckBox2_CheckedChanged(object sender, EventArgs e)
        {
            Configuration.AutoScanRemovableDevices = this.metroCheckBox2.Checked;
            API.SetAutoScanRemovableDevices(Configuration.AutoScanRemovableDevices);
        }

        private void metroButton7_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 0;
            Configuration.Save();

            var popup = new PopupNotifier()
            {
                ContentText = "Настройки сохранены",
                TitleText = "Antivirus"
            };

            popup.Popup();
        }
    }

    public static class APIHandlers
    {
        public static void OnScannedFile(ScannedFileInfo info)
        {
            if (ScanManager.State == ScanState.Active)
            {
                //Если антивирус во время сканирования просканировал файл
                return;
            }
            else
            {
                //Если просто обнаружен вирус
                MainForm.files.Enqueue(info);
            }
        }

        public static void OnFoundVirus(VirusFileInfo info)
        {
            if (ScanManager.State == ScanState.Active)
            {
                //Если антивирус во время сканирования обнаружил вирус
                return;
            }

            MainForm.viruses.Enqueue(info);
        }

        public static void virusInfo(VirusInfo info)
        {
            Debug.WriteLine("Virus info!\n" + info.path);
        }
    }

}
