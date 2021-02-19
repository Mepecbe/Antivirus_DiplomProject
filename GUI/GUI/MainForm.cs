using System;
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
using MetroFramework.Controls;

using Tulpep.NotificationWindow;
using API_Client_Library;

using GUI.Components.ScanManager;
using GUI.Components.Configurations;

using System.IO;

namespace GUI
{
    public partial class MainForm : MetroFramework.Forms.MetroForm
    {
        public static Mutex files_sync = new Mutex();
        public static Queue<ScannedFileInfo> files = new Queue<ScannedFileInfo>();

        public static List<VirusInfo> VirusesBuffer = new List<VirusInfo>(); //Обнаруженные вирусы
        public static List<VirusInfo> InfoBuffer = new List<VirusInfo>(); //Информация о вирусах принятая через событие

        public static Mutex InfoBuffer_sync = new Mutex();
        public static Mutex VirusesBuffer_sync = new Mutex();

        public static System.Windows.Forms.Timer Updater = new System.Windows.Forms.Timer();
        public static bool ScanEnabled = false;
        private static int CountShown = 0;

        public static bool QuarantineShow { get; private set; }

        public MainForm()
        {
            {
                //Накладываем белую панель на кусочек TabControl'а сверху
                var topPanel = new Panel();
                var leftPanel = new Panel();
                var rightPanel = new Panel();
                var buttomPanel = new Panel();

                {
                    {
                        topPanel.Visible = true;
                        topPanel.Location = new System.Drawing.Point(0, 27);
                        topPanel.Name = "topPanel";
                        topPanel.Size = new System.Drawing.Size(904, 20);
                        topPanel.TabIndex = 7;

                        topPanel.ForeColor = SystemColors.ControlLightLight;
                        topPanel.BackColor = SystemColors.ControlLightLight;
                    }

                    {
                        leftPanel.Visible = true;
                        leftPanel.Location = new System.Drawing.Point(0, 6);
                        leftPanel.Name = "leftPanel";
                        leftPanel.Size = new System.Drawing.Size(6, 470);
                        leftPanel.TabIndex = 8;

                        leftPanel.ForeColor = SystemColors.ControlLightLight;
                        leftPanel.BackColor = SystemColors.ControlLightLight;
                    }

                    {
                        rightPanel.Visible = true;
                        rightPanel.Location = new System.Drawing.Point(902, 6);
                        rightPanel.Name = "rightPanel";
                        rightPanel.Size = new System.Drawing.Size(4, 470);
                        rightPanel.TabIndex = 9;

                        rightPanel.ForeColor = SystemColors.ControlLightLight;
                        rightPanel.BackColor = SystemColors.ControlLightLight;
                    }

                    {
                        buttomPanel.Visible = true;
                        buttomPanel.Location = new System.Drawing.Point(0, 452);
                        buttomPanel.Name = "buttomPanel";
                        buttomPanel.Size = new System.Drawing.Size(910, 8);
                        buttomPanel.TabIndex = 9;

                        buttomPanel.ForeColor = SystemColors.ControlLightLight;
                        buttomPanel.BackColor = SystemColors.ControlLightLight;
                    }
                }


                this.Controls.Add(topPanel);
                this.Controls.Add(leftPanel);
                this.Controls.Add(rightPanel);
                this.Controls.Add(buttomPanel);
            }


            InitializeComponent();

            ScanManager.Init(this);

            {
                TabControl.Multiline = true;
                TabControl.Appearance = TabAppearance.Buttons; //FlatButtons
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

                //Добавление правил фильтрации
                {
                    foreach (string path in Configuration.PathExceptions)
                    {
                        API.AddSimpleRule(path);
                    }

                    foreach (string file in Configuration.ExtentionExceptions)
                    {
                        API.AddSimpleRule(file);
                    }
                }
            }

            {
                //Установка настроек на форму
                metroCheckBox1.Checked = Configuration.Notify_FoundVirus;
                metroCheckBox2.Checked = Configuration.AutoScanRemovableDevices;

                switch (Configuration.AutoAction)
                {
                    case ActionType.Delete:
                        {
                            settingsAutoAction.Text = "Удалить";
                            break;
                        }

                    case ActionType.ToQuarantine:
                        {
                            settingsAutoAction.Text = "В карантин";
                            break;
                        }

                    case ActionType.Nothing:
                        {
                            settingsAutoAction.Text = "Ничего не делать";
                            break;
                        }
                }
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


            if (Configuration.Notify_FoundVirus && VirusesBuffer.Count > 0 && CountShown < VirusesBuffer.Count)
            {
                VirusesBuffer_sync.WaitOne();
                {
                    var fileInfo = VirusesBuffer[VirusesBuffer.Count - 1];

                    var popup = new PopupNotifier()
                    {
                        TitleText = "Antivirus"
                    };

                    switch (Configuration.AutoAction)
                    {
                        case ActionType.Nothing:
                            {
                                popup.ContentText = "Обнаружена угроза " + fileInfo.path;
                                break;
                            }

                        case ActionType.Delete:
                            {
                                popup.ContentText = "Удалена угроза " + fileInfo.path;
                                API.DeleteFile(fileInfo.id);

                                VirusesBuffer.RemoveAt(VirusesBuffer.Count - 1);
                                break;
                            }

                        case ActionType.ToQuarantine:
                            {
                                popup.ContentText = "Угроза помещена в карантин " + fileInfo.path;
                                API.ToQuarantine(fileInfo.id);
                                break;
                            }
                    }

                    if (Configuration.Notify_FoundVirus)
                    {
                        popup.Popup();
                    }

                    CountShown++;
                }
                VirusesBuffer_sync.ReleaseMutex();
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
            QuarantineShow = true;

            VirusesBuffer.Clear();
            InfoBuffer.Clear();

            API.getAllViruses();
            Thread.Sleep(200);

            this.quarantine_files.Items.Clear();

            for(int index = 0; index < InfoBuffer.Count; index++)
            {
                if (!InfoBuffer[index].inQuarantine)
                {
                    continue;
                }

                var Item = this.quarantine_files.Items.Add(InfoBuffer[index].path);
                Item.SubItems.Add("Trojan");
                Item.Tag = InfoBuffer[index];
            }

            InfoBuffer.Clear();
            VirusesBuffer.Clear();

            this.TabControl.SelectTab(3);
            QuarantineShow = false;
        }

        private void ExceptionsButton_Click_1(object sender, EventArgs e)
        {
            this.exceptionPaths.Items.Clear();
            this.exceptionFiles.Items.Clear();

            var paths = Configuration.PathExceptions;
            var files = Configuration.ExtentionExceptions;

            for(int index = 0; index < paths.Length; index++)
            {
                var item = this.exceptionPaths.Items.Add((index + 1).ToString());
                item.SubItems.Add("       " + paths[index]);
            }

            for (int index = 0; index < files.Length; index++)
            {
                var item = this.exceptionFiles.Items.Add((index + 1).ToString());
                item.SubItems.Add("       " + paths[index]);
            }

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
                newItem.Tag = folderBrowserDialog1.SelectedPath;
            }
        }

        private void добавитьФайлToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var result = openFileDialog1.ShowDialog();

            if (result == DialogResult.OK)
            {
                var newItem = this.ScanObjectsList.Items.Add((this.ScanObjectsList.Items.Count + 1).ToString());
                newItem.SubItems.Add("       " + openFileDialog1.FileName);
                newItem.Tag = openFileDialog1.FileName;
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

            VirusesBuffer.Clear();
            this.TabControl.SelectedIndex = 6;

            var files = new List<string>();
            var dirs = new List<string>();

            foreach (ListViewItem Item in ScanObjectsList.Items)
            {
                if (Item.SubItems[1].Text.LastIndexOf('.') > Item.SubItems[1].Text.LastIndexOf('\\'))
                {
                    files.Add(Item.Tag.ToString());
                }
                else
                {
                    dirs.Add(Item.Tag.ToString());
                }
            }

            ScanManager.StartScan(dirs.ToArray(), files.ToArray());

            Thread.Sleep(300);
            active_scan_updater.Start();
        }

        /// <summary>
        /// При открытии вкладки отображения процесса сканирования
        /// </summary>
        private void tabPage7_Enter(object sender, EventArgs e)
        {
            //pass
        }

        /// <summary>
        /// Обновление данных на странице процесса сканирования
        /// </summary>
        private void active_scan_updater_Tick(object sender, EventArgs e)
        {
            {
                this.page_active_scan_all_count.Text = ScanManager.CountAllFiles.ToString();
                this.page_active_scan_scanned.Text = ScanManager.CountAllScannedFiles.ToString();
                this.foundVirusesCount.Text = VirusesBuffer.Count.ToString();
            }

            {
                this.progressBar.Maximum = ScanManager.CountAllFiles;
                this.progressBar.Value = ScanManager.CountAllScannedFiles;
            }

            {
                try { this.scanProgressSpinner.Maximum = ScanManager.CountAllFiles == 0 ? 1 : ScanManager.CountAllFiles; } catch { }
                try { this.scanProgressSpinner.Value = ScanManager.CountAllScannedFiles; } catch { }
            }

            {
                this.label_scanned_file.Text = ScanManager.LastScanned;
            }

            if (ScanManager.CountAllFiles == ScanManager.CountAllScannedFiles)
            {
                API.ClearScanQueue();

                this.TabControl.SelectedIndex = 7;
                page_scan_result_all_scanned.Text = ScanManager.CountAllScannedFiles.ToString();

                {
                    this.scanFoundResult.Text = VirusesBuffer.Count.ToString();
                }

                if (VirusesBuffer.Count == 0)
                {
                    page_result_text.Text = "Вирусов не обнаружено";
                    ApplyingActions.Text = "Назад на главную";
                }
                else
                {
                    foreach (VirusInfo info in VirusesBuffer)
                    {
                        VirusAction action = new VirusAction(info);

                        var item = metroListView4.Items.Add(info.path);
                        item.SubItems.Add("Trojan");
                        item.SubItems.Add("Удалить");
                        action.Action = ActionType.Delete;

                        item.Tag = action;
                    }
                }

                this.active_scan_updater.Stop();
                ScanManager.ExtentionsFilter = $"*.*";
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            switch (e.CloseReason) 
            {
                case CloseReason.WindowsShutDown:
                    {
                        //Windows закрывает все приложения перед завершением работы

                        ScanManager.Stop();
                        API.ApiStop();
                        Updater.Stop();
                        break;
                    }

                case CloseReason.UserClosing:
                    {
                        e.Cancel = true;
                        this.Hide();
                        break;
                    }

                case CloseReason.TaskManagerClosing:
                    {
                        //TaskManager закрывает приложение

                        ScanManager.Stop();
                        API.ApiStop();
                        Updater.Stop();
                        break;
                    }
            }
        }

        /// <summary>
        /// Отменить(завершить) сканирование
        /// </summary>
        private void metroButton3_Click(object sender, EventArgs e)
        {
            ScanManager.Abort();

            ScanManager.CountAllFiles = ScanManager.CountAllScannedFiles;
        }

        /// <summary>
        /// Приостановить сканирование
        /// </summary>
        private void metroButton4_Click(object sender, EventArgs e)
        {
            if (pauseScan.Text == "Приостановить")
            {
                pauseScan.Text = "Продолжить";
                ScanManager.Pause();
            }
            else
            {
                pauseScan.Text = "Приостановить";
                ScanManager.Resume();
            }
        }

        /// <summary>
        /// Нажатие кнопки "Выполнить действия" на вкладке результатов сканирования
        /// </summary>
        private void metroButton12_Click(object sender, EventArgs e)
        {
            ApplyingActions.Text = "Выполнить действия";

            List<VirusAction> virusesActions = new List<VirusAction>();

            foreach(ListViewItem item in metroListView4.Items)
            {
                virusesActions.Add((VirusAction)item.Tag);
            }

            if(virusesActions.Count > 0)
            {
                var popup = new PopupNotifier()
                {
                    ContentText = "Действия выполнены",
                    TitleText = "Antivirus"
                };

                popup.Popup();
            }

            API.ApplyingActions(virusesActions.ToArray());

            VirusesBuffer.Clear();
            this.ScanObjectsList.Items.Clear();
            this.metroListView4.Items.Clear();
            this.TabControl.SelectedIndex = 0;

            ScanManager.Reset();
        }

        private void metroCheckBox2_CheckedChanged(object sender, EventArgs e)
        {
            //Опция автопроверки съемных носителей
            this.saveSettings.Visible = true;
        }

        private void metroCheckBox1_CheckedChanged(object sender, EventArgs e)
        {
            //Опция показывать уведомления
            this.saveSettings.Visible = true;
        }

        private void metroButton7_Click(object sender, EventArgs e)
        {
            Configuration.Notify_FoundVirus = this.metroCheckBox1.Checked;
            Configuration.AutoScanRemovableDevices = this.metroCheckBox2.Checked;

            switch (this.settingsAutoAction.Text)
            {
                case "В карантин":
                    {
                        Configuration.AutoAction = ActionType.ToQuarantine;
                        break;
                    }

                case "Удалить":
                    {
                        Configuration.AutoAction = ActionType.Delete;
                        break;
                    }

                case "Ничего не делать":
                    {
                        Configuration.AutoAction = ActionType.Nothing;
                        break;
                    }
            }

            Configuration.Save();

            if (Configuration.AutoScanRemovableDevices)
            {
                API.ClearConnectedDevices();
            }

            API.SetAutoScanRemovableDevices(Configuration.AutoScanRemovableDevices);

            var popup = new PopupNotifier()
            {
                ContentText = "Настройки сохранены",
                TitleText = "Antivirus"
            };

            popup.Popup();

            this.saveSettings.Visible = true;
            this.TabControl.SelectedIndex = 0;
        }


        private void удалитьToolStripMenuItem2_Click(object sender, EventArgs e)
        {
            if(this.ScanObjectsList.SelectedItems.Count > 0)
            {
                for(int index = this.ScanObjectsList.SelectedItems.Count - 1; index >= 0; index--)
                {
                    this.ScanObjectsList.SelectedItems[index].Remove();
                }
            }

            for(int index = 0; index < this.ScanObjectsList.Items.Count; index++)
            {
                this.ScanObjectsList.Items[index].SubItems[0].Text = (index + 1).ToString();
            }
        }

        /*При выборе действий после окончания сканирования*/
        private void вКарантинToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if(metroListView4.SelectedItems.Count > 0)
            {
                ((VirusAction)metroListView4.SelectedItems[0].Tag).Action = ActionType.ToQuarantine;
                metroListView4.SelectedItems[0].SubItems[2].Text = "В карантин";
            }
        }

        private void удалитьToolStripMenuItem3_Click(object sender, EventArgs e)
        {
            if (metroListView4.SelectedItems.Count > 0)
            {
                ((VirusAction)metroListView4.SelectedItems[0].Tag).Action = ActionType.Delete;
                metroListView4.SelectedItems[0].SubItems[2].Text = "Удалить";
            }
        }

        private void ничегоНеДелатьToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (metroListView4.SelectedItems.Count > 0)
            {
                ((VirusAction)metroListView4.SelectedItems[0].Tag).Action = ActionType.Nothing;
                metroListView4.SelectedItems[0].SubItems[2].Text = "Ничего";
            }
        }

        //Восстановить файл находящийся в карантине
        private void восстановитьФайлToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (quarantine_files.SelectedItems.Count > 0)
            {
                VirusInfo info = (VirusInfo)quarantine_files.SelectedItems[0].Tag;
                info.inQuarantine = false;
                API.RestoreFile(info.id); 

                quarantine_files.SelectedItems[0].Remove();
            }
        }

        //Удалить файл находящийся в карантине
        private void удалитьФайлToolStripMenuItem_Click(object sender, EventArgs e)
        {
            VirusesBuffer_sync.WaitOne();
            {
                if (quarantine_files.SelectedItems.Count > 0)
                {
                    VirusInfo info = (VirusInfo)quarantine_files.SelectedItems[0].Tag;
                    API.DeleteFile(info.id);

                    for (int index = 0; index < VirusesBuffer.Count; index++)
                    {
                        if (VirusesBuffer[index].id == info.id)
                        {
                            VirusesBuffer.RemoveAt(index);
                            break;
                        }
                    }

                    quarantine_files.SelectedItems[0].Remove();
                }
            }
            VirusesBuffer_sync.ReleaseMutex();
        }

        private void notifyIcon_DoubleClick(object sender, EventArgs e)
        {
            this.Show();
        }

        private void открытьToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Show();
        }

        private void выходToolStripMenuItem_Click(object sender, EventArgs e)
        {
            API.StopKernel();
            ScanManager.Stop();
            API.ApiStop();
            Updater.Stop();

            Application.Exit();
        }

        private void добавитьToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var result = folderBrowserDialog1.ShowDialog();

            if (result == DialogResult.OK)
            {
                var item = this.exceptionPaths.Items.Add((this.exceptionPaths.Items.Count + 1).ToString());
                item.SubItems.Add("       " + folderBrowserDialog1.SelectedPath);

                this.saveExceptions.Visible = true;
            }
        }

        private void удалитьToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (this.exceptionPaths.SelectedItems.Count > 0)
            {
                this.exceptionPaths.SelectedItems[0].Remove();

                this.saveExceptions.Visible = true;
            }
        }

        private void metroButton1_Click(object sender, EventArgs e)
        {
            API.ClearSimpleRules();

            List<string> pathRules = new List<string>();
            List<string> fileRules = new List<string>();

            {
                foreach (ListViewItem item in this.exceptionPaths.Items)
                {
                    item.SubItems[1].Text = item.SubItems[1].Text.Remove(0, 7);
                    API.AddSimpleRule(item.SubItems[1].Text);

                    pathRules.Add(item.SubItems[1].Text);
                }
            }

            {
                foreach (ListViewItem item in this.exceptionFiles.Items)
                {
                    item.SubItems[1].Text = item.SubItems[1].Text.Remove(0, 7);
                    API.AddSimpleRule(item.SubItems[1].Text);

                    fileRules.Add(item.SubItems[1].Text);
                }
            }

            Configuration.PathExceptions = pathRules.ToArray();
            Configuration.ExtentionExceptions = fileRules.ToArray();
            Configuration.Save();

            this.TabControl.SelectedIndex = 0;

            var popup = new PopupNotifier()
            {
                TitleText = "Antivirus",
                ContentText = "Настройки исключений сохранены"
            };

            popup.Popup();
        }

        private void toolStripMenuItem1_Click(object sender, EventArgs e)
        {
            var result = openFileDialog1.ShowDialog();

            if (result == DialogResult.OK)
            {
                var item = this.exceptionFiles.Items.Add((this.exceptionFiles.Items.Count + 1).ToString());
                item.SubItems.Add("       " + openFileDialog1.FileName);

                this.saveExceptions.Visible = true;
            }
        }

        private void toolStripMenuItem2_Click(object sender, EventArgs e)
        {
            if (this.exceptionFiles.SelectedItems.Count > 0)
            {
                this.exceptionFiles.SelectedItems[0].Remove();

                this.saveExceptions.Visible = true;
            }
        }

        private void metroButton6_Click(object sender, EventArgs e)
        {
            //Полный скан
            this.ScanObjectsList.Items.Clear();
            ScanManager.ExtentionsFilter = $"*.*";

            foreach(DriveInfo drive in DriveInfo.GetDrives())
            {
                if(drive.DriveType == DriveType.Fixed)
                {
                    var item = ScanObjectsList.Items.Add((ScanObjectsList.Items.Count + 1).ToString());
                    item.SubItems.Add("       " + drive.Name);
                }
            }

            //Нажатие на кнопку "начать сканирование"
            metroButton2_Click(null, null);
        }

        private void metroButton5_Click(object sender, EventArgs e)
        {
            //Быстрый скан
            this.ScanObjectsList.Items.Clear();
            ScanManager.ExtentionsFilter = $"*.exe";

            var root = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System));

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Fixed && drive.Name != root)
                {
                    var item = ScanObjectsList.Items.Add((ScanObjectsList.Items.Count + 1).ToString());
                    item.SubItems.Add("       " + drive.Name);
                    item.Tag = drive.Name;
                }
            }

            //Нажатие на кнопку "начать сканирование"
            metroButton2_Click(null, null);
        }

        private void settingsAutoAction_SelectedIndexChanged(object sender, EventArgs e)
        {
            this.saveSettings.Visible = true;
        }

        private void progInfo_Click(object sender, EventArgs e)
        {
            MetroFramework.MetroMessageBox.Show(this, 
                "Программное средство защиты от файловых вирусов\n" +
                "Разработал учащийся группы 2218 Володько Никита Иванович\n" +
                "НГАЭК 2021", "О программе");
        }

        private void приостановитьЗащитуToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if(this.notifyIconContextMenu.Items[1].Text == "Приостановить защиту")
            {
                var popup = new PopupNotifier()
                {
                    TitleText = "Antivirus",
                    ContentText = "Защита приостановлена"
                };

                popup.Popup();

                this.notifyIconContextMenu.Items[1].Text = "Активировать защиту";
                API.SetDefenderState(true);
            }
            else
            {
                var popup = new PopupNotifier()
                {
                    TitleText = "Antivirus",
                    ContentText = "Защита активна"
                };

                popup.Popup();

                this.notifyIconContextMenu.Items[1].Text = "Приостановить защиту";
                API.SetDefenderState(false);
            }
        }

        private void Cryptographer_Click(object sender, EventArgs e)
        {
            this.TabControl.SelectedIndex = 8;
        }

        /*====*/
    }

    public static class APIHandlers
    {
        /// <summary>
        /// Если проверили файл и он не вирус
        /// </summary>
        public static void OnScannedFile(string file)
        {
            if (ScanManager.State == ScanState.Active)
            {
                ScanManager.LastScanned = file;
                ScanManager.CountAllScannedFiles++;
            }
        }

        public static void OnFoundVirus(VirusInfo info)
        {
            if (ScanManager.State == ScanState.Active)
            {
                ScanManager.CountAllScannedFiles++;
            }

            MainForm.VirusesBuffer.Add(info);
        }

        /// <summary>
        /// При получении информации о вирусе
        /// </summary>
        /// <param name="info"></param>
        public static void virusInfo(VirusInfo info)
        {
            if (ScanManager.State == ScanState.Active)
            {
                return;
            }

            if (MainForm.QuarantineShow)
            {
                //pass
            }

            MainForm.InfoBuffer_sync.WaitOne();
            {
                MainForm.InfoBuffer.Add(info);
            }
            MainForm.InfoBuffer_sync.ReleaseMutex();
        }
    }

}
