﻿using System.Windows.Forms;
using System.Drawing;

namespace GUI
{
    partial class MainForm
    {
        /// <summary>
        /// Обязательная переменная конструктора.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Освободить все используемые ресурсы.
        /// </summary>
        /// <param name="disposing">истинно, если управляемый ресурс должен быть удален; иначе ложно.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows

        /// <summary>
        /// Требуемый метод для поддержки конструктора — не изменяйте 
        /// содержимое этого метода с помощью редактора кода.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.TabControl = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.Cryptographer = new MetroFramework.Controls.MetroTile();
            this.progInfo = new MetroFramework.Controls.MetroTile();
            this.ExceptionsButton = new MetroFramework.Controls.MetroTile();
            this.UpdateButton = new MetroFramework.Controls.MetroTile();
            this.QuarantineButton = new MetroFramework.Controls.MetroTile();
            this.settingsButton = new MetroFramework.Controls.MetroTile();
            this.ScanButton = new MetroFramework.Controls.MetroTile();
            this.metroTile1 = new MetroFramework.Controls.MetroTile();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.metroButton9 = new MetroFramework.Controls.MetroButton();
            this.metroButton6 = new MetroFramework.Controls.MetroButton();
            this.metroButton5 = new MetroFramework.Controls.MetroButton();
            this.ScanObjectsList = new MetroFramework.Controls.MetroListView();
            this.columnHeader10 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader11 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.addToScan = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.добавитьПапкуToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.добавитьФайлToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьToolStripMenuItem2 = new System.Windows.Forms.ToolStripMenuItem();
            this.startScanButton = new MetroFramework.Controls.MetroButton();
            this.metroLabel6 = new MetroFramework.Controls.MetroLabel();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.settingsAutoAction = new MetroFramework.Controls.MetroComboBox();
            this.metroLabel8 = new MetroFramework.Controls.MetroLabel();
            this.metroButton8 = new MetroFramework.Controls.MetroButton();
            this.saveSettings = new MetroFramework.Controls.MetroButton();
            this.metroCheckBox2 = new MetroFramework.Controls.MetroCheckBox();
            this.metroCheckBox1 = new MetroFramework.Controls.MetroCheckBox();
            this.metroLabel5 = new MetroFramework.Controls.MetroLabel();
            this.tabPage4 = new System.Windows.Forms.TabPage();
            this.metroButton10 = new MetroFramework.Controls.MetroButton();
            this.quarantine_files = new MetroFramework.Controls.MetroListView();
            this.columnHeader5 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader13 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.quarantineContextMenu = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.восстановитьФайлToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьФайлToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.metroLabel7 = new MetroFramework.Controls.MetroLabel();
            this.tabPage5 = new System.Windows.Forms.TabPage();
            this.saveExceptions = new MetroFramework.Controls.MetroButton();
            this.page_exceptions_back_to_main = new MetroFramework.Controls.MetroButton();
            this.exceptionFiles = new MetroFramework.Controls.MetroListView();
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ExceptionFileContextMenu = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.toolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem2 = new System.Windows.Forms.ToolStripMenuItem();
            this.metroLabel3 = new MetroFramework.Controls.MetroLabel();
            this.exceptionPaths = new MetroFramework.Controls.MetroListView();
            this.columnHeader7 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader8 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ExceptionPathContextMenu = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.добавитьToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.metroLabel2 = new MetroFramework.Controls.MetroLabel();
            this.metroLabel1 = new MetroFramework.Controls.MetroLabel();
            this.tabPage6 = new System.Windows.Forms.TabPage();
            this.metroLabel20 = new MetroFramework.Controls.MetroLabel();
            this.latestSignatureDB_ver = new MetroFramework.Controls.MetroLabel();
            this.activeSignatureDB_ver = new MetroFramework.Controls.MetroLabel();
            this.metroLabel15 = new MetroFramework.Controls.MetroLabel();
            this.metroLabel14 = new MetroFramework.Controls.MetroLabel();
            this.metroButton11 = new MetroFramework.Controls.MetroButton();
            this.metroLabel4 = new MetroFramework.Controls.MetroLabel();
            this.tabPage7 = new System.Windows.Forms.TabPage();
            this.label_scanned_file = new MetroFramework.Controls.MetroLabel();
            this.scanProgressSpinner = new MetroFramework.Controls.MetroProgressSpinner();
            this.foundVirusesCount = new MetroFramework.Controls.MetroLabel();
            this.metroLabel17 = new MetroFramework.Controls.MetroLabel();
            this.page_active_scan_all_count = new MetroFramework.Controls.MetroLabel();
            this.metroLabel16 = new MetroFramework.Controls.MetroLabel();
            this.page_active_scan_scanned = new MetroFramework.Controls.MetroLabel();
            this.pauseScan = new MetroFramework.Controls.MetroButton();
            this.metroButton3 = new MetroFramework.Controls.MetroButton();
            this.metroLabel11 = new MetroFramework.Controls.MetroLabel();
            this.metroLabel10 = new MetroFramework.Controls.MetroLabel();
            this.progressBar = new MetroFramework.Controls.MetroProgressBar();
            this.metroLabel9 = new MetroFramework.Controls.MetroLabel();
            this.tabPage8 = new System.Windows.Forms.TabPage();
            this.scanFoundResult = new MetroFramework.Controls.MetroLabel();
            this.metroLabel13 = new MetroFramework.Controls.MetroLabel();
            this.page_result_text = new MetroFramework.Controls.MetroLabel();
            this.ApplyingActions = new MetroFramework.Controls.MetroButton();
            this.metroLabel19 = new MetroFramework.Controls.MetroLabel();
            this.metroListView4 = new MetroFramework.Controls.MetroListView();
            this.columnHeader6 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader12 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader15 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.setAction = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.вКарантинToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьToolStripMenuItem3 = new System.Windows.Forms.ToolStripMenuItem();
            this.ничегоНеДелатьToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.page_scan_result_all_scanned = new MetroFramework.Controls.MetroLabel();
            this.metroLabel18 = new MetroFramework.Controls.MetroLabel();
            this.metroLabel12 = new MetroFramework.Controls.MetroLabel();
            this.tabPage9 = new System.Windows.Forms.TabPage();
            this.metroButton4 = new MetroFramework.Controls.MetroButton();
            this.metroButton2 = new MetroFramework.Controls.MetroButton();
            this.cryptoTable = new System.Windows.Forms.ListView();
            this.columnHeader3 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader4 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader9 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.metroContextMenu1 = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.добавитьФайлToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьФайлToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьФайлИзЖесткогоДискаToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.зашифроватьToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.расшифроватьToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.metroButton1 = new MetroFramework.Controls.MetroButton();
            this.metroLabel21 = new MetroFramework.Controls.MetroLabel();
            this.MonPartitionContextMenu = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.добавитьToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.удалитьToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.notifyIcon = new System.Windows.Forms.NotifyIcon(this.components);
            this.notifyIconContextMenu = new MetroFramework.Controls.MetroContextMenu(this.components);
            this.открытьToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.приостановитьЗащитуToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.выходToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.active_scan_updater = new System.Windows.Forms.Timer(this.components);
            this.saveFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            this.TabControl.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.addToScan.SuspendLayout();
            this.tabPage3.SuspendLayout();
            this.tabPage4.SuspendLayout();
            this.quarantineContextMenu.SuspendLayout();
            this.tabPage5.SuspendLayout();
            this.ExceptionFileContextMenu.SuspendLayout();
            this.ExceptionPathContextMenu.SuspendLayout();
            this.tabPage6.SuspendLayout();
            this.tabPage7.SuspendLayout();
            this.tabPage8.SuspendLayout();
            this.setAction.SuspendLayout();
            this.tabPage9.SuspendLayout();
            this.metroContextMenu1.SuspendLayout();
            this.MonPartitionContextMenu.SuspendLayout();
            this.notifyIconContextMenu.SuspendLayout();
            this.SuspendLayout();
            // 
            // TabControl
            // 
            this.TabControl.Appearance = System.Windows.Forms.TabAppearance.Buttons;
            this.TabControl.Controls.Add(this.tabPage1);
            this.TabControl.Controls.Add(this.tabPage2);
            this.TabControl.Controls.Add(this.tabPage3);
            this.TabControl.Controls.Add(this.tabPage4);
            this.TabControl.Controls.Add(this.tabPage5);
            this.TabControl.Controls.Add(this.tabPage6);
            this.TabControl.Controls.Add(this.tabPage7);
            this.TabControl.Controls.Add(this.tabPage8);
            this.TabControl.Controls.Add(this.tabPage9);
            this.TabControl.ItemSize = new System.Drawing.Size(0, 10);
            this.TabControl.Location = new System.Drawing.Point(2, 27);
            this.TabControl.Name = "TabControl";
            this.TabControl.SelectedIndex = 0;
            this.TabControl.Size = new System.Drawing.Size(904, 433);
            this.TabControl.TabIndex = 0;
            this.TabControl.TabStop = false;
            // 
            // tabPage1
            // 
            this.tabPage1.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage1.Controls.Add(this.Cryptographer);
            this.tabPage1.Controls.Add(this.progInfo);
            this.tabPage1.Controls.Add(this.ExceptionsButton);
            this.tabPage1.Controls.Add(this.UpdateButton);
            this.tabPage1.Controls.Add(this.QuarantineButton);
            this.tabPage1.Controls.Add(this.settingsButton);
            this.tabPage1.Controls.Add(this.ScanButton);
            this.tabPage1.Controls.Add(this.metroTile1);
            this.tabPage1.Location = new System.Drawing.Point(4, 14);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(896, 415);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "page_main";
            // 
            // Cryptographer
            // 
            this.Cryptographer.ActiveControl = null;
            this.Cryptographer.Location = new System.Drawing.Point(642, 212);
            this.Cryptographer.Name = "Cryptographer";
            this.Cryptographer.Size = new System.Drawing.Size(168, 168);
            this.Cryptographer.TabIndex = 19;
            this.Cryptographer.Text = "КРИПТОГРАФ";
            this.Cryptographer.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.Cryptographer.TileImage = global::GUI.Properties.Resources._4124820_document_encryption_file_access_file_security_protected_file_113909;
            this.Cryptographer.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Cryptographer.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.Cryptographer.UseSelectable = true;
            this.Cryptographer.UseTileImage = true;
            this.Cryptographer.Click += new System.EventHandler(this.Cryptographer_Click);
            // 
            // progInfo
            // 
            this.progInfo.ActiveControl = null;
            this.progInfo.Location = new System.Drawing.Point(642, 22);
            this.progInfo.Name = "progInfo";
            this.progInfo.Size = new System.Drawing.Size(168, 168);
            this.progInfo.TabIndex = 18;
            this.progInfo.Text = "О программе";
            this.progInfo.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.progInfo.TileImage = global::GUI.Properties.Resources.About_icon_icons_com_55974;
            this.progInfo.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.progInfo.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.progInfo.UseSelectable = true;
            this.progInfo.UseTileImage = true;
            this.progInfo.Click += new System.EventHandler(this.progInfo_Click);
            // 
            // ExceptionsButton
            // 
            this.ExceptionsButton.ActiveControl = null;
            this.ExceptionsButton.Location = new System.Drawing.Point(222, 212);
            this.ExceptionsButton.Name = "ExceptionsButton";
            this.ExceptionsButton.Size = new System.Drawing.Size(168, 168);
            this.ExceptionsButton.TabIndex = 17;
            this.ExceptionsButton.Text = "ИСКЛЮЧЕНИЯ";
            this.ExceptionsButton.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.ExceptionsButton.TileImage = global::GUI.Properties.Resources.close_96;
            this.ExceptionsButton.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.ExceptionsButton.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.ExceptionsButton.UseSelectable = true;
            this.ExceptionsButton.UseTileImage = true;
            this.ExceptionsButton.Click += new System.EventHandler(this.ExceptionsButton_Click_1);
            // 
            // UpdateButton
            // 
            this.UpdateButton.ActiveControl = null;
            this.UpdateButton.Location = new System.Drawing.Point(435, 212);
            this.UpdateButton.Name = "UpdateButton";
            this.UpdateButton.Size = new System.Drawing.Size(168, 168);
            this.UpdateButton.TabIndex = 16;
            this.UpdateButton.Text = "ОБНОВЛЕНИЯ";
            this.UpdateButton.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.UpdateButton.TileImage = global::GUI.Properties.Resources.reload_96;
            this.UpdateButton.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.UpdateButton.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.UpdateButton.UseSelectable = true;
            this.UpdateButton.UseTileImage = true;
            this.UpdateButton.Click += new System.EventHandler(this.UpdateButton_Click_1);
            // 
            // QuarantineButton
            // 
            this.QuarantineButton.ActiveControl = null;
            this.QuarantineButton.Location = new System.Drawing.Point(435, 22);
            this.QuarantineButton.Name = "QuarantineButton";
            this.QuarantineButton.Size = new System.Drawing.Size(168, 168);
            this.QuarantineButton.TabIndex = 15;
            this.QuarantineButton.Text = "КАРАНТИН";
            this.QuarantineButton.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.QuarantineButton.TileImage = global::GUI.Properties.Resources.safe_96;
            this.QuarantineButton.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.QuarantineButton.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.QuarantineButton.UseSelectable = true;
            this.QuarantineButton.UseTileImage = true;
            this.QuarantineButton.Click += new System.EventHandler(this.QuarantineButton_Click_1);
            // 
            // settingsButton
            // 
            this.settingsButton.ActiveControl = null;
            this.settingsButton.Location = new System.Drawing.Point(17, 212);
            this.settingsButton.Name = "settingsButton";
            this.settingsButton.Size = new System.Drawing.Size(168, 168);
            this.settingsButton.TabIndex = 14;
            this.settingsButton.Text = "НАСТРОЙКИ";
            this.settingsButton.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.settingsButton.TileImage = global::GUI.Properties.Resources.settings_96;
            this.settingsButton.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.settingsButton.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.settingsButton.UseSelectable = true;
            this.settingsButton.UseTileImage = true;
            this.settingsButton.Click += new System.EventHandler(this.settingsButton_Click_1);
            // 
            // ScanButton
            // 
            this.ScanButton.ActiveControl = null;
            this.ScanButton.Location = new System.Drawing.Point(222, 22);
            this.ScanButton.Name = "ScanButton";
            this.ScanButton.Size = new System.Drawing.Size(168, 168);
            this.ScanButton.TabIndex = 13;
            this.ScanButton.Text = "СКАНИРОВАНИЕ";
            this.ScanButton.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.ScanButton.TileImage = global::GUI.Properties.Resources.search_96;
            this.ScanButton.TileImageAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.ScanButton.TileTextFontSize = MetroFramework.MetroTileTextSize.Tall;
            this.ScanButton.UseSelectable = true;
            this.ScanButton.UseTileImage = true;
            this.ScanButton.Click += new System.EventHandler(this.ScanButton_Click_2);
            // 
            // metroTile1
            // 
            this.metroTile1.ActiveControl = null;
            this.metroTile1.Location = new System.Drawing.Point(17, 22);
            this.metroTile1.Name = "metroTile1";
            this.metroTile1.Size = new System.Drawing.Size(168, 168);
            this.metroTile1.TabIndex = 12;
            this.metroTile1.Text = "ЗАЩИТА АКТИВНА";
            this.metroTile1.TextAlign = System.Drawing.ContentAlignment.BottomCenter;
            this.metroTile1.TileImage = global::GUI.Properties.Resources.iconfinder_securityprotectlockshield04_4021479_113137;
            this.metroTile1.TileImageAlign = System.Drawing.ContentAlignment.TopCenter;
            this.metroTile1.UseSelectable = true;
            this.metroTile1.UseTileImage = true;
            // 
            // tabPage2
            // 
            this.tabPage2.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage2.Controls.Add(this.metroButton9);
            this.tabPage2.Controls.Add(this.metroButton6);
            this.tabPage2.Controls.Add(this.metroButton5);
            this.tabPage2.Controls.Add(this.ScanObjectsList);
            this.tabPage2.Controls.Add(this.startScanButton);
            this.tabPage2.Controls.Add(this.metroLabel6);
            this.tabPage2.Location = new System.Drawing.Point(4, 14);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(896, 415);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "page_scan";
            // 
            // metroButton9
            // 
            this.metroButton9.Location = new System.Drawing.Point(631, 362);
            this.metroButton9.Name = "metroButton9";
            this.metroButton9.Size = new System.Drawing.Size(75, 23);
            this.metroButton9.TabIndex = 7;
            this.metroButton9.Text = "Отмена";
            this.metroButton9.UseSelectable = true;
            this.metroButton9.Click += new System.EventHandler(this.metroButton9_Click);
            // 
            // metroButton6
            // 
            this.metroButton6.Location = new System.Drawing.Point(17, 362);
            this.metroButton6.Name = "metroButton6";
            this.metroButton6.Size = new System.Drawing.Size(128, 23);
            this.metroButton6.TabIndex = 6;
            this.metroButton6.Text = "Полная проверка";
            this.metroButton6.UseSelectable = true;
            this.metroButton6.Click += new System.EventHandler(this.metroButton6_Click);
            // 
            // metroButton5
            // 
            this.metroButton5.Location = new System.Drawing.Point(164, 362);
            this.metroButton5.Name = "metroButton5";
            this.metroButton5.Size = new System.Drawing.Size(135, 23);
            this.metroButton5.TabIndex = 5;
            this.metroButton5.Text = "Быстрая проверка";
            this.metroButton5.UseSelectable = true;
            this.metroButton5.Click += new System.EventHandler(this.metroButton5_Click);
            // 
            // ScanObjectsList
            // 
            this.ScanObjectsList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader10,
            this.columnHeader11});
            this.ScanObjectsList.ContextMenuStrip = this.addToScan;
            this.ScanObjectsList.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.ScanObjectsList.FullRowSelect = true;
            this.ScanObjectsList.Location = new System.Drawing.Point(17, 46);
            this.ScanObjectsList.Name = "ScanObjectsList";
            this.ScanObjectsList.OwnerDraw = true;
            this.ScanObjectsList.Size = new System.Drawing.Size(860, 310);
            this.ScanObjectsList.TabIndex = 4;
            this.ScanObjectsList.UseCompatibleStateImageBehavior = false;
            this.ScanObjectsList.UseSelectable = true;
            this.ScanObjectsList.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader10
            // 
            this.columnHeader10.DisplayIndex = 1;
            this.columnHeader10.Text = "Файл или папка";
            this.columnHeader10.Width = 795;
            // 
            // columnHeader11
            // 
            this.columnHeader11.DisplayIndex = 0;
            this.columnHeader11.Text = "№";
            // 
            // addToScan
            // 
            this.addToScan.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.добавитьПапкуToolStripMenuItem,
            this.добавитьФайлToolStripMenuItem,
            this.удалитьToolStripMenuItem2});
            this.addToScan.Name = "addToScan";
            this.addToScan.Size = new System.Drawing.Size(162, 70);
            // 
            // добавитьПапкуToolStripMenuItem
            // 
            this.добавитьПапкуToolStripMenuItem.Name = "добавитьПапкуToolStripMenuItem";
            this.добавитьПапкуToolStripMenuItem.Size = new System.Drawing.Size(161, 22);
            this.добавитьПапкуToolStripMenuItem.Text = "Добавить папку";
            this.добавитьПапкуToolStripMenuItem.Click += new System.EventHandler(this.добавитьПапкуToolStripMenuItem_Click);
            // 
            // добавитьФайлToolStripMenuItem
            // 
            this.добавитьФайлToolStripMenuItem.Name = "добавитьФайлToolStripMenuItem";
            this.добавитьФайлToolStripMenuItem.Size = new System.Drawing.Size(161, 22);
            this.добавитьФайлToolStripMenuItem.Text = "Добавить файл";
            this.добавитьФайлToolStripMenuItem.Click += new System.EventHandler(this.добавитьФайлToolStripMenuItem_Click);
            // 
            // удалитьToolStripMenuItem2
            // 
            this.удалитьToolStripMenuItem2.Name = "удалитьToolStripMenuItem2";
            this.удалитьToolStripMenuItem2.Size = new System.Drawing.Size(161, 22);
            this.удалитьToolStripMenuItem2.Text = "Удалить";
            this.удалитьToolStripMenuItem2.Click += new System.EventHandler(this.удалитьToolStripMenuItem2_Click);
            // 
            // startScanButton
            // 
            this.startScanButton.Location = new System.Drawing.Point(712, 362);
            this.startScanButton.Name = "startScanButton";
            this.startScanButton.Size = new System.Drawing.Size(165, 23);
            this.startScanButton.TabIndex = 3;
            this.startScanButton.Text = "Начать проверку";
            this.startScanButton.UseSelectable = true;
            this.startScanButton.Click += new System.EventHandler(this.metroButton2_Click);
            // 
            // metroLabel6
            // 
            this.metroLabel6.AutoSize = true;
            this.metroLabel6.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel6.Location = new System.Drawing.Point(17, 9);
            this.metroLabel6.Name = "metroLabel6";
            this.metroLabel6.Size = new System.Drawing.Size(258, 25);
            this.metroLabel6.TabIndex = 2;
            this.metroLabel6.Text = "Сканирование файлов и папок";
            // 
            // tabPage3
            // 
            this.tabPage3.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage3.Controls.Add(this.settingsAutoAction);
            this.tabPage3.Controls.Add(this.metroLabel8);
            this.tabPage3.Controls.Add(this.metroButton8);
            this.tabPage3.Controls.Add(this.saveSettings);
            this.tabPage3.Controls.Add(this.metroCheckBox2);
            this.tabPage3.Controls.Add(this.metroCheckBox1);
            this.tabPage3.Controls.Add(this.metroLabel5);
            this.tabPage3.Location = new System.Drawing.Point(4, 14);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage3.Size = new System.Drawing.Size(896, 415);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "page_settings";
            // 
            // settingsAutoAction
            // 
            this.settingsAutoAction.FormattingEnabled = true;
            this.settingsAutoAction.ItemHeight = 23;
            this.settingsAutoAction.Items.AddRange(new object[] {
            "Удалить",
            "В карантин",
            "Ничего не делать"});
            this.settingsAutoAction.Location = new System.Drawing.Point(47, 125);
            this.settingsAutoAction.Name = "settingsAutoAction";
            this.settingsAutoAction.Size = new System.Drawing.Size(247, 29);
            this.settingsAutoAction.TabIndex = 11;
            this.settingsAutoAction.UseSelectable = true;
            this.settingsAutoAction.SelectedIndexChanged += new System.EventHandler(this.settingsAutoAction_SelectedIndexChanged);
            // 
            // metroLabel8
            // 
            this.metroLabel8.AutoSize = true;
            this.metroLabel8.Location = new System.Drawing.Point(47, 103);
            this.metroLabel8.Name = "metroLabel8";
            this.metroLabel8.Size = new System.Drawing.Size(247, 19);
            this.metroLabel8.TabIndex = 10;
            this.metroLabel8.Text = "Действие над обнаруженным вирусом";
            // 
            // metroButton8
            // 
            this.metroButton8.Location = new System.Drawing.Point(795, 362);
            this.metroButton8.Name = "metroButton8";
            this.metroButton8.Size = new System.Drawing.Size(75, 23);
            this.metroButton8.TabIndex = 9;
            this.metroButton8.Text = "На главную";
            this.metroButton8.UseSelectable = true;
            this.metroButton8.Click += new System.EventHandler(this.metroButton8_Click);
            // 
            // saveSettings
            // 
            this.saveSettings.Location = new System.Drawing.Point(625, 362);
            this.saveSettings.Name = "saveSettings";
            this.saveSettings.Size = new System.Drawing.Size(140, 23);
            this.saveSettings.TabIndex = 8;
            this.saveSettings.Text = "Сохранить изменения";
            this.saveSettings.UseSelectable = true;
            this.saveSettings.Visible = false;
            this.saveSettings.Click += new System.EventHandler(this.metroButton7_Click);
            // 
            // metroCheckBox2
            // 
            this.metroCheckBox2.AutoSize = true;
            this.metroCheckBox2.Location = new System.Drawing.Point(47, 72);
            this.metroCheckBox2.Name = "metroCheckBox2";
            this.metroCheckBox2.Size = new System.Drawing.Size(276, 15);
            this.metroCheckBox2.TabIndex = 6;
            this.metroCheckBox2.Text = "Автоматически проверять съемные носители";
            this.metroCheckBox2.UseSelectable = true;
            this.metroCheckBox2.CheckedChanged += new System.EventHandler(this.metroCheckBox2_CheckedChanged);
            // 
            // metroCheckBox1
            // 
            this.metroCheckBox1.AutoSize = true;
            this.metroCheckBox1.Location = new System.Drawing.Point(47, 51);
            this.metroCheckBox1.Name = "metroCheckBox1";
            this.metroCheckBox1.Size = new System.Drawing.Size(164, 15);
            this.metroCheckBox1.TabIndex = 5;
            this.metroCheckBox1.Text = "Показывать уведомления";
            this.metroCheckBox1.UseSelectable = true;
            this.metroCheckBox1.CheckedChanged += new System.EventHandler(this.metroCheckBox1_CheckedChanged);
            // 
            // metroLabel5
            // 
            this.metroLabel5.AutoSize = true;
            this.metroLabel5.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel5.Location = new System.Drawing.Point(17, 9);
            this.metroLabel5.Name = "metroLabel5";
            this.metroLabel5.Size = new System.Drawing.Size(96, 25);
            this.metroLabel5.TabIndex = 2;
            this.metroLabel5.Text = "Настройки";
            // 
            // tabPage4
            // 
            this.tabPage4.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage4.Controls.Add(this.metroButton10);
            this.tabPage4.Controls.Add(this.quarantine_files);
            this.tabPage4.Controls.Add(this.metroLabel7);
            this.tabPage4.Location = new System.Drawing.Point(4, 14);
            this.tabPage4.Name = "tabPage4";
            this.tabPage4.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage4.Size = new System.Drawing.Size(896, 415);
            this.tabPage4.TabIndex = 3;
            this.tabPage4.Text = "page_quarantine";
            // 
            // metroButton10
            // 
            this.metroButton10.Location = new System.Drawing.Point(802, 370);
            this.metroButton10.Name = "metroButton10";
            this.metroButton10.Size = new System.Drawing.Size(75, 23);
            this.metroButton10.TabIndex = 4;
            this.metroButton10.Text = "На главную";
            this.metroButton10.UseSelectable = true;
            this.metroButton10.Click += new System.EventHandler(this.metroButton10_Click);
            // 
            // quarantine_files
            // 
            this.quarantine_files.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader5,
            this.columnHeader13});
            this.quarantine_files.ContextMenuStrip = this.quarantineContextMenu;
            this.quarantine_files.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.quarantine_files.FullRowSelect = true;
            this.quarantine_files.Location = new System.Drawing.Point(17, 37);
            this.quarantine_files.Name = "quarantine_files";
            this.quarantine_files.OwnerDraw = true;
            this.quarantine_files.Size = new System.Drawing.Size(860, 327);
            this.quarantine_files.TabIndex = 3;
            this.quarantine_files.UseCompatibleStateImageBehavior = false;
            this.quarantine_files.UseSelectable = true;
            this.quarantine_files.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader5
            // 
            this.columnHeader5.Text = "Файл";
            this.columnHeader5.Width = 660;
            // 
            // columnHeader13
            // 
            this.columnHeader13.Text = "Тип вируса";
            this.columnHeader13.Width = 196;
            // 
            // quarantineContextMenu
            // 
            this.quarantineContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.восстановитьФайлToolStripMenuItem,
            this.удалитьФайлToolStripMenuItem});
            this.quarantineContextMenu.Name = "quarantineContextMenu";
            this.quarantineContextMenu.Size = new System.Drawing.Size(182, 48);
            // 
            // восстановитьФайлToolStripMenuItem
            // 
            this.восстановитьФайлToolStripMenuItem.Name = "восстановитьФайлToolStripMenuItem";
            this.восстановитьФайлToolStripMenuItem.Size = new System.Drawing.Size(181, 22);
            this.восстановитьФайлToolStripMenuItem.Text = "Восстановить файл";
            this.восстановитьФайлToolStripMenuItem.Click += new System.EventHandler(this.восстановитьФайлToolStripMenuItem_Click);
            // 
            // удалитьФайлToolStripMenuItem
            // 
            this.удалитьФайлToolStripMenuItem.Name = "удалитьФайлToolStripMenuItem";
            this.удалитьФайлToolStripMenuItem.Size = new System.Drawing.Size(181, 22);
            this.удалитьФайлToolStripMenuItem.Text = "Удалить файл";
            this.удалитьФайлToolStripMenuItem.Click += new System.EventHandler(this.удалитьФайлToolStripMenuItem_Click);
            // 
            // metroLabel7
            // 
            this.metroLabel7.AutoSize = true;
            this.metroLabel7.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel7.Location = new System.Drawing.Point(17, 9);
            this.metroLabel7.Name = "metroLabel7";
            this.metroLabel7.Size = new System.Drawing.Size(86, 25);
            this.metroLabel7.TabIndex = 2;
            this.metroLabel7.Text = "Карантин";
            // 
            // tabPage5
            // 
            this.tabPage5.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage5.Controls.Add(this.saveExceptions);
            this.tabPage5.Controls.Add(this.page_exceptions_back_to_main);
            this.tabPage5.Controls.Add(this.exceptionFiles);
            this.tabPage5.Controls.Add(this.metroLabel3);
            this.tabPage5.Controls.Add(this.exceptionPaths);
            this.tabPage5.Controls.Add(this.metroLabel2);
            this.tabPage5.Controls.Add(this.metroLabel1);
            this.tabPage5.Location = new System.Drawing.Point(4, 14);
            this.tabPage5.Name = "tabPage5";
            this.tabPage5.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage5.Size = new System.Drawing.Size(896, 415);
            this.tabPage5.TabIndex = 4;
            this.tabPage5.Text = "page_exceptions";
            // 
            // saveExceptions
            // 
            this.saveExceptions.Location = new System.Drawing.Point(495, 362);
            this.saveExceptions.Name = "saveExceptions";
            this.saveExceptions.Size = new System.Drawing.Size(154, 23);
            this.saveExceptions.TabIndex = 6;
            this.saveExceptions.Text = "Сохранить изменения";
            this.saveExceptions.UseSelectable = true;
            this.saveExceptions.Visible = false;
            this.saveExceptions.Click += new System.EventHandler(this.metroButton1_Click);
            // 
            // page_exceptions_back_to_main
            // 
            this.page_exceptions_back_to_main.Location = new System.Drawing.Point(655, 362);
            this.page_exceptions_back_to_main.Name = "page_exceptions_back_to_main";
            this.page_exceptions_back_to_main.Size = new System.Drawing.Size(143, 23);
            this.page_exceptions_back_to_main.TabIndex = 5;
            this.page_exceptions_back_to_main.Text = "Назад на главную";
            this.page_exceptions_back_to_main.UseSelectable = true;
            this.page_exceptions_back_to_main.Click += new System.EventHandler(this.page_exceptions_back_to_main_Click);
            // 
            // exceptionFiles
            // 
            this.exceptionFiles.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1,
            this.columnHeader2});
            this.exceptionFiles.ContextMenuStrip = this.ExceptionFileContextMenu;
            this.exceptionFiles.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.exceptionFiles.FullRowSelect = true;
            this.exceptionFiles.Location = new System.Drawing.Point(66, 218);
            this.exceptionFiles.Name = "exceptionFiles";
            this.exceptionFiles.OwnerDraw = true;
            this.exceptionFiles.Size = new System.Drawing.Size(732, 132);
            this.exceptionFiles.TabIndex = 4;
            this.exceptionFiles.UseCompatibleStateImageBehavior = false;
            this.exceptionFiles.UseSelectable = true;
            this.exceptionFiles.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader1
            // 
            this.columnHeader1.DisplayIndex = 1;
            this.columnHeader1.Text = "Файл";
            this.columnHeader1.Width = 668;
            // 
            // columnHeader2
            // 
            this.columnHeader2.DisplayIndex = 0;
            this.columnHeader2.Text = "№";
            // 
            // ExceptionFileContextMenu
            // 
            this.ExceptionFileContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripMenuItem1,
            this.toolStripMenuItem2});
            this.ExceptionFileContextMenu.Name = "ExceptionsContextMenu";
            this.ExceptionFileContextMenu.Size = new System.Drawing.Size(127, 48);
            // 
            // toolStripMenuItem1
            // 
            this.toolStripMenuItem1.Name = "toolStripMenuItem1";
            this.toolStripMenuItem1.Size = new System.Drawing.Size(126, 22);
            this.toolStripMenuItem1.Text = "Добавить";
            this.toolStripMenuItem1.Click += new System.EventHandler(this.toolStripMenuItem1_Click);
            // 
            // toolStripMenuItem2
            // 
            this.toolStripMenuItem2.Name = "toolStripMenuItem2";
            this.toolStripMenuItem2.Size = new System.Drawing.Size(126, 22);
            this.toolStripMenuItem2.Text = "Удалить";
            this.toolStripMenuItem2.Click += new System.EventHandler(this.toolStripMenuItem2_Click);
            // 
            // metroLabel3
            // 
            this.metroLabel3.AutoSize = true;
            this.metroLabel3.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel3.Location = new System.Drawing.Point(66, 190);
            this.metroLabel3.Name = "metroLabel3";
            this.metroLabel3.Size = new System.Drawing.Size(181, 25);
            this.metroLabel3.TabIndex = 3;
            this.metroLabel3.Text = "Исключаемые файлы";
            // 
            // exceptionPaths
            // 
            this.exceptionPaths.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader7,
            this.columnHeader8});
            this.exceptionPaths.ContextMenuStrip = this.ExceptionPathContextMenu;
            this.exceptionPaths.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.exceptionPaths.FullRowSelect = true;
            this.exceptionPaths.Location = new System.Drawing.Point(66, 66);
            this.exceptionPaths.Name = "exceptionPaths";
            this.exceptionPaths.OwnerDraw = true;
            this.exceptionPaths.Size = new System.Drawing.Size(732, 118);
            this.exceptionPaths.TabIndex = 2;
            this.exceptionPaths.UseCompatibleStateImageBehavior = false;
            this.exceptionPaths.UseSelectable = true;
            this.exceptionPaths.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader7
            // 
            this.columnHeader7.DisplayIndex = 1;
            this.columnHeader7.Text = "Путь";
            this.columnHeader7.Width = 668;
            // 
            // columnHeader8
            // 
            this.columnHeader8.DisplayIndex = 0;
            this.columnHeader8.Text = "№";
            // 
            // ExceptionPathContextMenu
            // 
            this.ExceptionPathContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.добавитьToolStripMenuItem,
            this.удалитьToolStripMenuItem});
            this.ExceptionPathContextMenu.Name = "ExceptionsContextMenu";
            this.ExceptionPathContextMenu.Size = new System.Drawing.Size(127, 48);
            // 
            // добавитьToolStripMenuItem
            // 
            this.добавитьToolStripMenuItem.Name = "добавитьToolStripMenuItem";
            this.добавитьToolStripMenuItem.Size = new System.Drawing.Size(126, 22);
            this.добавитьToolStripMenuItem.Text = "Добавить";
            this.добавитьToolStripMenuItem.Click += new System.EventHandler(this.добавитьToolStripMenuItem_Click);
            // 
            // удалитьToolStripMenuItem
            // 
            this.удалитьToolStripMenuItem.Name = "удалитьToolStripMenuItem";
            this.удалитьToolStripMenuItem.Size = new System.Drawing.Size(126, 22);
            this.удалитьToolStripMenuItem.Text = "Удалить";
            this.удалитьToolStripMenuItem.Click += new System.EventHandler(this.удалитьToolStripMenuItem_Click);
            // 
            // metroLabel2
            // 
            this.metroLabel2.AutoSize = true;
            this.metroLabel2.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel2.Location = new System.Drawing.Point(66, 38);
            this.metroLabel2.Name = "metroLabel2";
            this.metroLabel2.Size = new System.Drawing.Size(165, 25);
            this.metroLabel2.TabIndex = 1;
            this.metroLabel2.Text = "Исключаемые пути";
            // 
            // metroLabel1
            // 
            this.metroLabel1.AutoSize = true;
            this.metroLabel1.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel1.Location = new System.Drawing.Point(17, 9);
            this.metroLabel1.Name = "metroLabel1";
            this.metroLabel1.Size = new System.Drawing.Size(112, 25);
            this.metroLabel1.TabIndex = 0;
            this.metroLabel1.Text = "Исключения";
            // 
            // tabPage6
            // 
            this.tabPage6.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage6.Controls.Add(this.metroLabel20);
            this.tabPage6.Controls.Add(this.latestSignatureDB_ver);
            this.tabPage6.Controls.Add(this.activeSignatureDB_ver);
            this.tabPage6.Controls.Add(this.metroLabel15);
            this.tabPage6.Controls.Add(this.metroLabel14);
            this.tabPage6.Controls.Add(this.metroButton11);
            this.tabPage6.Controls.Add(this.metroLabel4);
            this.tabPage6.Location = new System.Drawing.Point(4, 14);
            this.tabPage6.Name = "tabPage6";
            this.tabPage6.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage6.Size = new System.Drawing.Size(896, 415);
            this.tabPage6.TabIndex = 5;
            this.tabPage6.Text = "page_update";
            // 
            // metroLabel20
            // 
            this.metroLabel20.AutoSize = true;
            this.metroLabel20.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel20.Location = new System.Drawing.Point(41, 151);
            this.metroLabel20.Name = "metroLabel20";
            this.metroLabel20.Size = new System.Drawing.Size(378, 75);
            this.metroLabel20.TabIndex = 10;
            this.metroLabel20.Text = "Установлена последняя версия базы сигнатур\r\nОбновление не требуется\r\n";
            // 
            // latestSignatureDB_ver
            // 
            this.latestSignatureDB_ver.AutoSize = true;
            this.latestSignatureDB_ver.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.latestSignatureDB_ver.Location = new System.Drawing.Point(330, 97);
            this.latestSignatureDB_ver.Name = "latestSignatureDB_ver";
            this.latestSignatureDB_ver.Size = new System.Drawing.Size(51, 25);
            this.latestSignatureDB_ver.TabIndex = 9;
            this.latestSignatureDB_ver.Text = "v2.20";
            // 
            // activeSignatureDB_ver
            // 
            this.activeSignatureDB_ver.AutoSize = true;
            this.activeSignatureDB_ver.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.activeSignatureDB_ver.Location = new System.Drawing.Point(307, 47);
            this.activeSignatureDB_ver.Name = "activeSignatureDB_ver";
            this.activeSignatureDB_ver.Size = new System.Drawing.Size(51, 25);
            this.activeSignatureDB_ver.TabIndex = 8;
            this.activeSignatureDB_ver.Text = "v2.20";
            // 
            // metroLabel15
            // 
            this.metroLabel15.AutoSize = true;
            this.metroLabel15.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel15.Location = new System.Drawing.Point(41, 97);
            this.metroLabel15.Name = "metroLabel15";
            this.metroLabel15.Size = new System.Drawing.Size(283, 25);
            this.metroLabel15.TabIndex = 7;
            this.metroLabel15.Text = "Актуальная версия базы сигнатур:";
            // 
            // metroLabel14
            // 
            this.metroLabel14.AutoSize = true;
            this.metroLabel14.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel14.Location = new System.Drawing.Point(41, 47);
            this.metroLabel14.Name = "metroLabel14";
            this.metroLabel14.Size = new System.Drawing.Size(260, 25);
            this.metroLabel14.TabIndex = 6;
            this.metroLabel14.Text = "Текущая версия базы сигнатур:";
            // 
            // metroButton11
            // 
            this.metroButton11.Location = new System.Drawing.Point(802, 362);
            this.metroButton11.Name = "metroButton11";
            this.metroButton11.Size = new System.Drawing.Size(75, 23);
            this.metroButton11.TabIndex = 5;
            this.metroButton11.Text = "На главную";
            this.metroButton11.UseSelectable = true;
            this.metroButton11.Click += new System.EventHandler(this.metroButton11_Click);
            // 
            // metroLabel4
            // 
            this.metroLabel4.AutoSize = true;
            this.metroLabel4.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel4.Location = new System.Drawing.Point(17, 9);
            this.metroLabel4.Name = "metroLabel4";
            this.metroLabel4.Size = new System.Drawing.Size(112, 25);
            this.metroLabel4.TabIndex = 1;
            this.metroLabel4.Text = "Обновления";
            // 
            // tabPage7
            // 
            this.tabPage7.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage7.Controls.Add(this.label_scanned_file);
            this.tabPage7.Controls.Add(this.scanProgressSpinner);
            this.tabPage7.Controls.Add(this.foundVirusesCount);
            this.tabPage7.Controls.Add(this.metroLabel17);
            this.tabPage7.Controls.Add(this.page_active_scan_all_count);
            this.tabPage7.Controls.Add(this.metroLabel16);
            this.tabPage7.Controls.Add(this.page_active_scan_scanned);
            this.tabPage7.Controls.Add(this.pauseScan);
            this.tabPage7.Controls.Add(this.metroButton3);
            this.tabPage7.Controls.Add(this.metroLabel11);
            this.tabPage7.Controls.Add(this.metroLabel10);
            this.tabPage7.Controls.Add(this.progressBar);
            this.tabPage7.Controls.Add(this.metroLabel9);
            this.tabPage7.Location = new System.Drawing.Point(4, 14);
            this.tabPage7.Name = "tabPage7";
            this.tabPage7.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage7.Size = new System.Drawing.Size(896, 415);
            this.tabPage7.TabIndex = 6;
            this.tabPage7.Text = "page_active_scan";
            this.tabPage7.Enter += new System.EventHandler(this.tabPage7_Enter);
            // 
            // label_scanned_file
            // 
            this.label_scanned_file.AutoSize = true;
            this.label_scanned_file.Location = new System.Drawing.Point(52, 109);
            this.label_scanned_file.Name = "label_scanned_file";
            this.label_scanned_file.Size = new System.Drawing.Size(13, 19);
            this.label_scanned_file.TabIndex = 16;
            this.label_scanned_file.Text = " ";
            // 
            // scanProgressSpinner
            // 
            this.scanProgressSpinner.Location = new System.Drawing.Point(826, 68);
            this.scanProgressSpinner.Maximum = 100;
            this.scanProgressSpinner.Name = "scanProgressSpinner";
            this.scanProgressSpinner.Size = new System.Drawing.Size(38, 38);
            this.scanProgressSpinner.TabIndex = 15;
            this.scanProgressSpinner.UseSelectable = true;
            // 
            // foundVirusesCount
            // 
            this.foundVirusesCount.AutoSize = true;
            this.foundVirusesCount.Location = new System.Drawing.Point(178, 219);
            this.foundVirusesCount.Name = "foundVirusesCount";
            this.foundVirusesCount.Size = new System.Drawing.Size(16, 19);
            this.foundVirusesCount.TabIndex = 14;
            this.foundVirusesCount.Text = "0";
            // 
            // metroLabel17
            // 
            this.metroLabel17.AutoSize = true;
            this.metroLabel17.Location = new System.Drawing.Point(52, 219);
            this.metroLabel17.Name = "metroLabel17";
            this.metroLabel17.Size = new System.Drawing.Size(129, 19);
            this.metroLabel17.TabIndex = 13;
            this.metroLabel17.Text = "Обнаружено угроз:";
            // 
            // page_active_scan_all_count
            // 
            this.page_active_scan_all_count.AutoSize = true;
            this.page_active_scan_all_count.Location = new System.Drawing.Point(153, 164);
            this.page_active_scan_all_count.Name = "page_active_scan_all_count";
            this.page_active_scan_all_count.Size = new System.Drawing.Size(16, 19);
            this.page_active_scan_all_count.TabIndex = 12;
            this.page_active_scan_all_count.Text = "0";
            // 
            // metroLabel16
            // 
            this.metroLabel16.AutoSize = true;
            this.metroLabel16.Location = new System.Drawing.Point(51, 164);
            this.metroLabel16.Name = "metroLabel16";
            this.metroLabel16.Size = new System.Drawing.Size(96, 19);
            this.metroLabel16.TabIndex = 11;
            this.metroLabel16.Text = "Всего файлов:";
            // 
            // page_active_scan_scanned
            // 
            this.page_active_scan_scanned.AutoSize = true;
            this.page_active_scan_scanned.Location = new System.Drawing.Point(210, 191);
            this.page_active_scan_scanned.Name = "page_active_scan_scanned";
            this.page_active_scan_scanned.Size = new System.Drawing.Size(16, 19);
            this.page_active_scan_scanned.TabIndex = 9;
            this.page_active_scan_scanned.Text = "0";
            // 
            // pauseScan
            // 
            this.pauseScan.Location = new System.Drawing.Point(553, 351);
            this.pauseScan.Name = "pauseScan";
            this.pauseScan.Size = new System.Drawing.Size(131, 34);
            this.pauseScan.TabIndex = 8;
            this.pauseScan.Text = "Приостановить";
            this.pauseScan.UseSelectable = true;
            this.pauseScan.Click += new System.EventHandler(this.metroButton4_Click);
            // 
            // metroButton3
            // 
            this.metroButton3.Location = new System.Drawing.Point(690, 351);
            this.metroButton3.Name = "metroButton3";
            this.metroButton3.Size = new System.Drawing.Size(187, 34);
            this.metroButton3.TabIndex = 7;
            this.metroButton3.Text = "Завершить сканирование";
            this.metroButton3.UseSelectable = true;
            this.metroButton3.Click += new System.EventHandler(this.metroButton3_Click);
            // 
            // metroLabel11
            // 
            this.metroLabel11.AutoSize = true;
            this.metroLabel11.Location = new System.Drawing.Point(52, 191);
            this.metroLabel11.Name = "metroLabel11";
            this.metroLabel11.Size = new System.Drawing.Size(152, 19);
            this.metroLabel11.TabIndex = 5;
            this.metroLabel11.Text = "Всего отсканированно:";
            // 
            // metroLabel10
            // 
            this.metroLabel10.AutoSize = true;
            this.metroLabel10.Location = new System.Drawing.Point(51, 136);
            this.metroLabel10.Name = "metroLabel10";
            this.metroLabel10.Size = new System.Drawing.Size(153, 19);
            this.metroLabel10.TabIndex = 4;
            this.metroLabel10.Text = "Сканирование активно";
            // 
            // progressBar
            // 
            this.progressBar.Location = new System.Drawing.Point(51, 68);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(769, 38);
            this.progressBar.TabIndex = 3;
            // 
            // metroLabel9
            // 
            this.metroLabel9.AutoSize = true;
            this.metroLabel9.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel9.Location = new System.Drawing.Point(17, 9);
            this.metroLabel9.Name = "metroLabel9";
            this.metroLabel9.Size = new System.Drawing.Size(158, 25);
            this.metroLabel9.TabIndex = 2;
            this.metroLabel9.Text = "Ход сканирования";
            // 
            // tabPage8
            // 
            this.tabPage8.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage8.Controls.Add(this.scanFoundResult);
            this.tabPage8.Controls.Add(this.metroLabel13);
            this.tabPage8.Controls.Add(this.page_result_text);
            this.tabPage8.Controls.Add(this.ApplyingActions);
            this.tabPage8.Controls.Add(this.metroLabel19);
            this.tabPage8.Controls.Add(this.metroListView4);
            this.tabPage8.Controls.Add(this.page_scan_result_all_scanned);
            this.tabPage8.Controls.Add(this.metroLabel18);
            this.tabPage8.Controls.Add(this.metroLabel12);
            this.tabPage8.Location = new System.Drawing.Point(4, 14);
            this.tabPage8.Name = "tabPage8";
            this.tabPage8.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage8.Size = new System.Drawing.Size(896, 415);
            this.tabPage8.TabIndex = 7;
            this.tabPage8.Text = "page_scan_result";
            // 
            // scanFoundResult
            // 
            this.scanFoundResult.AutoSize = true;
            this.scanFoundResult.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.scanFoundResult.Location = new System.Drawing.Point(235, 67);
            this.scanFoundResult.Name = "scanFoundResult";
            this.scanFoundResult.Size = new System.Drawing.Size(21, 25);
            this.scanFoundResult.TabIndex = 11;
            this.scanFoundResult.Text = "0";
            // 
            // metroLabel13
            // 
            this.metroLabel13.AutoSize = true;
            this.metroLabel13.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel13.Location = new System.Drawing.Point(52, 67);
            this.metroLabel13.Name = "metroLabel13";
            this.metroLabel13.Size = new System.Drawing.Size(186, 25);
            this.metroLabel13.TabIndex = 10;
            this.metroLabel13.Text = "Обнаружено вирусов:";
            // 
            // page_result_text
            // 
            this.page_result_text.AutoSize = true;
            this.page_result_text.Location = new System.Drawing.Point(52, 67);
            this.page_result_text.Name = "page_result_text";
            this.page_result_text.Size = new System.Drawing.Size(13, 19);
            this.page_result_text.TabIndex = 9;
            this.page_result_text.Text = " ";
            // 
            // ApplyingActions
            // 
            this.ApplyingActions.Location = new System.Drawing.Point(741, 128);
            this.ApplyingActions.Name = "ApplyingActions";
            this.ApplyingActions.Size = new System.Drawing.Size(149, 23);
            this.ApplyingActions.TabIndex = 8;
            this.ApplyingActions.Text = "Выполнить действия";
            this.ApplyingActions.UseSelectable = true;
            this.ApplyingActions.Click += new System.EventHandler(this.metroButton12_Click);
            // 
            // metroLabel19
            // 
            this.metroLabel19.AutoSize = true;
            this.metroLabel19.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel19.Location = new System.Drawing.Point(52, 132);
            this.metroLabel19.Name = "metroLabel19";
            this.metroLabel19.Size = new System.Drawing.Size(193, 25);
            this.metroLabel19.TabIndex = 7;
            this.metroLabel19.Text = "Обнаруженные угрозы";
            // 
            // metroListView4
            // 
            this.metroListView4.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader6,
            this.columnHeader12,
            this.columnHeader15});
            this.metroListView4.ContextMenuStrip = this.setAction;
            this.metroListView4.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.metroListView4.FullRowSelect = true;
            this.metroListView4.Location = new System.Drawing.Point(3, 157);
            this.metroListView4.Name = "metroListView4";
            this.metroListView4.OwnerDraw = true;
            this.metroListView4.Size = new System.Drawing.Size(887, 252);
            this.metroListView4.TabIndex = 6;
            this.metroListView4.UseCompatibleStateImageBehavior = false;
            this.metroListView4.UseSelectable = true;
            this.metroListView4.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader6
            // 
            this.columnHeader6.Text = "Файл";
            this.columnHeader6.Width = 560;
            // 
            // columnHeader12
            // 
            this.columnHeader12.Text = "Тип вируса";
            this.columnHeader12.Width = 200;
            // 
            // columnHeader15
            // 
            this.columnHeader15.Text = "Действие";
            this.columnHeader15.Width = 123;
            // 
            // setAction
            // 
            this.setAction.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.вКарантинToolStripMenuItem,
            this.удалитьToolStripMenuItem3,
            this.ничегоНеДелатьToolStripMenuItem});
            this.setAction.Name = "setAction";
            this.setAction.Size = new System.Drawing.Size(171, 70);
            // 
            // вКарантинToolStripMenuItem
            // 
            this.вКарантинToolStripMenuItem.Name = "вКарантинToolStripMenuItem";
            this.вКарантинToolStripMenuItem.Size = new System.Drawing.Size(170, 22);
            this.вКарантинToolStripMenuItem.Text = "В карантин";
            this.вКарантинToolStripMenuItem.Click += new System.EventHandler(this.вКарантинToolStripMenuItem_Click);
            // 
            // удалитьToolStripMenuItem3
            // 
            this.удалитьToolStripMenuItem3.Name = "удалитьToolStripMenuItem3";
            this.удалитьToolStripMenuItem3.Size = new System.Drawing.Size(170, 22);
            this.удалитьToolStripMenuItem3.Text = "Удалить";
            this.удалитьToolStripMenuItem3.Click += new System.EventHandler(this.удалитьToolStripMenuItem3_Click);
            // 
            // ничегоНеДелатьToolStripMenuItem
            // 
            this.ничегоНеДелатьToolStripMenuItem.Name = "ничегоНеДелатьToolStripMenuItem";
            this.ничегоНеДелатьToolStripMenuItem.Size = new System.Drawing.Size(170, 22);
            this.ничегоНеДелатьToolStripMenuItem.Text = "Ничего не делать";
            this.ничегоНеДелатьToolStripMenuItem.Click += new System.EventHandler(this.ничегоНеДелатьToolStripMenuItem_Click);
            // 
            // page_scan_result_all_scanned
            // 
            this.page_scan_result_all_scanned.AutoSize = true;
            this.page_scan_result_all_scanned.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.page_scan_result_all_scanned.Location = new System.Drawing.Point(274, 44);
            this.page_scan_result_all_scanned.Name = "page_scan_result_all_scanned";
            this.page_scan_result_all_scanned.Size = new System.Drawing.Size(21, 25);
            this.page_scan_result_all_scanned.TabIndex = 5;
            this.page_scan_result_all_scanned.Text = "0";
            // 
            // metroLabel18
            // 
            this.metroLabel18.AutoSize = true;
            this.metroLabel18.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel18.Location = new System.Drawing.Point(52, 44);
            this.metroLabel18.Name = "metroLabel18";
            this.metroLabel18.Size = new System.Drawing.Size(225, 25);
            this.metroLabel18.TabIndex = 4;
            this.metroLabel18.Text = "Всего проверенно файлов:";
            // 
            // metroLabel12
            // 
            this.metroLabel12.AutoSize = true;
            this.metroLabel12.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel12.Location = new System.Drawing.Point(17, 9);
            this.metroLabel12.Name = "metroLabel12";
            this.metroLabel12.Size = new System.Drawing.Size(214, 25);
            this.metroLabel12.TabIndex = 3;
            this.metroLabel12.Text = "Результаты сканирования";
            // 
            // tabPage9
            // 
            this.tabPage9.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.tabPage9.Controls.Add(this.metroButton4);
            this.tabPage9.Controls.Add(this.metroButton2);
            this.tabPage9.Controls.Add(this.cryptoTable);
            this.tabPage9.Controls.Add(this.metroButton1);
            this.tabPage9.Controls.Add(this.metroLabel21);
            this.tabPage9.Location = new System.Drawing.Point(4, 14);
            this.tabPage9.Name = "tabPage9";
            this.tabPage9.Size = new System.Drawing.Size(896, 415);
            this.tabPage9.TabIndex = 8;
            this.tabPage9.Text = "page_cryptograph";
            // 
            // metroButton4
            // 
            this.metroButton4.Location = new System.Drawing.Point(521, 372);
            this.metroButton4.Name = "metroButton4";
            this.metroButton4.Size = new System.Drawing.Size(114, 23);
            this.metroButton4.TabIndex = 9;
            this.metroButton4.Text = "Зашифровать";
            this.metroButton4.UseSelectable = true;
            this.metroButton4.Click += new System.EventHandler(this.metroButton4_Click_1);
            // 
            // metroButton2
            // 
            this.metroButton2.Location = new System.Drawing.Point(657, 372);
            this.metroButton2.Name = "metroButton2";
            this.metroButton2.Size = new System.Drawing.Size(114, 23);
            this.metroButton2.TabIndex = 8;
            this.metroButton2.Text = "Расшифровать";
            this.metroButton2.UseSelectable = true;
            this.metroButton2.Click += new System.EventHandler(this.metroButton2_Click_1);
            // 
            // cryptoTable
            // 
            this.cryptoTable.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader3,
            this.columnHeader4,
            this.columnHeader9});
            this.cryptoTable.ContextMenuStrip = this.metroContextMenu1;
            this.cryptoTable.FullRowSelect = true;
            this.cryptoTable.HideSelection = false;
            this.cryptoTable.Location = new System.Drawing.Point(17, 37);
            this.cryptoTable.Name = "cryptoTable";
            this.cryptoTable.Size = new System.Drawing.Size(860, 329);
            this.cryptoTable.TabIndex = 7;
            this.cryptoTable.UseCompatibleStateImageBehavior = false;
            this.cryptoTable.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader3
            // 
            this.columnHeader3.Text = "Файл";
            this.columnHeader3.Width = 540;
            // 
            // columnHeader4
            // 
            this.columnHeader4.Text = "Размер (Мегабайт)";
            this.columnHeader4.Width = 196;
            // 
            // columnHeader9
            // 
            this.columnHeader9.Text = "Зашифрован";
            this.columnHeader9.Width = 120;
            // 
            // metroContextMenu1
            // 
            this.metroContextMenu1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.добавитьФайлToolStripMenuItem1,
            this.удалитьФайлToolStripMenuItem1,
            this.удалитьФайлИзЖесткогоДискаToolStripMenuItem,
            this.зашифроватьToolStripMenuItem,
            this.расшифроватьToolStripMenuItem});
            this.metroContextMenu1.Name = "metroContextMenu1";
            this.metroContextMenu1.Size = new System.Drawing.Size(254, 114);
            // 
            // добавитьФайлToolStripMenuItem1
            // 
            this.добавитьФайлToolStripMenuItem1.Name = "добавитьФайлToolStripMenuItem1";
            this.добавитьФайлToolStripMenuItem1.Size = new System.Drawing.Size(253, 22);
            this.добавитьФайлToolStripMenuItem1.Text = "Добавить файл";
            this.добавитьФайлToolStripMenuItem1.Click += new System.EventHandler(this.добавитьФайлToolStripMenuItem1_Click);
            // 
            // удалитьФайлToolStripMenuItem1
            // 
            this.удалитьФайлToolStripMenuItem1.Name = "удалитьФайлToolStripMenuItem1";
            this.удалитьФайлToolStripMenuItem1.Size = new System.Drawing.Size(253, 22);
            this.удалитьФайлToolStripMenuItem1.Text = "Удалить файл из списка";
            this.удалитьФайлToolStripMenuItem1.Click += new System.EventHandler(this.удалитьФайлToolStripMenuItem1_Click);
            // 
            // удалитьФайлИзЖесткогоДискаToolStripMenuItem
            // 
            this.удалитьФайлИзЖесткогоДискаToolStripMenuItem.Name = "удалитьФайлИзЖесткогоДискаToolStripMenuItem";
            this.удалитьФайлИзЖесткогоДискаToolStripMenuItem.Size = new System.Drawing.Size(253, 22);
            this.удалитьФайлИзЖесткогоДискаToolStripMenuItem.Text = "Удалить файл из жесткого диска";
            this.удалитьФайлИзЖесткогоДискаToolStripMenuItem.Click += new System.EventHandler(this.удалитьФайлИзЖесткогоДискаToolStripMenuItem_Click);
            // 
            // зашифроватьToolStripMenuItem
            // 
            this.зашифроватьToolStripMenuItem.Name = "зашифроватьToolStripMenuItem";
            this.зашифроватьToolStripMenuItem.Size = new System.Drawing.Size(253, 22);
            this.зашифроватьToolStripMenuItem.Text = "Зашифровать";
            this.зашифроватьToolStripMenuItem.Click += new System.EventHandler(this.зашифроватьToolStripMenuItem_Click);
            // 
            // расшифроватьToolStripMenuItem
            // 
            this.расшифроватьToolStripMenuItem.Name = "расшифроватьToolStripMenuItem";
            this.расшифроватьToolStripMenuItem.Size = new System.Drawing.Size(253, 22);
            this.расшифроватьToolStripMenuItem.Text = "Расшифровать";
            this.расшифроватьToolStripMenuItem.Click += new System.EventHandler(this.расшифроватьToolStripMenuItem_Click);
            // 
            // metroButton1
            // 
            this.metroButton1.Location = new System.Drawing.Point(802, 372);
            this.metroButton1.Name = "metroButton1";
            this.metroButton1.Size = new System.Drawing.Size(75, 23);
            this.metroButton1.TabIndex = 6;
            this.metroButton1.Text = "На главную";
            this.metroButton1.UseSelectable = true;
            this.metroButton1.Click += new System.EventHandler(this.metroButton1_Click_1);
            // 
            // metroLabel21
            // 
            this.metroLabel21.AutoSize = true;
            this.metroLabel21.FontSize = MetroFramework.MetroLabelSize.Tall;
            this.metroLabel21.Location = new System.Drawing.Point(17, 9);
            this.metroLabel21.Name = "metroLabel21";
            this.metroLabel21.Size = new System.Drawing.Size(254, 25);
            this.metroLabel21.TabIndex = 4;
            this.metroLabel21.Text = "Защита файлов шифрованием";
            // 
            // MonPartitionContextMenu
            // 
            this.MonPartitionContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.добавитьToolStripMenuItem1,
            this.удалитьToolStripMenuItem1});
            this.MonPartitionContextMenu.Name = "MonPartitionContextMenu";
            this.MonPartitionContextMenu.Size = new System.Drawing.Size(127, 48);
            // 
            // добавитьToolStripMenuItem1
            // 
            this.добавитьToolStripMenuItem1.Name = "добавитьToolStripMenuItem1";
            this.добавитьToolStripMenuItem1.Size = new System.Drawing.Size(126, 22);
            this.добавитьToolStripMenuItem1.Text = "Добавить";
            // 
            // удалитьToolStripMenuItem1
            // 
            this.удалитьToolStripMenuItem1.Name = "удалитьToolStripMenuItem1";
            this.удалитьToolStripMenuItem1.Size = new System.Drawing.Size(126, 22);
            this.удалитьToolStripMenuItem1.Text = "Удалить";
            // 
            // notifyIcon
            // 
            this.notifyIcon.ContextMenuStrip = this.notifyIconContextMenu;
            this.notifyIcon.Icon = ((System.Drawing.Icon)(resources.GetObject("notifyIcon.Icon")));
            this.notifyIcon.Text = "Защита активна";
            this.notifyIcon.Visible = true;
            this.notifyIcon.DoubleClick += new System.EventHandler(this.notifyIcon_DoubleClick);
            // 
            // notifyIconContextMenu
            // 
            this.notifyIconContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.открытьToolStripMenuItem,
            this.приостановитьЗащитуToolStripMenuItem,
            this.выходToolStripMenuItem});
            this.notifyIconContextMenu.Name = "notifyIconContextMenu";
            this.notifyIconContextMenu.Size = new System.Drawing.Size(203, 70);
            // 
            // открытьToolStripMenuItem
            // 
            this.открытьToolStripMenuItem.Name = "открытьToolStripMenuItem";
            this.открытьToolStripMenuItem.Size = new System.Drawing.Size(202, 22);
            this.открытьToolStripMenuItem.Text = "Открыть";
            this.открытьToolStripMenuItem.Click += new System.EventHandler(this.открытьToolStripMenuItem_Click);
            // 
            // приостановитьЗащитуToolStripMenuItem
            // 
            this.приостановитьЗащитуToolStripMenuItem.Name = "приостановитьЗащитуToolStripMenuItem";
            this.приостановитьЗащитуToolStripMenuItem.Size = new System.Drawing.Size(202, 22);
            this.приостановитьЗащитуToolStripMenuItem.Text = "Приостановить защиту";
            this.приостановитьЗащитуToolStripMenuItem.Click += new System.EventHandler(this.приостановитьЗащитуToolStripMenuItem_Click);
            // 
            // выходToolStripMenuItem
            // 
            this.выходToolStripMenuItem.Name = "выходToolStripMenuItem";
            this.выходToolStripMenuItem.Size = new System.Drawing.Size(202, 22);
            this.выходToolStripMenuItem.Text = "Выход";
            this.выходToolStripMenuItem.Click += new System.EventHandler(this.выходToolStripMenuItem_Click);
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // active_scan_updater
            // 
            this.active_scan_updater.Interval = 50;
            this.active_scan_updater.Tick += new System.EventHandler(this.active_scan_updater_Tick);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(906, 459);
            this.Controls.Add(this.TabControl);
            this.MaximizeBox = false;
            this.Name = "MainForm";
            this.Resizable = false;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MainForm_FormClosing);
            this.TabControl.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.addToScan.ResumeLayout(false);
            this.tabPage3.ResumeLayout(false);
            this.tabPage3.PerformLayout();
            this.tabPage4.ResumeLayout(false);
            this.tabPage4.PerformLayout();
            this.quarantineContextMenu.ResumeLayout(false);
            this.tabPage5.ResumeLayout(false);
            this.tabPage5.PerformLayout();
            this.ExceptionFileContextMenu.ResumeLayout(false);
            this.ExceptionPathContextMenu.ResumeLayout(false);
            this.tabPage6.ResumeLayout(false);
            this.tabPage6.PerformLayout();
            this.tabPage7.ResumeLayout(false);
            this.tabPage7.PerformLayout();
            this.tabPage8.ResumeLayout(false);
            this.tabPage8.PerformLayout();
            this.setAction.ResumeLayout(false);
            this.tabPage9.ResumeLayout(false);
            this.tabPage9.PerformLayout();
            this.metroContextMenu1.ResumeLayout(false);
            this.MonPartitionContextMenu.ResumeLayout(false);
            this.notifyIconContextMenu.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.TabPage tabPage1;
        private MetroFramework.Controls.MetroTile ExceptionsButton;
        private MetroFramework.Controls.MetroTile UpdateButton;
        private MetroFramework.Controls.MetroTile QuarantineButton;
        private MetroFramework.Controls.MetroTile settingsButton;
        private MetroFramework.Controls.MetroTile ScanButton;
        private MetroFramework.Controls.MetroTile metroTile1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.TabPage tabPage4;
        private System.Windows.Forms.TabPage tabPage5;
        private System.Windows.Forms.TabPage tabPage6;
        private MetroFramework.Controls.MetroListView exceptionFiles;
        private MetroFramework.Controls.MetroLabel metroLabel3;
        private MetroFramework.Controls.MetroListView exceptionPaths;
        private MetroFramework.Controls.MetroLabel metroLabel2;
        private MetroFramework.Controls.MetroLabel metroLabel1;
        private MetroFramework.Controls.MetroContextMenu ExceptionPathContextMenu;
        private System.Windows.Forms.ToolStripMenuItem добавитьToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem удалитьToolStripMenuItem;
        private MetroFramework.Controls.MetroLabel metroLabel6;
        private MetroFramework.Controls.MetroLabel metroLabel5;
        private MetroFramework.Controls.MetroLabel metroLabel7;
        private MetroFramework.Controls.MetroLabel metroLabel4;
        private MetroFramework.Controls.MetroContextMenu MonPartitionContextMenu;
        private System.Windows.Forms.ToolStripMenuItem добавитьToolStripMenuItem1;
        private System.Windows.Forms.ToolStripMenuItem удалитьToolStripMenuItem1;
        private MetroFramework.Controls.MetroButton page_exceptions_back_to_main;
        private MetroFramework.Controls.MetroButton saveExceptions;
        private System.Windows.Forms.NotifyIcon notifyIcon;
        private MetroFramework.Controls.MetroListView ScanObjectsList;
        private MetroFramework.Controls.MetroButton startScanButton;
        private System.Windows.Forms.TabPage tabPage7;
        private MetroFramework.Controls.MetroLabel metroLabel9;
        private MetroFramework.Controls.MetroButton pauseScan;
        private MetroFramework.Controls.MetroButton metroButton3;
        private MetroFramework.Controls.MetroLabel metroLabel11;
        private MetroFramework.Controls.MetroLabel metroLabel10;
        private MetroFramework.Controls.MetroProgressBar progressBar;
        private MetroFramework.Controls.MetroButton metroButton6;
        private MetroFramework.Controls.MetroButton metroButton5;
        private MetroFramework.Controls.MetroButton metroButton9;
        private MetroFramework.Controls.MetroButton metroButton8;
        private MetroFramework.Controls.MetroButton saveSettings;
        private MetroFramework.Controls.MetroCheckBox metroCheckBox2;
        private MetroFramework.Controls.MetroCheckBox metroCheckBox1;
        private MetroFramework.Controls.MetroContextMenu quarantineContextMenu;
        private System.Windows.Forms.ToolStripMenuItem восстановитьФайлToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem удалитьФайлToolStripMenuItem;
        private MetroFramework.Controls.MetroButton metroButton10;
        private MetroFramework.Controls.MetroLabel metroLabel15;
        private MetroFramework.Controls.MetroLabel metroLabel14;
        private MetroFramework.Controls.MetroButton metroButton11;
        private MetroFramework.Controls.MetroContextMenu addToScan;
        private System.Windows.Forms.ToolStripMenuItem добавитьПапкуToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem добавитьФайлToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem удалитьToolStripMenuItem2;
        private FolderBrowserDialog folderBrowserDialog1;
        private OpenFileDialog openFileDialog1;
        private ColumnHeader columnHeader10;
        private ColumnHeader columnHeader11;
        private Timer active_scan_updater;
        private MetroFramework.Controls.MetroLabel page_active_scan_scanned;
        private MetroFramework.Controls.MetroLabel page_active_scan_all_count;
        private MetroFramework.Controls.MetroLabel metroLabel16;
        private MetroFramework.Controls.MetroLabel foundVirusesCount;
        private MetroFramework.Controls.MetroLabel metroLabel17;
        private TabPage tabPage8;
        private MetroFramework.Controls.MetroLabel metroLabel12;
        private MetroFramework.Controls.MetroLabel metroLabel19;
        private MetroFramework.Controls.MetroListView metroListView4;
        private MetroFramework.Controls.MetroLabel page_scan_result_all_scanned;
        private MetroFramework.Controls.MetroLabel metroLabel18;
        private MetroFramework.Controls.MetroProgressSpinner scanProgressSpinner;
        private MetroFramework.Controls.MetroButton ApplyingActions;
        private MetroFramework.Controls.MetroLabel label_scanned_file;
        private MetroFramework.Controls.MetroLabel page_result_text;
        private MetroFramework.Controls.MetroContextMenu setAction;
        private ToolStripMenuItem вКарантинToolStripMenuItem;
        private ToolStripMenuItem удалитьToolStripMenuItem3;
        private ToolStripMenuItem ничегоНеДелатьToolStripMenuItem;
        private MetroFramework.Controls.MetroLabel scanFoundResult;
        private MetroFramework.Controls.MetroLabel metroLabel13;
        private ColumnHeader columnHeader6;
        private ColumnHeader columnHeader12;
        private ColumnHeader columnHeader15;
        public TabControl TabControl;
        private ColumnHeader columnHeader5;
        private ColumnHeader columnHeader13;
        private MetroFramework.Controls.MetroContextMenu notifyIconContextMenu;
        private ToolStripMenuItem открытьToolStripMenuItem;
        private ToolStripMenuItem выходToolStripMenuItem;
        private MetroFramework.Controls.MetroLabel latestSignatureDB_ver;
        private MetroFramework.Controls.MetroLabel activeSignatureDB_ver;
        private MetroFramework.Controls.MetroLabel metroLabel20;
        private MetroFramework.Controls.MetroContextMenu ExceptionFileContextMenu;
        private ToolStripMenuItem toolStripMenuItem1;
        private ToolStripMenuItem toolStripMenuItem2;
        private ColumnHeader columnHeader7;
        private ColumnHeader columnHeader8;
        private ColumnHeader columnHeader1;
        private ColumnHeader columnHeader2;
        private MetroFramework.Controls.MetroComboBox settingsAutoAction;
        private MetroFramework.Controls.MetroLabel metroLabel8;
        private MetroFramework.Controls.MetroTile progInfo;
        private ToolStripMenuItem приостановитьЗащитуToolStripMenuItem;
        private MetroFramework.Controls.MetroTile Cryptographer;
        private TabPage tabPage9;
        private MetroFramework.Controls.MetroLabel metroLabel21;
        private MetroFramework.Controls.MetroButton metroButton1;
        private ListView cryptoTable;
        private ColumnHeader columnHeader3;
        private ColumnHeader columnHeader4;
        private MetroFramework.Controls.MetroContextMenu metroContextMenu1;
        private ToolStripMenuItem добавитьФайлToolStripMenuItem1;
        private ToolStripMenuItem удалитьФайлToolStripMenuItem1;
        private ToolStripMenuItem удалитьФайлИзЖесткогоДискаToolStripMenuItem;
        private ToolStripMenuItem зашифроватьToolStripMenuItem;
        private ToolStripMenuItem расшифроватьToolStripMenuItem;
        private MetroFramework.Controls.MetroButton metroButton4;
        private MetroFramework.Controls.MetroButton metroButton2;
        private SaveFileDialog saveFileDialog1;
        private ColumnHeader columnHeader9;
        public MetroFramework.Controls.MetroListView quarantine_files;
    }










    /*MY*/
    class myTabControl : TabControl
    {
        public myTabControl() : base()
        {
            base.Multiline = true;
            base.Appearance = TabAppearance.Buttons;
            base.ItemSize = new System.Drawing.Size(0, 1);
            base.SizeMode = TabSizeMode.Fixed;
            base.TabStop = false;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            e.Graphics.DrawRectangle(Pens.Red, new Rectangle(base.Location.X, base.Location.Y, 100, 100));
            e.Graphics.FillRectangle(new SolidBrush(Color.Blue), new Rectangle(base.Location.X, base.Location.Y, 100, 100));
        }
    }
}

