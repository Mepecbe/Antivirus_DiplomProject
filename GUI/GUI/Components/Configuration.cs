﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Xml;
using System.Xml.Serialization;

using API_Client_Library;

namespace GUI.Components.Configurations
{
    static class Configuration
    {
        private static readonly XmlDocument Doc;
        private static readonly XmlElement Root;

        /// <summary>
        /// Уведомления при обнаружении вируса
        /// </summary>
        public static bool Notify_FoundVirus {
            get { return bool.Parse(getElementValueByName("Notify_FoundVirus").InnerText); } 
            set { getElementValueByName("Notify_FoundVirus").InnerText = value.ToString(); }
        }

        /// <summary>
        /// Автоскан подключаемых съемных носителей
        /// </summary>
        public static bool AutoScanRemovableDevices
        {
            get { return bool.Parse(getElementValueByName("RemovableDevices_AutoScan").InnerText); }
            set { getElementValueByName("RemovableDevices_AutoScan").InnerText = value.ToString(); }
        }

        /// <summary>
        /// Действие осуществляемое автоматически над обнаруженным вирусом
        /// </summary>
        public static ActionType AutoAction
        {
            get { return ((ActionType)byte.Parse(getElementValueByName("Action").InnerText)); }
            set { getElementValueByName("Action").InnerText = ((byte)value).ToString(); }
        }


        public static string[] PathExceptions
        {
            get {
                var element = getElementValueByName("ExceptionPaths");
                List<string> paths = new List<string>();
                foreach(XmlElement elem in element.ChildNodes)
                {

                    paths.Add(elem.InnerText);
                }

                return paths.ToArray();
            }

            set
            {
                var element = getElementValueByName("ExceptionPaths");

                for(int index = element.ChildNodes.Count - 1; index >= 0; index--)
                {
                    element.RemoveChild(element.ChildNodes[index]);
                }

                foreach(string path in value)
                {
                    var elem = Doc.CreateElement("path");
                    elem.InnerText = path;

                    element.AppendChild(elem);
                }
            }
        }

        public static string[] ExtentionExceptions
        {
            get
            {
                var element = getElementValueByName("Extentions");
                List<string> paths = new List<string>();
                foreach (XmlElement elem in element.ChildNodes)
                {
                    paths.Add(elem.InnerText);
                }

                return paths.ToArray();
            }

            set
            {
                var element = getElementValueByName("Extentions");

                for (int index = element.ChildNodes.Count - 1; index >= 0; index--)
                {
                    element.RemoveChild(element.ChildNodes[index]);
                }

                foreach (string path in value)
                {
                    var elem = Doc.CreateElement("filepath");
                    elem.InnerText = path;

                    element.AppendChild(elem);
                }
            }
        }


        public static void Save()
        {
            Doc.Save("UserConf.xml");
        }

        static Configuration()
        {
            Doc = new XmlDocument();

            if (!File.Exists("UserConf.xml"))
            {
                var file = new StreamWriter(File.Create("UserConf.xml"));
                file.WriteLine($"<?xml version=\"1.0\"?>\n" +
                    $"<conf>" +
                    $" <Notify_FoundVirus>true</Notify_FoundVirus>\n" +
                    $" <RemovableDevices_AutoScan>true</RemovableDevices_AutoScan>\n" +
                    $" <ExceptionPaths></ExceptionPaths>\n" +
                    $" <Extentions></Extentions>\n" +
                    $" <Action>1</Action>\n" +
                    $"</conf>");
                file.Close();
            }

            Doc.Load("UserConf.xml");
            Root = Doc.DocumentElement;
        }

        private static XmlElement getElementValueByName(string name)
        {
            foreach (XmlElement child in Root.ChildNodes)
            {
                if (child.Name == name)
                {
                    return child;
                }
            }

            return null;
        }
    }
}
