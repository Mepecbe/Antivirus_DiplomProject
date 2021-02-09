using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Xml;
using System.Xml.Serialization;

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
        /// Уведомления при обнаружении вируса
        /// </summary>
        public static bool AutoScanRemovableDevices
        {
            get { return bool.Parse(getElementValueByName("RemovableDevices_AutoScan").InnerText); }
            set { getElementValueByName("RemovableDevices_AutoScan").InnerText = value.ToString(); }
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
                    $" <RemovableDevices_AutoScan>true</RemovableDevices_AutoScan>\n"
                    + $"</conf>");
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
