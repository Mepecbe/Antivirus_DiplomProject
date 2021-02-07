using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Core.Kernel.Connectors;

using System.IO;
using System.Xml;
using System.Xml.Serialization;


namespace Core.Kernel.Configurations
{
    [Serializable]
    public class Configuration
    {
        /// <summary>
        /// Кодировка именованных каналов(труб)
        /// </summary>
        public Encoding NamedPipeEncoding { get; private set; }

        /// <summary>
        /// Пользовательские настройки
        /// </summary>
        public UserSettings userSettings { get; private set; }

        private FileStream SystemConftFile;
        private XmlDocument SystemXmlFile = new XmlDocument();

        private FileStream UserConfFile;
        private XmlDocument UserXmlFile = new XmlDocument();

        private XmlSerializer UserSettingsFormatter = new XmlSerializer(typeof(UserSettings));

        public Configuration()
        {

        }

        public Configuration(string pathToSystemConf, string pathToUserConf)
        {
            /*Check conf files*/
            {
                var defaultConf = GetDefaultConfiguration();

                if (!File.Exists(pathToSystemConf))
                {
                    KernelConnectors.Logger.WriteLine("[Configuration] CREATE SYSTEM CONF", LoggerLib.LogLevel.WARN);

                    var file = new StreamWriter(File.Create(pathToSystemConf));
                    file.WriteLine(
                        "<?xml version=\"1.0\"?>"
                        + "<sysConf>\n" +
                        $"<PipeEncode>{defaultConf.NamedPipeEncoding}</PipeEncode>\n" +
                        "</sysConf>\n"
                        );
                    file.Close();
                }

                if (!File.Exists(pathToUserConf))
                {
                    KernelConnectors.Logger.WriteLine("[Configuration] CREATE USER CONF", LoggerLib.LogLevel.WARN);

                    var file = new StreamWriter(File.Create(pathToUserConf));
                    UserSettingsFormatter.Serialize(file, defaultConf.userSettings);

                    KernelConnectors.Logger.WriteLine("[Configuration] CLOSE", LoggerLib.LogLevel.WARN);
                    file.Close();
                }
            }

            KernelConnectors.Logger.WriteLine("[Configuration] LOAD SYSTEM CONF", LoggerLib.LogLevel.WARN);

            {
                this.SystemConftFile = new FileStream(pathToSystemConf, FileMode.OpenOrCreate);
                SystemXmlFile.Load(this.SystemConftFile);

                var root = SystemXmlFile.DocumentElement;

                /* Named pipe encoding */
                {
                    var XmlEncode = getElementValueByName("PipeEncode", root);

                    {
                        if (XmlEncode != null)
                        {
                            switch (XmlEncode.InnerText)
                            {
                                case "System.Text.UTF8Encoding":
                                    {
                                        NamedPipeEncoding = Encoding.UTF8;
                                        break;
                                    }

                                case "System.Text.UnicodeEncoding":
                                    {
                                        NamedPipeEncoding = Encoding.Unicode;
                                        break;
                                    }

                                case "System.Text.UTF32Encoding":
                                    {
                                        NamedPipeEncoding = Encoding.UTF32;
                                        break;
                                    }
                            }
                        }
                    }
                }
            }

            /* User settings */
            KernelConnectors.Logger.WriteLine("[Configuration] LOAD USER CONF", LoggerLib.LogLevel.WARN);

            {
                UserConfFile = new FileStream(pathToUserConf, FileMode.OpenOrCreate);
                this.UserSettingsFormatter = new XmlSerializer(typeof(UserSettings));

                this.userSettings = (UserSettings)UserSettingsFormatter.Deserialize(this.UserConfFile);
                this.UserConfFile.Close();
            }

            KernelConnectors.Logger.WriteLine("[Configuration] LOAD SUCCESS", LoggerLib.LogLevel.OK);
        }








        private static XmlElement getElementValueByName(string name, XmlElement element)
        {
            foreach(XmlElement child in element.ChildNodes)
            {
                if(child.Name == name)
                {
                    return child;
                }
            }

            return null;
        }

        /// <summary>
        /// Загрузить стандартную конфигурацию
        /// </summary>
        /// <returns></returns>
        public static Configuration GetDefaultConfiguration()
        {
            return new Configuration
            {
                NamedPipeEncoding = Encoding.Unicode,

                userSettings = new UserSettings() 
                { 
                    Notify_FoundVirus = true 
                }                
            };
        }
    }

    /// <summary>
    /// Настройки пользователя
    /// </summary>
    [Serializable]
    public class UserSettings
    {
        public bool Notify_FoundVirus;
    }
}
