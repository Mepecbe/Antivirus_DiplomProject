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
        /// Автозапуск GUI
        /// </summary>
        public bool GUI_Autostart { get; private set; }

        private FileStream SystemConftFile;
        private XmlDocument SystemXmlFile = new XmlDocument();

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
                        $"<guiautostart>true</guiautostart>\n" +
                        "</sysConf>\n"
                        );
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

                /**/
                {
                    var XmlEncode = getElementValueByName("guiautostart", root);

                    if(XmlEncode != null)
                    {
                        this.GUI_Autostart = bool.Parse(XmlEncode.InnerText);
                    }
                }
            }


            KernelConnectors.Logger.WriteLine("[Configuration] Конфигурация загружена", LoggerLib.LogLevel.OK);
        }



        /// <summary>
        /// Найти XML элемент по имени среди потомков 
        /// </summary>
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
                NamedPipeEncoding = Encoding.Unicode             
            };
        }
    }
}
