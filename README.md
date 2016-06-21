# fiwasp
        Description:    Free IBM WebSphere Application Server Parser v0.01
                        This program is free software: you can redistribute it and/or modify it under the terms of the
                        GNU General Public License as published by the Free Software Foundation, either version 3 of
                        the License, or (at your option) any later version.

        Usage:          ./fiwasp [-m mode|-f file.xml|-h]

        Example:        ./fiwasp -m processDefinitions -f /path/to/file/server.xml

        Options:        -m      (Optional) This option specifies a fragment or full information.

                                For server.xml file
                                -------------------
                                The following options are valid:

                                streamRedirect          Print 'streamRedirect' block information form server.xml.
                                components              Print 'components' block information form server.xml.
                                processDefinitions      Print 'processDefinitions' block information form server.xml.
                                all                     Print all information form server.xml.

                                If the -m option is not specified the program prints 'processDefinitions' block
                                information by default.


                                For resources.xml file
                                ----------------------
                                The following options are valid:

                                datasources             Print JDBC 'Datasources' block information form resources.xml.
                                queues                  Print JMS 'Queues' block information form resources.xml.
                                topics                  Print JMS 'Topics' block information form resources.xml.
                                connFactories           Print JMS 'Connection Factories' block information form resources.xml.
                                queueConnFactories      Print JMS 'Queue Connection Factories' block information form resources.xml.
                                topicConnFactories      Print JMS 'Topic Connection Factories' block information form resources.xml.
                                all                     Print all information form resources.xml.

                                If the -m option is not specified the program prints 'Datasources' block
                                information by default.

                        -f      File XML input. These are the valid files to print information:

                                resources.xml           Contains all resources information, like datasources, topics, queues,
                                                        connection factories, resource adapters, JMS or JDBC providers, etc.
                                server.xml              Contains all JVM settings.
                                serverindex.xml         Contains all the servers ports information.
                                variables.xml           Contains all WebSphere variables settings.
                                virtualhosts.xml        Contains all host aliases to a single hostname.

                        -h      This help.

